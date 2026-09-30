#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <cjson/cJSON.h>

#include "../http/http.h"
#include "../sock/sock.h"
#include "gq.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define SOCK_PATH "/tmp/sentinel.sock"

/* Socket framing: 8-byte ASCII-decimal length header followed by payload.
 * The peer must use the same framing. If your peer doesn't, see the
 * "loose framing" comment near send_framed_message. */
#define FRAME_HDR 8

/* ------------------------------------------------------------------
 * Data structures
 * ------------------------------------------------------------------ */

typedef struct {
    char *name;
    char *type_string;
} ArgInfo;

typedef struct {
    char *name;
    ArgInfo *args;
    int num_args;
    char *type_string;
    int is_deprecated;
    char *default_value;
} FieldInfo;

typedef struct {
    char *name;
    int is_deprecated;
} EnumValueInfo;

typedef struct {
    char *name;
    char *kind;
    char *description;
    FieldInfo *fields;
    int num_fields;
    char **interfaces;
    int num_interfaces;
    EnumValueInfo *enum_values;
    int num_enum_values;
    FieldInfo *input_fields;
    int num_input_fields;
    char **possible_types;
    int num_possible_types;
    char *specified_by_url;
} TypeInfo;

/* Tagged (was anonymous) so it can be passed to helpers. */
typedef struct {
    char *name;
    ArgInfo *args;
    int num_args;
} DirectiveInfo;

typedef struct {
    TypeInfo *query_type;
    TypeInfo *mutation_type;
    TypeInfo *subscription_type;
    TypeInfo **types;
    int num_types;
    DirectiveInfo *directives;
    int num_directives;
} SchemaData;

/* ------------------------------------------------------------------
 * Forward declarations (everything at file scope, no nested funcs)
 * ------------------------------------------------------------------ */
static void   append_type_string(cJSON *type_obj, char *buffer, size_t buflen);
static void   parse_field(cJSON *field_json, FieldInfo *out);
static void   parse_enum_value(cJSON *val_json, EnumValueInfo *out);
static TypeInfo *parse_type(cJSON *type_json);
static cJSON *find_type_json_by_name(cJSON *types, const char *target);
static SchemaData *build_schema_data(cJSON *root);
static void   print_field_info(FieldInfo *field, int indent);
static void   print_type_info(TypeInfo *type, int indent);
static void   print_schema_data(SchemaData *schema);
static void   perform_security_analysis(SchemaData *schema);
static void   free_field_info(FieldInfo *f);
static void   free_type_info(TypeInfo *t);
static void   free_schema_data(SchemaData *schema);
static char  *read_json_from_file(const char *filename, long *out_len);
static char  *capture_introspection_check(const char *filename, size_t *out_len);
static int    send_framed_message(int fd, const char *msg, size_t len);
static char  *recv_framed_message(int fd);

/* ------------------------------------------------------------------
 * append_type_string: unwrap LIST/NON_NULL into a string.
 * Bounded, so a malicious schema can't overflow the stack buffer.
 * ------------------------------------------------------------------ */
static void append_type_string(cJSON *type_obj, char *buffer, size_t buflen) {
    if (!type_obj || !buffer || buflen == 0) return;

    cJSON *kind = cJSON_GetObjectItem(type_obj, "kind");
    cJSON *name = cJSON_GetObjectItem(type_obj, "name");
    cJSON *of_type = cJSON_GetObjectItem(type_obj, "ofType");

    if (!kind || !kind->valuestring) return;
    const char *kind_str = kind->valuestring;

    size_t used = strlen(buffer);
    if (used >= buflen - 1) return;   /* already full */

    if (strcmp(kind_str, "NON_NULL") == 0) {
        append_type_string(of_type, buffer, buflen);
        used = strlen(buffer);
        if (used < buflen - 1) {
            buffer[used] = '!';
            buffer[used + 1] = '\0';
        }
    } else if (strcmp(kind_str, "LIST") == 0) {
        if (used < buflen - 1) {
            buffer[used++] = '[';
            buffer[used]   = '\0';
        }
        append_type_string(of_type, buffer, buflen);
        used = strlen(buffer);
        if (used < buflen - 1) {
            buffer[used]   = ']';
            buffer[used+1] = '\0';
        }
    } else {
        const char *n = (name && name->valuestring) ? name->valuestring : "Unknown";
        size_t nlen = strlen(n);
        size_t room = (buflen > used + 1) ? (buflen - used - 1) : 0;
        if (nlen > room) nlen = room;
        memcpy(buffer + used, n, nlen);
        buffer[used + nlen] = '\0';
    }
}

/* ------------------------------------------------------------------
 * parse_field: fills caller-provided struct. No leak, no shallow copy.
 * ------------------------------------------------------------------ */
static void parse_field(cJSON *field_json, FieldInfo *out) {
    if (!field_json || !out) return;

    cJSON *name = cJSON_GetObjectItem(field_json, "name");
    if (name && name->valuestring) out->name = strdup(name->valuestring);

    cJSON *args = cJSON_GetObjectItem(field_json, "args");
    if (args) {
        int count = cJSON_GetArraySize(args);
        if (count > 0) {
            out->args = calloc((size_t)count, sizeof(ArgInfo));
            if (out->args) {
                out->num_args = count;
                for (int i = 0; i < count; i++) {
                    cJSON *arg = cJSON_GetArrayItem(args, i);
                    if (!arg) continue;
                    cJSON *arg_name = cJSON_GetObjectItem(arg, "name");
                    cJSON *arg_type = cJSON_GetObjectItem(arg, "type");
                    if (arg_name && arg_name->valuestring)
                        out->args[i].name = strdup(arg_name->valuestring);

                    char type_buf[512] = {0};
                    append_type_string(arg_type, type_buf, sizeof(type_buf));
                    out->args[i].type_string = strdup(type_buf);
                }
            }
        }
    }

    cJSON *type = cJSON_GetObjectItem(field_json, "type");
    if (type) {
        char type_buf[512] = {0};
        append_type_string(type, type_buf, sizeof(type_buf));
        out->type_string = strdup(type_buf);
    } else {
        out->type_string = strdup("Unknown");
    }

    cJSON *dep = cJSON_GetObjectItem(field_json, "isDeprecated");
    out->is_deprecated = (dep && dep->type == cJSON_True);

    cJSON *def = cJSON_GetObjectItem(field_json, "defaultValue");
    if (def && def->valuestring)
        out->default_value = strdup(def->valuestring);
}

/* ------------------------------------------------------------------
 * parse_enum_value
 * ------------------------------------------------------------------ */
static void parse_enum_value(cJSON *val_json, EnumValueInfo *out) {
    if (!val_json || !out) return;
    cJSON *name = cJSON_GetObjectItem(val_json, "name");
    if (name && name->valuestring) out->name = strdup(name->valuestring);
    cJSON *dep = cJSON_GetObjectItem(val_json, "isDeprecated");
    out->is_deprecated = (dep && dep->type == cJSON_True);
}

/* ------------------------------------------------------------------
 * find_type_json_by_name (file scope, was nested)
 * ------------------------------------------------------------------ */
static cJSON *find_type_json_by_name(cJSON *types, const char *target) {
    if (!types || !target) return NULL;
    int count = cJSON_GetArraySize(types);
    for (int i = 0; i < count; i++) {
        cJSON *t = cJSON_GetArrayItem(types, i);
        cJSON *tname = cJSON_GetObjectItem(t, "name");
        if (tname && tname->valuestring &&
            strcmp(tname->valuestring, target) == 0) {
            return t;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------
 * parse_type
 * ------------------------------------------------------------------ */
static TypeInfo *parse_type(cJSON *type_json) {
    if (!type_json) return NULL;

    TypeInfo *t = calloc(1, sizeof(TypeInfo));
    if (!t) return NULL;

    cJSON *kind = cJSON_GetObjectItem(type_json, "kind");
    cJSON *name = cJSON_GetObjectItem(type_json, "name");
    cJSON *description = cJSON_GetObjectItem(type_json, "description");

    /* Default kind to "" so strcmp() is always safe. */
    if (kind && kind->valuestring) t->kind = strdup(kind->valuestring);
    else                           t->kind = strdup("");
    if (name && name->valuestring) t->name = strdup(name->valuestring);
    else                           t->name = strdup("");
    if (description && description->valuestring)
        t->description = strdup(description->valuestring);

    const char *kind_str = t->kind;

    if (strcmp(kind_str, "OBJECT") == 0 || strcmp(kind_str, "INTERFACE") == 0) {
        cJSON *fields = cJSON_GetObjectItem(type_json, "fields");
        if (fields) {
            int count = cJSON_GetArraySize(fields);
            if (count > 0) {
                t->fields = calloc((size_t)count, sizeof(FieldInfo));
                if (t->fields) {
                    t->num_fields = count;
                    for (int i = 0; i < count; i++) {
                        parse_field(cJSON_GetArrayItem(fields, i), &t->fields[i]);
                    }
                }
            }
        }

        if (strcmp(kind_str, "OBJECT") == 0) {
            cJSON *interfaces = cJSON_GetObjectItem(type_json, "interfaces");
            if (interfaces) {
                int count = cJSON_GetArraySize(interfaces);
                if (count > 0) {
                    t->interfaces = calloc((size_t)count, sizeof(char *));
                    if (t->interfaces) {
                        t->num_interfaces = count;
                        for (int i = 0; i < count; i++) {
                            cJSON *iface = cJSON_GetArrayItem(interfaces, i);
                            cJSON *iface_name = cJSON_GetObjectItem(iface, "name");
                            if (iface_name && iface_name->valuestring)
                                t->interfaces[i] = strdup(iface_name->valuestring);
                        }
                    }
                }
            }
        }
    }
    else if (strcmp(kind_str, "ENUM") == 0) {
        cJSON *enum_values = cJSON_GetObjectItem(type_json, "enumValues");
        if (enum_values) {
            int count = cJSON_GetArraySize(enum_values);
            if (count > 0) {
                t->enum_values = calloc((size_t)count, sizeof(EnumValueInfo));
                if (t->enum_values) {
                    t->num_enum_values = count;
                    for (int i = 0; i < count; i++) {
                        parse_enum_value(cJSON_GetArrayItem(enum_values, i),
                                         &t->enum_values[i]);
                    }
                }
            }
        }
    }
    else if (strcmp(kind_str, "INPUT_OBJECT") == 0) {
        cJSON *input_fields = cJSON_GetObjectItem(type_json, "inputFields");
        if (input_fields) {
            int count = cJSON_GetArraySize(input_fields);
            if (count > 0) {
                t->input_fields = calloc((size_t)count, sizeof(FieldInfo));
                if (t->input_fields) {
                    t->num_input_fields = count;
                    for (int i = 0; i < count; i++) {
                        parse_field(cJSON_GetArrayItem(input_fields, i),
                                    &t->input_fields[i]);
                    }
                }
            }
        }
    }
    else if (strcmp(kind_str, "UNION") == 0) {
        cJSON *possible_types = cJSON_GetObjectItem(type_json, "possibleTypes");
        if (possible_types) {
            int count = cJSON_GetArraySize(possible_types);
            if (count > 0) {
                t->possible_types = calloc((size_t)count, sizeof(char *));
                if (t->possible_types) {
                    t->num_possible_types = count;
                    for (int i = 0; i < count; i++) {
                        cJSON *pt = cJSON_GetArrayItem(possible_types, i);
                        cJSON *pt_name = cJSON_GetObjectItem(pt, "name");
                        if (pt_name && pt_name->valuestring)
                            t->possible_types[i] = strdup(pt_name->valuestring);
                    }
                }
            }
        }
    }
    else if (strcmp(kind_str, "SCALAR") == 0) {
        cJSON *spec_url = cJSON_GetObjectItem(type_json, "specifiedByURL");
        if (spec_url && spec_url->valuestring)
            t->specified_by_url = strdup(spec_url->valuestring);
    }

    return t;
}

/* ------------------------------------------------------------------
 * build_schema_data
 * ------------------------------------------------------------------ */
static SchemaData *build_schema_data(cJSON *root) {
    if (!root) return NULL;

    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (!data) {
        fprintf(stderr, "Error: 'data' key not found.\n");
        return NULL;
    }

    cJSON *schema = cJSON_GetObjectItem(data, "__schema");
    if (!schema) {
        fprintf(stderr, "Error: '__schema' key not found.\n");
        return NULL;
    }

    cJSON *types = cJSON_GetObjectItem(schema, "types");
    if (!types) {
        fprintf(stderr, "Error: 'types' key not found.\n");
        return NULL;
    }

    SchemaData *sdata = calloc(1, sizeof(SchemaData));
    if (!sdata) return NULL;

    cJSON *query_type = cJSON_GetObjectItem(schema, "queryType");
    cJSON *mutation_type = cJSON_GetObjectItem(schema, "mutationType");
    cJSON *subscription_type = cJSON_GetObjectItem(schema, "subscriptionType");

    if (query_type) {
        cJSON *qname = cJSON_GetObjectItem(query_type, "name");
        if (qname && qname->valuestring) {
            cJSON *qobj = find_type_json_by_name(types, qname->valuestring);
            if (qobj) sdata->query_type = parse_type(qobj);
        }
    }
    if (mutation_type) {
        cJSON *mname = cJSON_GetObjectItem(mutation_type, "name");
        if (mname && mname->valuestring) {
            cJSON *mobj = find_type_json_by_name(types, mname->valuestring);
            if (mobj) sdata->mutation_type = parse_type(mobj);
        }
    }
    if (subscription_type) {
        cJSON *sname = cJSON_GetObjectItem(subscription_type, "name");
        if (sname && sname->valuestring) {
            cJSON *sobj = find_type_json_by_name(types, sname->valuestring);
            if (sobj) sdata->subscription_type = parse_type(sobj);
        }
    }

    /* Custom types (skip built-ins and __-prefixed). */
    int total_types = cJSON_GetArraySize(types);
    int custom_count = 0;
    for (int i = 0; i < total_types; i++) {
        cJSON *type = cJSON_GetArrayItem(types, i);
        cJSON *name = cJSON_GetObjectItem(type, "name");
        if (!name || !name->valuestring) continue;
        const char *n = name->valuestring;
        if (strcmp(n, "Boolean") == 0 || strcmp(n, "Int") == 0 ||
            strcmp(n, "String")  == 0 || strcmp(n, "Float") == 0 ||
            strcmp(n, "ID")      == 0 || strncmp(n, "__", 2) == 0) {
            continue;
        }
        custom_count++;
    }

    if (custom_count > 0) {
        sdata->types = calloc((size_t)custom_count, sizeof(TypeInfo *));
        if (!sdata->types) { free(sdata); return NULL; }
        int idx = 0;
        for (int i = 0; i < total_types; i++) {
            cJSON *type = cJSON_GetArrayItem(types, i);
            cJSON *name = cJSON_GetObjectItem(type, "name");
            if (!name || !name->valuestring) continue;
            const char *n = name->valuestring;
            if (strcmp(n, "Boolean") == 0 || strcmp(n, "Int") == 0 ||
                strcmp(n, "String")  == 0 || strcmp(n, "Float") == 0 ||
                strcmp(n, "ID")      == 0 || strncmp(n, "__", 2) == 0) {
                continue;
            }
            sdata->types[idx++] = parse_type(type);
        }
        sdata->num_types = idx;
    }

    cJSON *directives = cJSON_GetObjectItem(schema, "directives");
    if (directives) {
        int dcount = cJSON_GetArraySize(directives);
        if (dcount > 0) {
            sdata->directives = calloc((size_t)dcount, sizeof(DirectiveInfo));
            if (sdata->directives) {
                sdata->num_directives = dcount;
                for (int i = 0; i < dcount; i++) {
                    cJSON *dir = cJSON_GetArrayItem(directives, i);
                    cJSON *dname = cJSON_GetObjectItem(dir, "name");
                    if (dname && dname->valuestring)
                        sdata->directives[i].name = strdup(dname->valuestring);

                    cJSON *dargs = cJSON_GetObjectItem(dir, "args");
                    if (dargs) {
                        int ac = cJSON_GetArraySize(dargs);
                        if (ac > 0) {
                            sdata->directives[i].args =
                                calloc((size_t)ac, sizeof(ArgInfo));
                            if (sdata->directives[i].args) {
                                sdata->directives[i].num_args = ac;
                                for (int j = 0; j < ac; j++) {
                                    cJSON *arg = cJSON_GetArrayItem(dargs, j);
                                    cJSON *aname = cJSON_GetObjectItem(arg, "name");
                                    cJSON *atype = cJSON_GetObjectItem(arg, "type");
                                    if (aname && aname->valuestring)
                                        sdata->directives[i].args[j].name =
                                            strdup(aname->valuestring);
                                    char buf[512] = {0};
                                    append_type_string(atype, buf, sizeof(buf));
                                    sdata->directives[i].args[j].type_string =
                                        strdup(buf);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return sdata;
}

/* ------------------------------------------------------------------
 * Printing
 * ------------------------------------------------------------------ */
static void print_field_info(FieldInfo *field, int indent) {
    for (int i = 0; i < indent; i++) printf("  ");
    printf("%s", field->name ? field->name : "?");

    if (field->num_args > 0) {
        printf("(");
        for (int i = 0; i < field->num_args; i++) {
            printf("%s: %s",
                   field->args[i].name        ? field->args[i].name        : "?",
                   field->args[i].type_string ? field->args[i].type_string : "?");
            if (i < field->num_args - 1) printf(", ");
        }
        printf(")");
    } else {
        printf("()");
    }

    printf(": %s", field->type_string ? field->type_string : "?");
    if (field->is_deprecated) printf(" [deprecated]");
    if (field->default_value) printf(" = %s", field->default_value);
    printf("\n");
}

static void print_type_info(TypeInfo *type, int indent) {
    if (!type) return;

    for (int i = 0; i < indent; i++) printf("  ");
    printf("%s %s", type->kind ? type->kind : "?",
                    type->name ? type->name : "?");
    if (type->description) printf("  # %s", type->description);
    printf("\n");

    const char *kind = type->kind ? type->kind : "";

    if (strcmp(kind, "OBJECT") == 0 || strcmp(kind, "INTERFACE") == 0) {
        for (int i = 0; i < type->num_fields; i++)
            print_field_info(&type->fields[i], indent + 1);

        if (strcmp(kind, "OBJECT") == 0 && type->num_interfaces > 0) {
            for (int i = 0; i < indent + 1; i++) printf("  ");
            printf("implements ");
            for (int j = 0; j < type->num_interfaces; j++) {
                printf("%s", type->interfaces[j] ? type->interfaces[j] : "?");
                if (j < type->num_interfaces - 1) printf(", ");
            }
            printf("\n");
        }
        printf("\n");
    }
    else if (strcmp(kind, "ENUM") == 0) {
        for (int i = 0; i < type->num_enum_values; i++) {
            for (int j = 0; j < indent + 1; j++) printf("  ");
            printf("%s", type->enum_values[i].name ? type->enum_values[i].name : "?");
            if (type->enum_values[i].is_deprecated) printf(" [deprecated]");
            printf("\n");
        }
        printf("\n");
    }
    else if (strcmp(kind, "INPUT_OBJECT") == 0) {
        for (int i = 0; i < type->num_input_fields; i++)
            print_field_info(&type->input_fields[i], indent + 1);
        printf("\n");
    }
    else if (strcmp(kind, "SCALAR") == 0) {
        if (type->specified_by_url) {
            for (int i = 0; i < indent + 1; i++) printf("  ");
            printf("@specifiedBy(url: \"%s\")\n", type->specified_by_url);
        }
        printf("\n");
    }
    else if (strcmp(kind, "UNION") == 0) {
        if (type->num_possible_types > 0) {
            for (int i = 0; i < indent + 1; i++) printf("  ");
            printf("= ");
            for (int j = 0; j < type->num_possible_types; j++) {
                printf("%s", type->possible_types[j] ? type->possible_types[j] : "?");
                if (j < type->num_possible_types - 1) printf(" | ");
            }
            printf("\n\n");
        }
    }
}

static void print_schema_data(SchemaData *schema) {
    if (!schema) return;

    printf("\n========== GRAPHQL SCHEMA ==========\n\n");

    if (schema->query_type) {
        printf("ROOT QUERY:\n");
        print_type_info(schema->query_type, 0);
    }
    if (schema->mutation_type) {
        printf("ROOT MUTATION:\n");
        print_type_info(schema->mutation_type, 0);
    } else {
        printf("ROOT MUTATION: (none)\n\n");
    }
    if (schema->subscription_type) {
        printf("ROOT SUBSCRIPTION:\n");
        print_type_info(schema->subscription_type, 0);
    } else {
        printf("ROOT SUBSCRIPTION: (none)\n\n");
    }

    printf("ALL CUSTOM TYPES:\n\n");
    for (int i = 0; i < schema->num_types; i++)
        print_type_info(schema->types[i], 0);

    if (schema->num_directives > 0) {
        printf("DIRECTIVES:\n");
        for (int i = 0; i < schema->num_directives; i++) {
            printf("  @%s", schema->directives[i].name ? schema->directives[i].name : "?");
            if (schema->directives[i].num_args > 0) {
                printf("(");
                for (int j = 0; j < schema->directives[i].num_args; j++) {
                    printf("%s: %s",
                           schema->directives[i].args[j].name        ? schema->directives[i].args[j].name        : "?",
                           schema->directives[i].args[j].type_string ? schema->directives[i].args[j].type_string : "?");
                    if (j < schema->directives[i].num_args - 1) printf(", ");
                }
                printf(")");
            }
            printf("\n");
        }
        printf("\n");
    }

    printf("SUMMARY: %d custom types, %d directives\n\n",
           schema->num_types, schema->num_directives);
}

/* ------------------------------------------------------------------
 * Security analysis
 * ------------------------------------------------------------------ */
static void perform_security_analysis(SchemaData *schema) {
    if (!schema) return;

    printf("========== SECURITY ANALYSIS ==========\n\n");

    const char *sensitive_keywords[] = {
        "password", "pass", "secret", "token", "apiKey", "apikey",
        "credit", "card", "ssn", "social", "tax", "bank", "account",
        "private", "internal", "admin", "root", "superuser"
    };
    const int num_keywords =
        (int)(sizeof(sensitive_keywords) / sizeof(sensitive_keywords[0]));

    printf("SENSITIVE FIELDS:\n");
    int found_sensitive = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (!t || !t->kind) continue;

        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                FieldInfo *f = &t->fields[j];
                if (!f->name) continue;
                for (int k = 0; k < num_keywords; k++) {
                    if (strstr(f->name, sensitive_keywords[k]) != NULL) {
                        printf("  %s.%s : %s\n", t->name, f->name,
                               f->type_string ? f->type_string : "?");
                        found_sensitive++;
                        break;
                    }
                }
            }
        }
        if (strcmp(t->kind, "INPUT_OBJECT") == 0) {
            for (int j = 0; j < t->num_input_fields; j++) {
                FieldInfo *f = &t->input_fields[j];
                if (!f->name) continue;
                for (int k = 0; k < num_keywords; k++) {
                    if (strstr(f->name, sensitive_keywords[k]) != NULL) {
                        printf("  %s (input) : %s\n", f->name,
                               f->type_string ? f->type_string : "?");
                        found_sensitive++;
                        break;
                    }
                }
            }
        }
    }
    if (!found_sensitive) printf("  (none)\n");

    if (schema->mutation_type) {
        printf("\nMUTATIONS (data modification):\n");
        TypeInfo *mut = schema->mutation_type;
        for (int i = 0; i < mut->num_fields; i++) {
            FieldInfo *f = &mut->fields[i];
            printf("  %s(", f->name ? f->name : "?");
            for (int j = 0; j < f->num_args; j++) {
                printf("%s: %s",
                       f->args[j].name        ? f->args[j].name        : "?",
                       f->args[j].type_string ? f->args[j].type_string : "?");
                if (j < f->num_args - 1) printf(", ");
            }
            printf(") -> %s\n", f->type_string ? f->type_string : "?");
        }
    } else {
        printf("\nMUTATIONS: (none)\n");
    }

    printf("\nLIST FIELDS (possible DoS):\n");
    int found_lists = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (!t || !t->kind) continue;
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                FieldInfo *f = &t->fields[j];
                if (f->type_string && strstr(f->type_string, "[") != NULL) {
                    printf("  %s.%s : %s\n", t->name, f->name, f->type_string);
                    found_lists++;
                }
            }
        }
    }
    if (!found_lists) printf("  (none)\n");

    const char *scalars[] = {"String", "Int", "Float", "Boolean", "ID"};
    const int num_scalars = 5;
    printf("\nOBJECT FIELDS (deep nesting potential):\n");
    int found_objects = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (!t || !t->kind) continue;
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                FieldInfo *f = &t->fields[j];
                if (!f->type_string) continue;
                int is_scalar = 0;
                for (int k = 0; k < num_scalars; k++) {
                    if (strcmp(f->type_string, scalars[k]) == 0) {
                        is_scalar = 1;
                        break;
                    }
                }
                if (!is_scalar && strchr(f->type_string, '[') == NULL) {
                    printf("  %s.%s -> %s\n", t->name, f->name, f->type_string);
                    found_objects++;
                }
            }
        }
    }
    if (!found_objects) printf("  (none)\n");

    printf("\nDEPRECATED FIELDS:\n");
    int found_deprecated = 0;
    for (int i = 0; i < schema->num_types; i++) {
        TypeInfo *t = schema->types[i];
        if (!t || !t->kind) continue;
        if (strcmp(t->kind, "OBJECT") == 0 || strcmp(t->kind, "INTERFACE") == 0) {
            for (int j = 0; j < t->num_fields; j++) {
                if (t->fields[j].is_deprecated) {
                    printf("  %s.%s\n", t->name, t->fields[j].name);
                    found_deprecated++;
                }
            }
        }
        if (strcmp(t->kind, "ENUM") == 0) {
            for (int j = 0; j < t->num_enum_values; j++) {
                if (t->enum_values[j].is_deprecated) {
                    printf("  %s.%s (enum)\n", t->name, t->enum_values[j].name);
                    found_deprecated++;
                }
            }
        }
    }
    if (!found_deprecated) printf("  (none)\n");

    printf("\nRECOMMENDATIONS:\n");
    if (schema->mutation_type)
        printf("  - Mutations exist: enforce authentication and authorization.\n");
    if (found_sensitive)
        printf("  - Sensitive fields exposed: restrict access or use field-level permissions.\n");
    if (found_lists)
        printf("  - List fields: implement pagination (first, after) to prevent DoS.\n");
    if (found_objects)
        printf("  - Object fields: implement query depth limiting.\n");
    printf("  - Disable introspection in production unless required.\n");
    printf("=========================================\n\n");
}

/* ------------------------------------------------------------------
 * Frees (file-scope, no nested functions)
 * ------------------------------------------------------------------ */
static void free_field_info(FieldInfo *f) {
    if (!f) return;
    free(f->name);
    free(f->type_string);
    free(f->default_value);
    for (int i = 0; i < f->num_args; i++) {
        free(f->args[i].name);
        free(f->args[i].type_string);
    }
    free(f->args);
    f->name = f->type_string = f->default_value = NULL;
    f->args = NULL;
   