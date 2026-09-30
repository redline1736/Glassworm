#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <cjson/cJSON.h>

#include "../http/http.h"
#include "../sock/sock.h"
#include "scan.h"

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
    f->num_args = 0;
}

static void free_type_info(TypeInfo *t) {
    if (!t) return;
    free(t->name);
    free(t->kind);
    free(t->description);

    for (int i = 0; i < t->num_fields; i++) free_field_info(&t->fields[i]);
    free(t->fields);

    for (int i = 0; i < t->num_interfaces; i++) free(t->interfaces[i]);
    free(t->interfaces);

    for (int i = 0; i < t->num_enum_values; i++) free(t->enum_values[i].name);
    free(t->enum_values);

    for (int i = 0; i < t->num_input_fields; i++) free_field_info(&t->input_fields[i]);
    free(t->input_fields);

    for (int i = 0; i < t->num_possible_types; i++) free(t->possible_types[i]);
    free(t->possible_types);

    free(t->specified_by_url);
    free(t);
}

static void free_schema_data(SchemaData *schema) {
    if (!schema) return;
    if (schema->query_type)        free_type_info(schema->query_type);
    if (schema->mutation_type)     free_type_info(schema->mutation_type);
    if (schema->subscription_type) free_type_info(schema->subscription_type);

    for (int i = 0; i < schema->num_types; i++)
        if (schema->types[i]) free_type_info(schema->types[i]);
    free(schema->types);

    for (int i = 0; i < schema->num_directives; i++) {
        free(schema->directives[i].name);
        for (int j = 0; j < schema->directives[i].num_args; j++) {
            free(schema->directives[i].args[j].name);
            free(schema->directives[i].args[j].type_string);
        }
        free(schema->directives[i].args);
    }
    free(schema->directives);
    free(schema);
}

/* ------------------------------------------------------------------
 * read_json_from_file: strips any preamble before the first '{'.
 * Returns heap buffer, caller frees. No off-by-one past EOF.
 * ------------------------------------------------------------------ */
static char *read_json_from_file(const char *filename, long *out_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) return NULL;

    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
    long length = ftell(file);
    if (length < 0) { fclose(file); return NULL; }
    rewind(file);

    char *data = malloc((size_t)length + 1);
    if (!data) { fclose(file); return NULL; }

    size_t read_len = fread(data, 1, (size_t)length, file);
    fclose(file);

    if (read_len != (size_t)length) { free(data); return NULL; }
    data[length] = '\0';

    char *start = strchr(data, '{');
    if (!start) { free(data); return NULL; }

    if (start != data) {
        size_t tail = (size_t)length - (size_t)(start - data);
        memmove(data, start, tail);          /* no +1: NUL already at tail */
        data[tail] = '\0';
        length = (long)tail;
    }

    if (out_len) *out_len = length;
    return data;
}

/* ------------------------------------------------------------------
 * capture_introspection_check: capture stdout of introspection_check
 * via open_memstream. Returns NULL if nothing was written.
 * ------------------------------------------------------------------ */
static char *capture_introspection_check(const char *filename, size_t *out_len) {
    char   *buf = NULL;
    size_t  len = 0;

    FILE *mem = open_memstream(&buf, &len);
    if (!mem) return NULL;

    int saved_stdout = dup(fileno(stdout));
    if (saved_stdout < 0) {
        fclose(mem);
        free(buf);
        return NULL;
    }

    fflush(stdout);
    if (dup2(fileno(mem), fileno(stdout)) < 0) {
        close(saved_stdout);
        fclose(mem);
        free(buf);
        return NULL;
    }

    (void)introspection_check((char *)filename);

    fflush(stdout);
    dup2(saved_stdout, fileno(stdout));
    close(saved_stdout);
    fclose(mem);   /* flushes and finalizes buf/len */

    if (len == 0) { free(buf); return NULL; }
    if (out_len) *out_len = len;
    return buf;
}

/* ------------------------------------------------------------------
 * Minimal framing over the socket so a single recv() can't truncate
 * a 256 KB introspection response. Header is 8 ASCII digits, then
 * the payload. If your peer uses a different protocol, replace these
 * with matching read/write loops, or drop framing and read until EOF.
 * ------------------------------------------------------------------ */
static int send_framed_message(int fd, const char *msg, size_t len) {
    char hdr[FRAME_HDR + 1];
    snprintf(hdr, sizeof(hdr), "%08zu", len);
    if (send_message(fd, hdr) < 0) return -1;
    if (len > 0 && send_message(fd, msg) < 0) return -1;
    return 0;
}

static char *recv_framed_message(int fd) {
    char hdr[FRAME_HDR + 1] = {0};
    /* Read exactly FRAME_HDR bytes. */
    size_t got = 0;
    while (got < FRAME_HDR) {
        int n = receive_message(fd, hdr + got, FRAME_HDR - got);
        if (n <= 0) return NULL;
        got += (size_t)n;
    }
    hdr[FRAME_HDR] = '\0';

    char *endp = NULL;
    unsigned long long plen = strtoull(hdr, &endp, 10);
    if (!endp || *endp != '\0' || plen == 0 || plen > (64ULL * 1024 * 1024))
        return NULL;

    char *buf = malloc((size_t)plen + 1);
    if (!buf) return NULL;

    size_t have = 0;
    while (have < (size_t)plen) {
        int n = receive_message(fd, buf + have, (size_t)plen - have);
        if (n <= 0) { free(buf); return NULL; }
        have += (size_t)n;
    }
    buf[plen] = '\0';
    return buf;
}

/* ------------------------------------------------------------------
 * introspection_check: parse JSON file, print schema + analysis.
 * ------------------------------------------------------------------ */
int introspection_check(char *intro_json) {
    long length = 0;
    char *data = read_json_from_file(intro_json, &length);
    if (!data) {
        fprintf(stderr, "Failed to read JSON from %s\n", intro_json);
        return 1;
    }

    cJSON *json = cJSON_Parse(data);
    free(data);

    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr) fprintf(stderr, "JSON Parse Error near: %s\n", error_ptr);
        return 1;
    }

    SchemaData *schema = build_schema_data(json);
    if (!schema) {
        cJSON_Delete(json);
        return 1;
    }

    print_schema_data(schema);
    perform_security_analysis(schema);
    free_schema_data(schema);
    cJSON_Delete(json);
    return 0;
}

/* ------------------------------------------------------------------
 * detect_graphql: probe each URL in api_path with uni.json, write the
 * ones that look like GraphQL into graphql_path. Returns 0 if any found.
 * ------------------------------------------------------------------ */
int detect_graphql(char *api_path, char *graphql_path) {
    request r = {0};

    FILE *f = fopen("glassworm/graphql/uni.json", "r");
    if (!f) { fprintf(stderr, "Failed to open uni.json\n"); return 1; }

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long json_size = ftell(f);
    if (json_size < 0) { fclose(f); return 1; }
    rewind(f);

    char *json = malloc((size_t)json_size + 1);
    if (!json) { fclose(f); return 1; }
    if ((long)fread(json, 1, (size_t)json_size, f) != json_size) {
        free(json); fclose(f); return 1;
    }
    json[json_size] = '\0';
    fclose(f);

    FILE *api = fopen(api_path, "r");
    if (!api) { free(json); return 1; }

    FILE *graphql = fopen(graphql_path, "w");
    if (!graphql) { free(json); fclose(api); return 1; }

    char api_url[1024];
    int found_any = 0;

    while (fgets(api_url, sizeof(api_url), api)) {
        api_url[strcspn(api_url, "\n")] = '\0';
        if (api_url[0] == '\0') continue;

        if (!http_send_post(&r, api_url, false, NULL, true, json)) {
            fprintf(stderr, "HTTP POST failed for %s\n", api_url);
            continue;
        }
        if (r.code != 200) {
            fprintf(stderr, "Non-200 response for %s\n", api_url);
            continue;
        }

        char *resp = read_json_from_file(r.filename, NULL);
        if (!resp) continue;

        if (strstr(resp, "__schema") || strstr(resp, "\"data\"") ||
            strstr(resp, "\"errors\"") || strstr(resp, "\"query\"")) {
            printf("[+] GraphQL detected at %s\n", api_url);
            fprintf(graphql, "%s\n", api_url);
            found_any = 1;
        }
        free(resp);
    }

    fclose(api);
    fclose(graphql);
    free(json);
    return found_any ? 0 : 1;
}

/* ------------------------------------------------------------------
 * graphql_scanning
 * ------------------------------------------------------------------ */
int graphql_scanning(char *path, bool gobuster, char *target_url) {
    /* 1) Load introspection query up front. */
    FILE *f = fopen("glassworm/graphql/introspection.json", "r");
    if (!f) { fprintf(stderr, "Failed to open introspection.json\n"); return 1; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long json_size = ftell(f);
    if (json_size < 0) { fclose(f); return 1; }
    rewind(f);

    char *introspection_json = malloc((size_t)json_size + 1);
    if (!introspection_json) { fclose(f); return 1; }
    if ((long)fread(introspection_json, 1, (size_t)json_size, f) != json_size) {
        free(introspection_json); fclose(f); return 1;
    }
    introspection_json[json_size] = '\0';
    fclose(f);

    char api_path[PATH_MAX];
    char graphql_path[PATH_MAX];
    snprintf(api_path,     sizeof(api_path),     "%s/api.txt",     path);
    snprintf(graphql_path, sizeof(graphql_path), "%s/graphql.txt", path);

    /* 2) Build api.txt (either filter gobuster, or write target_url). */
    if (gobuster) {
        char gobuster_path[PATH_MAX];
        snprintf(gobuster_path, sizeof(gobuster_path), "%s/gobuster.txt", path);

        FILE *gobuster_file = fopen(gobuster_path, "r");
        if (!gobuster_file) {
            fprintf(stderr, "Failed to open gobuster.txt\n");
            free(introspection_json);
            return 1;
        }
        FILE *api_file = fopen(api_path, "w");
        if (!api_file) {
            fclose(gobuster_file);
            free(introspection_json);
            return 1;
        }
        char gobuster_url[1024];
        while (fgets(gobuster_url, sizeof(gobuster_url), gobuster_file)) {
            gobuster_url[strcspn(gobuster_url, "\n")] = '\0';
            if (strstr(gobuster_url, "graphql") || strstr(gobuster_url, "api"))
                fprintf(api_file, "%s\n", gobuster_url);
        }
        fclose(gobuster_file);
        fclose(api_file);
    } else {
        if (!target_url) {
            fprintf(stderr, "No target_url and not in gobuster mode\n");
            free(introspection_json);
            return 1;
        }
        FILE *api_file = fopen(api_path, "w");
        if (!api_file) { free(introspection_json); return 1; }
        fprintf(api_file, "%s\n", target_url);
        fclose(api_file);
    }

    /* 3) Probe endpoints, write graphql.txt. */
    if (detect_graphql(api_path, graphql_path) == 0)
        printf("[+] GraphQL detection completed.\n");
    else
        printf("[-] No GraphQL endpoints found.\n");

    /* 4) Socket: bind + accept ONCE, before the loop. */
    int fd = init_socket(SOCK_PATH);
    if (fd < 0) {
        fprintf(stderr, "Failed to init socket at %s\n", SOCK_PATH);
        free(introspection_json);
        return 1;
    }
    int client = accept_connection(fd);
    if (client < 0) {
        fprintf(stderr, "Failed to accept socket connection\n");
        close_socket(fd, client, SOCK_PATH);
        free(introspection_json);
        return 1;
    }

    FILE *graphql_file = fopen(graphql_path, "r");
    if (!graphql_file) {
        fprintf(stderr, "Failed to open graphql.txt\n");
        close_socket(fd, client, SOCK_PATH);
        free(introspection_json);
        return 1;
    }

    /* 5) Main loop: one round-trip per URL. */
    request r = {0};
    char graphql_url[1024];
    int  sent_count = 0;

    while (fgets(graphql_url, sizeof(graphql_url), graphql_file)) {
        graphql_url[strcspn(graphql_url, "\n")] = '\0';
        if (graphql_url[0] == '\0') continue;

        /* 5a) Send the introspection *query* over the socket. */
        if (send_framed_message(client, introspection_json,
                                strlen(introspection_json)) < 0) {
            fprintf(stderr, "[-] socket send failed for %s\n", graphql_url);
            continue;
        }
        printf("[+] Sent introspection query over socket for %s\n", graphql_url);

        /* 5b) Receive the peer's reply. */
        char *peer_reply = recv_framed_message(client);
        if (!peer_reply) {
            fprintf(stderr, "[-] no/invalid socket reply for %s\n", graphql_url);
            continue;
        }

        /* 5c) POST that reply to the GraphQL endpoint. */
        if (!http_send_post(&r, graphql_url, false, NULL, true, peer_reply)) {
            fprintf(stderr, "[-] HTTP POST failed for %s\n", graphql_url);
            free(peer_reply);
            continue;
        }
        free(peer_reply);

        if (r.code != 200) {
            fprintf(stderr, "[-] Non-200 (%d) from %s\n", (int)r.code, graphql_url);
            continue;
        }
        sent_count++;
        printf("[+] Response from %s saved to %s\n", graphql_url, r.filename);

        /* 5d) Analyze, capture stdout, send analysis back over the socket. */
        size_t analysis_len = 0;
        char  *analysis = capture_introspection_check(r.filename, &analysis_len);
        if (!analysis) {
            fprintf(stderr, "[-] analysis failed for %s\n", graphql_url);
            continue;
        }

        if (send_framed_message(client, analysis, analysis_len) < 0) {
            fprintf(stderr, "[-] socket send (analysis) failed for %s\n",
                    graphql_url);
            free(analysis);
            continue;
        }
        printf("[+] Sent analysis (%zu bytes) for %s\n",
               analysis_len, graphql_url);
        free(analysis);
    }

    fclose(graphql_file);
    close_socket(fd, client, SOCK_PATH);
    free(introspection_json);
    printf("\n[+] Done. %d introspection responses analyzed.\n", sent_count);

    return 0;
}