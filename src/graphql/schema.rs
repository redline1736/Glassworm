use std::fmt::Write as _;
use serde_json::Value;

// --------------------------------------------------------------
// Data structures (Vec/Option instead of raw arrays + null checks)
// --------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ArgInfo {
    pub name: String,
    pub type_string: String,
}

#[derive(Debug, Clone, Default)]
pub struct FieldInfo {
    pub name: String,
    pub args: Vec<ArgInfo>,
    pub type_string: String,
    pub is_deprecated: bool,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct EnumValueInfo {
    pub name: String,
    pub is_deprecated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TypeInfo {
    pub name: String,
    pub kind: String,
    pub description: Option<String>,
    pub fields: Vec<FieldInfo>,
    pub interfaces: Vec<String>,
    pub enum_values: Vec<EnumValueInfo>,
    pub input_fields: Vec<FieldInfo>,
    pub possible_types: Vec<String>,
    pub specified_by_url: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DirectiveInfo {
    pub name: String,
    pub args: Vec<ArgInfo>,
}

#[derive(Debug, Default)]
pub struct SchemaData {
    pub query_type: Option<TypeInfo>,
    pub mutation_type: Option<TypeInfo>,
    pub subscription_type: Option<TypeInfo>,
    pub types: Vec<TypeInfo>,
    pub directives: Vec<DirectiveInfo>,
}

// --------------------------------------------------------------
// Parsing (mirrors append_type_string / parse_field / parse_type /
// build_schema_data). No manual free()s needed -- Vec/String/Option
// clean themselves up when dropped.
// --------------------------------------------------------------

/// Unwraps a GraphQL type (LIST, NON_NULL) into a display string,
/// e.g. `[User!]!`.
fn type_string(type_obj: &Value) -> String {
    let kind = type_obj.get("kind").and_then(Value::as_str).unwrap_or("");
    match kind {
        "NON_NULL" => {
            let inner = type_obj.get("ofType").map(type_string).unwrap_or_default();
            format!("{}!", inner)
        }
        "LIST" => {
            let inner = type_obj.get("ofType").map(type_string).unwrap_or_default();
            format!("[{}]", inner)
        }
        _ => type_obj
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Unknown")
            .to_string(),
    }
}

fn parse_arg(arg: &Value) -> ArgInfo {
    ArgInfo {
        name: arg.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
        type_string: arg.get("type").map(type_string).unwrap_or_default(),
    }
}

fn parse_field(field_json: &Value) -> FieldInfo {
    let name = field_json
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let args = field_json
        .get("args")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().map(parse_arg).collect())
        .unwrap_or_default();

    let type_str = field_json.get("type").map(type_string).unwrap_or_default();
    let is_deprecated = field_json
        .get("isDeprecated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let default_value = field_json
        .get("defaultValue")
        .and_then(Value::as_str)
        .map(String::from);

    FieldInfo {
        name,
        args,
        type_string: type_str,
        is_deprecated,
        default_value,
    }
}

fn parse_enum_value(val_json: &Value) -> EnumValueInfo {
    EnumValueInfo {
        name: val_json.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
        is_deprecated: val_json.get("isDeprecated").and_then(Value::as_bool).unwrap_or(false),
    }
}

fn parse_type(type_json: &Value) -> TypeInfo {
    let kind = type_json.get("kind").and_then(Value::as_str).unwrap_or_default().to_string();
    let name = type_json.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
    let description = type_json.get("description").and_then(Value::as_str).map(String::from);

    let mut t = TypeInfo {
        kind: kind.clone(),
        name,
        description,
        ..Default::default()
    };

    match kind.as_str() {
        "OBJECT" | "INTERFACE" => {
            if let Some(fields) = type_json.get("fields").and_then(Value::as_array) {
                t.fields = fields.iter().map(parse_field).collect();
            }
            if kind == "OBJECT" {
                if let Some(ifaces) = type_json.get("interfaces").and_then(Value::as_array) {
                    t.interfaces = ifaces
                        .iter()
                        .filter_map(|i| i.get("name").and_then(Value::as_str))
                        .map(String::from)
                        .collect();
                }
            }
        }
        "ENUM" => {
            if let Some(vals) = type_json.get("enumValues").and_then(Value::as_array) {
                t.enum_values = vals.iter().map(parse_enum_value).collect();
            }
        }
        "INPUT_OBJECT" => {
            if let Some(fields) = type_json.get("inputFields").and_then(Value::as_array) {
                t.input_fields = fields.iter().map(parse_field).collect();
            }
        }
        "UNION" => {
            if let Some(pts) = type_json.get("possibleTypes").and_then(Value::as_array) {
                t.possible_types = pts
                    .iter()
                    .filter_map(|p| p.get("name").and_then(Value::as_str))
                    .map(String::from)
                    .collect();
            }
        }
        "SCALAR" => {
            t.specified_by_url = type_json
                .get("specifiedByURL")
                .and_then(Value::as_str)
                .map(String::from);
        }
        _ => {}
    }

    t
}

/// Builds a `SchemaData` from a parsed introspection response.
/// Returns `None` (with a message on stderr) where the C version
/// would `fprintf(stderr, ...)` and return NULL.
pub fn build_schema_data(root: &Value) -> Option<SchemaData> {
    let data = root.get("data").or_else(|| {
        eprintln!("Error: 'data' key not found.");
        None
    })?;
    let schema = data.get("__schema").or_else(|| {
        eprintln!("Error: '__schema' key not found.");
        None
    })?;
    let types = schema
        .get("types")
        .and_then(Value::as_array)
        .or_else(|| {
            eprintln!("Error: 'types' key not found.");
            None
        })?;

    let find_type = |target: &str| {
        types
            .iter()
            .find(|t| t.get("name").and_then(Value::as_str) == Some(target))
    };

    let mut sdata = SchemaData::default();

    if let Some(name) = schema
        .get("queryType")
        .and_then(|q| q.get("name"))
        .and_then(Value::as_str)
    {
        if let Some(obj) = find_type(name) {
            sdata.query_type = Some(parse_type(obj));
        }
    }
    if let Some(name) = schema
        .get("mutationType")
        .and_then(|q| q.get("name"))
        .and_then(Value::as_str)
    {
        if let Some(obj) = find_type(name) {
            sdata.mutation_type = Some(parse_type(obj));
        }
    }
    if let Some(name) = schema
        .get("subscriptionType")
        .and_then(|q| q.get("name"))
        .and_then(Value::as_str)
    {
        if let Some(obj) = find_type(name) {
            sdata.subscription_type = Some(parse_type(obj));
        }
    }

    const BUILTIN: [&str; 5] = ["Boolean", "Int", "String", "Float", "ID"];
    sdata.types = types
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str).map(|n| (n, t)))
        .filter(|(n, _)| !BUILTIN.contains(n) && !n.starts_with("__"))
        .map(|(_, t)| parse_type(t))
        .collect();

    if let Some(dirs) = schema.get("directives").and_then(Value::as_array) {
        sdata.directives = dirs
            .iter()
            .map(|d| DirectiveInfo {
                name: d.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                args: d
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|args| args.iter().map(parse_arg).collect())
                    .unwrap_or_default(),
            })
            .collect();
    }

    Some(sdata)
}

// --------------------------------------------------------------
// Formatting (mirrors print_field_info / print_type_info /
// print_schema_data). These *return* a String instead of writing
// to stdout directly -- the C version has to dup2() stdout into a
// memstream to capture this for `capture_introspection_check`;
// returning a String sidesteps that trick entirely.
// --------------------------------------------------------------

fn write_field_info(out: &mut String, field: &FieldInfo, indent: usize) {
    let pad = "  ".repeat(indent);
    let _ = write!(out, "{}{}", pad, field.name);

    if !field.args.is_empty() {
        out.push('(');
        for (i, a) in field.args.iter().enumerate() {
            let _ = write!(out, "{}: {}", a.name, a.type_string);
            if i < field.args.len() - 1 {
                out.push_str(", ");
            }
        }
        out.push(')');
    } else {
        out.push_str("()");
    }

    let _ = write!(out, ": {}", field.type_string);
    if field.is_deprecated {
        out.push_str(" [deprecated]");
    }
    if let Some(dv) = &field.default_value {
        let _ = write!(out, " = {}", dv);
    }
    out.push('\n');
}

fn write_type_info(out: &mut String, t: &TypeInfo, indent: usize) {
    let pad = "  ".repeat(indent);
    let _ = write!(out, "{}{} {}", pad, t.kind, t.name);
    if let Some(desc) = &t.description {
        let _ = write!(out, "  # {}", desc);
    }
    out.push('\n');

    match t.kind.as_str() {
        "OBJECT" | "INTERFACE" => {
            for f in &t.fields {
                write_field_info(out, f, indent + 1);
            }
            if t.kind == "OBJECT" && !t.interfaces.is_empty() {
                let inner_pad = "  ".repeat(indent + 1);
                let _ = write!(out, "{}implements {}", inner_pad, t.interfaces.join(", "));
                out.push('\n');
            }
            out.push('\n');
        }
        "ENUM" => {
            let inner_pad = "  ".repeat(indent + 1);
            for v in &t.enum_values {
                let _ = write!(out, "{}{}", inner_pad, v.name);
                if v.is_deprecated {
                    out.push_str(" [deprecated]");
                }
                out.push('\n');
            }
            out.push('\n');
        }
        "INPUT_OBJECT" => {
            for f in &t.input_fields {
                write_field_info(out, f, indent + 1);
            }
            out.push('\n');
        }
        "SCALAR" => {
            if let Some(url) = &t.specified_by_url {
                let inner_pad = "  ".repeat(indent + 1);
                let _ = write!(out, "{}@specifiedBy(url: \"{}\")\n", inner_pad, url);
            }
            out.push('\n');
        }
        "UNION" => {
            if !t.possible_types.is_empty() {
                let inner_pad = "  ".repeat(indent + 1);
                let _ = write!(out, "{}= {}\n\n", inner_pad, t.possible_types.join(" | "));
            }
        }
        _ => {}
    }
}

pub fn format_schema_data(schema: &SchemaData) -> String {
    let mut out = String::new();
    out.push_str("\n========== GRAPHQL SCHEMA ==========\n\n");

    if let Some(q) = &schema.query_type {
        out.push_str("ROOT QUERY:\n");
        write_type_info(&mut out, q, 0);
    }
    if let Some(m) = &schema.mutation_type {
        out.push_str("ROOT MUTATION:\n");
        write_type_info(&mut out, m, 0);
    } else {
        out.push_str("ROOT MUTATION: (none)\n\n");
    }
    if let Some(s) = &schema.subscription_type {
        out.push_str("ROOT SUBSCRIPTION:\n");
        write_type_info(&mut out, s, 0);
    } else {
        out.push_str("ROOT SUBSCRIPTION: (none)\n\n");
    }

    out.push_str("ALL CUSTOM TYPES:\n\n");
    for t in &schema.types {
        write_type_info(&mut out, t, 0);
    }

    if !schema.directives.is_empty() {
        out.push_str("DIRECTIVES:\n");
        for d in &schema.directives {
            let _ = write!(out, "  @{}", d.name);
            if !d.args.is_empty() {
                out.push('(');
                for (i, a) in d.args.iter().enumerate() {
                    let _ = write!(out, "{}: {}", a.name, a.type_string);
                    if i < d.args.len() - 1 {
                        out.push_str(", ");
                    }
                }
                out.push(')');
            }
            out.push('\n');
        }
        out.push('\n');
    }

    let _ = write!(
        out,
        "SUMMARY: {} custom types, {} directives\n\n",
        schema.types.len(),
        schema.directives.len()
    );

    out
}

// --------------------------------------------------------------
// Security analysis (mirrors perform_security_analysis)
// --------------------------------------------------------------

const SENSITIVE_KEYWORDS: [&str; 17] = [
    "password", "pass", "secret", "token", "apiKey", "apikey",
    "credit", "card", "ssn", "social", "tax", "bank", "account",
    "private", "internal", "admin", "root", "superuser",
];

const SCALARS: [&str; 5] = ["String", "Int", "Float", "Boolean", "ID"];

pub fn format_security_analysis(schema: &SchemaData) -> String {
    let mut out = String::new();
    out.push_str("========== SECURITY ANALYSIS ==========\n\n");

    // 1. Sensitive fields
    out.push_str("SENSITIVE FIELDS:\n");
    let mut found_sensitive = 0;
    for t in &schema.types {
        if t.kind == "OBJECT" || t.kind == "INTERFACE" {
            for f in &t.fields {
                if SENSITIVE_KEYWORDS.iter().any(|k| f.name.contains(k)) {
                    let _ = write!(out, "  {}.{} : {}\n", t.name, f.name, f.type_string);
                    found_sensitive += 1;
                }
            }
        }
        if t.kind == "INPUT_OBJECT" {
            for f in &t.input_fields {
                if SENSITIVE_KEYWORDS.iter().any(|k| f.name.contains(k)) {
                    let _ = write!(out, "  {} (input) : {}\n", f.name, f.type_string);
                    found_sensitive += 1;
                }
            }
        }
    }
    if found_sensitive == 0 {
        out.push_str("  (none)\n");
    }

    // 2. Mutations
    if let Some(mutation) = &schema.mutation_type {
        out.push_str("\nMUTATIONS (data modification):\n");
        for f in &mutation.fields {
            let _ = write!(out, "  {}(", f.name);
            for (i, a) in f.args.iter().enumerate() {
                let _ = write!(out, "{}: {}", a.name, a.type_string);
                if i < f.args.len() - 1 {
                    out.push_str(", ");
                }
            }
            let _ = write!(out, ") -> {}\n", f.type_string);
        }
    } else {
        out.push_str("\nMUTATIONS: (none)\n");
    }

    // 3. List fields (DoS risk)
    out.push_str("\nLIST FIELDS (possible DoS):\n");
    let mut found_lists = 0;
    for t in &schema.types {
        if t.kind == "OBJECT" || t.kind == "INTERFACE" {
            for f in &t.fields {
                if f.type_string.contains('[') {
                    let _ = write!(out, "  {}.{} : {}\n", t.name, f.name, f.type_string);
                    found_lists += 1;
                }
            }
        }
    }
    if found_lists == 0 {
        out.push_str("  (none)\n");
    }

    // 4. Object fields (nesting risk)
    out.push_str("\nOBJECT FIELDS (deep nesting potential):\n");
    let mut found_objects = 0;
    for t in &schema.types {
        if t.kind == "OBJECT" || t.kind == "INTERFACE" {
            for f in &t.fields {
                let is_scalar = SCALARS.contains(&f.type_string.as_str());
                if !is_scalar && !f.type_string.contains('[') {
                    let _ = write!(out, "  {}.{} -> {}\n", t.name, f.name, f.type_string);
                    found_objects += 1;
                }
            }
        }
    }
    if found_objects == 0 {
        out.push_str("  (none)\n");
    }

    // 5. Deprecated fields
    out.push_str("\nDEPRECATED FIELDS:\n");
    let mut found_deprecated = 0;
    for t in &schema.types {
        if t.kind == "OBJECT" || t.kind == "INTERFACE" {
            for f in &t.fields {
                if f.is_deprecated {
                    let _ = write!(out, "  {}.{}\n", t.name, f.name);
                    found_deprecated += 1;
                }
            }
        }
        if t.kind == "ENUM" {
            for v in &t.enum_values {
                if v.is_deprecated {
                    let _ = write!(out, "  {}.{} (enum)\n", t.name, v.name);
                    found_deprecated += 1;
                }
            }
        }
    }
    if found_deprecated == 0 {
        out.push_str("  (none)\n");
    }

    // 6. Recommendations
    out.push_str("\nRECOMMENDATIONS:\n");
    if schema.mutation_type.is_some() {
        out.push_str("  - Mutations exist: enforce authentication and authorization.\n");
    }
    if found_sensitive > 0 {
        out.push_str("  - Sensitive fields exposed: restrict access or use field-level permissions.\n");
    }
    if found_lists > 0 {
        out.push_str("  - List fields: implement pagination (first, after) to prevent DoS.\n");
    }
    if found_objects > 0 {
        out.push_str("  - Object fields: implement query depth limiting.\n");
    }
    out.push_str("  - Disable introspection in production unless required.\n");
    out.push_str("=========================================\n\n");

    out
}
