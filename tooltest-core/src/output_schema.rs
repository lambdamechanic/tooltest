use jsonschema::{draft201909, draft202012, draft4, draft6, draft7, Validator};
use serde_json::Value as JsonValue;

use crate::schema_dialect::{
    normalize_schema_id, DRAFT201909, DRAFT202012, DRAFT4_HTTP, DRAFT4_HTTPS, DRAFT6_HTTP,
    DRAFT6_HTTPS, DRAFT7_HTTP, DRAFT7_HTTPS,
};
use crate::JsonObject;

pub(crate) fn compile_output_schema(schema: &JsonObject) -> Result<Validator, String> {
    let schema_value = JsonValue::Object(schema.clone());
    let schema_id = schema
        .get("$schema")
        .and_then(|value| value.as_str())
        .map(normalize_schema_id)
        .unwrap_or(DRAFT202012);

    match schema_id {
        DRAFT202012 => draft202012::new(&schema_value).map_err(|error| error.to_string()),
        DRAFT201909 => draft201909::new(&schema_value).map_err(|error| error.to_string()),
        DRAFT7_HTTP | DRAFT7_HTTPS => draft7::new(&schema_value).map_err(|error| error.to_string()),
        DRAFT6_HTTP | DRAFT6_HTTPS => draft6::new(&schema_value).map_err(|error| error.to_string()),
        DRAFT4_HTTP | DRAFT4_HTTPS => draft4::new(&schema_value).map_err(|error| error.to_string()),
        other => Err(format!("unknown output schema version: {other}")),
    }
}

#[cfg(test)]
#[path = "../tests/internal/output_schema_unit_tests.rs"]
mod tests;
