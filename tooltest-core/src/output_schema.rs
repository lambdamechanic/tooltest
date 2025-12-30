use jsonschema::{draft201909, draft202012, draft4, draft6, draft7, Validator};
use serde_json::Value as JsonValue;

use crate::JsonObject;

const DRAFT202012: &str = "https://json-schema.org/draft/2020-12/schema";
const DRAFT201909: &str = "https://json-schema.org/draft/2019-09/schema";
const DRAFT7_HTTP: &str = "http://json-schema.org/draft-07/schema";
const DRAFT7_HTTPS: &str = "https://json-schema.org/draft-07/schema";
const DRAFT6_HTTP: &str = "http://json-schema.org/draft-06/schema";
const DRAFT6_HTTPS: &str = "https://json-schema.org/draft-06/schema";
const DRAFT4_HTTP: &str = "http://json-schema.org/draft-04/schema";
const DRAFT4_HTTPS: &str = "https://json-schema.org/draft-04/schema";

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

fn normalize_schema_id(schema_id: &str) -> &str {
    schema_id.strip_suffix('#').unwrap_or(schema_id)
}

#[cfg(test)]
#[path = "../tests/internal/output_schema_unit_tests.rs"]
mod tests;
