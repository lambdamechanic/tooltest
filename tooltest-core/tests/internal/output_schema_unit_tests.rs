use super::compile_output_schema;
use serde_json::json;

#[test]
fn compile_output_schema_defaults_to_draft_2020_12() {
    let schema = json!({
        "type": "object",
        "properties": { "status": { "type": "string" } }
    });
    let validator = compile_output_schema(schema.as_object().expect("schema object"));
    assert!(validator.is_ok());
}

#[test]
fn compile_output_schema_accepts_draft_2019_09() {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2019-09/schema",
        "type": "object"
    });
    let validator = compile_output_schema(schema.as_object().expect("schema object"));
    assert!(validator.is_ok());
}

#[test]
fn compile_output_schema_accepts_draft_07() {
    let schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object"
    });
    let validator = compile_output_schema(schema.as_object().expect("schema object"));
    assert!(validator.is_ok());
}

#[test]
fn compile_output_schema_accepts_draft_06() {
    let schema = json!({
        "$schema": "https://json-schema.org/draft-06/schema",
        "type": "object"
    });
    let validator = compile_output_schema(schema.as_object().expect("schema object"));
    assert!(validator.is_ok());
}

#[test]
fn compile_output_schema_accepts_draft_04() {
    let schema = json!({
        "$schema": "http://json-schema.org/draft-04/schema",
        "type": "object"
    });
    let validator = compile_output_schema(schema.as_object().expect("schema object"));
    assert!(validator.is_ok());
}

#[test]
fn compile_output_schema_rejects_unknown_schema() {
    let schema = json!({
        "$schema": "https://example.com/unknown",
        "type": "object"
    });
    let error = compile_output_schema(schema.as_object().expect("schema object"))
        .expect_err("unknown schema");
    assert!(error.contains("unknown output schema version"));
}

#[test]
fn compile_output_schema_rejects_invalid_default_schema() {
    let schema = json!({
        "type": 5
    });
    assert!(compile_output_schema(schema.as_object().expect("schema object")).is_err());
}

#[test]
fn compile_output_schema_rejects_invalid_draft_2019_09() {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2019-09/schema",
        "type": 5
    });
    assert!(compile_output_schema(schema.as_object().expect("schema object")).is_err());
}

#[test]
fn compile_output_schema_rejects_invalid_draft_07() {
    let schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema",
        "type": 5
    });
    assert!(compile_output_schema(schema.as_object().expect("schema object")).is_err());
}

#[test]
fn compile_output_schema_rejects_invalid_draft_06() {
    let schema = json!({
        "$schema": "https://json-schema.org/draft-06/schema",
        "type": 5
    });
    assert!(compile_output_schema(schema.as_object().expect("schema object")).is_err());
}

#[test]
fn compile_output_schema_rejects_invalid_draft_04() {
    let schema = json!({
        "$schema": "http://json-schema.org/draft-04/schema",
        "type": 5
    });
    assert!(compile_output_schema(schema.as_object().expect("schema object")).is_err());
}
