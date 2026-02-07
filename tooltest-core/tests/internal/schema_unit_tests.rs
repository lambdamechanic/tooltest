use super::*;
use serde_json::json;
use std::sync::OnceLock;

#[test]
fn parse_list_tools_payload_accepts_valid_value() {
    let result = parse_list_tools_payload(json!({ "tools": [] }));
    assert!(result.is_ok());
}

#[test]
fn parse_list_tools_payload_rejects_invalid_value() {
    let result = parse_list_tools_payload(JsonValue::Null);
    assert!(result.is_err());
}

#[test]
fn parse_call_tool_request_payload_accepts_valid_value() {
    let result = parse_call_tool_request_payload(json!({ "name": "noop", "arguments": {} }));
    assert!(result.is_ok());
}

#[test]
fn parse_call_tool_request_payload_rejects_invalid_value() {
    let result = parse_call_tool_request_payload(JsonValue::Null);
    assert!(result.is_err());
}

#[test]
fn validators_build_and_cache() {
    let config = SchemaConfig::default();
    let first = list_tools_validator(&config).expect("list tools validator");
    let second = list_tools_validator(&config).expect("list tools validator");
    assert!(std::ptr::eq(first, second));

    let first = call_tool_request_validator(&config).expect("call tool validator");
    let second = call_tool_request_validator(&config).expect("call tool validator");
    assert!(std::ptr::eq(first, second));
}

#[test]
fn build_validator_for_def_rejects_unknown_def() {
    let error = build_validator_for_def(MCP_SCHEMA, "DefinitelyMissing").expect_err("error");
    assert!(error.contains("failed to compile MCP schema"));
}

#[test]
fn build_validator_for_def_rejects_invalid_schema_json() {
    let error = build_validator_for_def("{", "ListToolsResult").expect_err("error");
    assert!(error.contains("failed to parse MCP schema JSON"));
}

#[test]
fn build_validator_for_def_rejects_schema_missing_defs() {
    let schema_json = r#"{ "$schema": "https://json-schema.org/draft/2020-12/schema" }"#;
    let error = build_validator_for_def(schema_json, "ListToolsResult").expect_err("error");
    assert!(error.contains("missing $defs"));
}

#[test]
fn validator_for_def_maps_init_errors_for_list_tools() {
    let lock: OnceLock<Result<Validator, String>> = OnceLock::new();
    let error = validator_for_def(&lock, "{", "ListToolsResult", SchemaError::InvalidListTools)
        .expect_err("error");
    let SchemaError::InvalidListTools(message) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(message.contains("failed to parse MCP schema JSON"));
}

#[test]
fn validator_for_def_maps_init_errors_for_call_tool_request() {
    let lock: OnceLock<Result<Validator, String>> = OnceLock::new();
    let error = validator_for_def(
        &lock,
        "{",
        "CallToolRequestParams",
        SchemaError::InvalidCallToolRequest,
    )
    .expect_err("error");
    let SchemaError::InvalidCallToolRequest(message) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert!(message.contains("failed to parse MCP schema JSON"));
}

#[test]
fn schema_id_for_defaults_when_missing() {
    let schema_id = schema_id_for(&json!({ "$defs": {} }));
    assert_eq!(schema_id, json!(DEFAULT_SCHEMA_ID));
}
