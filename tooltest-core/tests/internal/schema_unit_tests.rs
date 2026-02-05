use super::*;
use serde_json::json;

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
fn schema_id_for_defaults_when_missing() {
    let schema_id = schema_id_for(&json!({ "$defs": {} }));
    assert_eq!(schema_id, json!(DEFAULT_SCHEMA_ID));
}
