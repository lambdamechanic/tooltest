use serde_json::json;
use tooltest_core::{
    parse_call_tool_request, parse_call_tool_result, parse_list_tools, schema_version_label,
    SchemaConfig, SchemaError, SchemaVersion,
};

fn default_config() -> SchemaConfig {
    SchemaConfig {
        version: SchemaVersion::V2025_11_25,
    }
}

#[test]
fn parse_list_tools_accepts_valid_schema() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "value": { "type": "string" }
                    },
                    "required": ["value"]
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config()).expect("list tools");
    assert_eq!(result.tools.len(), 1);
}

#[test]
fn parse_list_tools_rejects_missing_type() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "properties": {
                        "value": { "type": "string" }
                    }
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}

#[test]
fn parse_list_tools_rejects_invalid_required() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "required": [1, 2]
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}

#[test]
fn parse_list_tools_rejects_non_object_type() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": "string"
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}

#[test]
fn parse_list_tools_rejects_non_string_type_field() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": 5
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}

#[test]
fn parse_list_tools_rejects_invalid_schema_field_types() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "$schema": 12,
                    "properties": ["bad"],
                    "required": "bad"
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}

#[test]
fn parse_list_tools_rejects_properties_not_object() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "properties": []
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}

#[test]
fn parse_list_tools_accepts_supported_schema_url() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "$schema": "https://json-schema.org/draft/2020-12/schema"
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(result.is_ok());
}

#[test]
fn parse_list_tools_rejects_unsupported_schema_url() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "$schema": "https://json-schema.org/draft-07/schema#"
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}

#[test]
fn parse_list_tools_rejects_required_not_array() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "properties": {
                        "value": { "type": "string" }
                    },
                    "required": "value"
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}

#[test]
fn parse_list_tools_rejects_invalid_list_payload() {
    let payload = json!({
        "tools": "nope"
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidListTools(_))));
}

#[test]
fn unsupported_schema_version_fails() {
    let config = SchemaConfig {
        version: SchemaVersion::Other("2025-12-01".to_string()),
    };
    let payload = json!({ "tools": [] });
    let result = parse_list_tools(payload, &config);
    assert!(matches!(
        result,
        Err(SchemaError::UnsupportedSchemaVersion(_))
    ));
}

#[test]
fn supported_other_version_is_accepted() {
    let config = SchemaConfig {
        version: SchemaVersion::Other("2025-11-25".to_string()),
    };
    let payload = json!({ "tools": [] });
    let result = parse_list_tools(payload, &config);
    assert!(result.is_ok());
}

#[test]
fn parse_call_tool_request_uses_rmcp_type() {
    let payload = json!({
        "name": "echo",
        "arguments": {
            "value": "hello"
        }
    });
    let result = parse_call_tool_request(payload, &default_config()).expect("call request");
    assert_eq!(result.name, "echo");
}

#[test]
fn parse_call_tool_request_rejects_unsupported_schema_version() {
    let config = SchemaConfig {
        version: SchemaVersion::Other("2025-12-01".to_string()),
    };
    let payload = json!({
        "name": "echo",
        "arguments": {
            "value": "hello"
        }
    });
    let result = parse_call_tool_request(payload, &config);
    assert!(matches!(
        result,
        Err(SchemaError::UnsupportedSchemaVersion(_))
    ));
}

#[test]
fn parse_call_tool_request_rejects_invalid_payload() {
    let payload = json!({
        "arguments": {
            "value": "hello"
        }
    });
    let result = parse_call_tool_request(payload, &default_config());
    assert!(matches!(
        result,
        Err(SchemaError::InvalidCallToolRequest(_))
    ));
}

#[test]
fn parse_call_tool_result_uses_rmcp_type() {
    let payload = json!({
        "content": [
            { "type": "text", "text": "ok" }
        ],
        "isError": false
    });
    let result = parse_call_tool_result(payload, &default_config()).expect("call result");
    assert_eq!(result.content.len(), 1);
}

#[test]
fn parse_call_tool_result_rejects_unsupported_schema_version() {
    let config = SchemaConfig {
        version: SchemaVersion::Other("2025-12-01".to_string()),
    };
    let payload = json!({
        "content": [
            { "type": "text", "text": "ok" }
        ],
        "isError": false
    });
    let result = parse_call_tool_result(payload, &config);
    assert!(matches!(
        result,
        Err(SchemaError::UnsupportedSchemaVersion(_))
    ));
}

#[test]
fn parse_call_tool_result_rejects_invalid_payload() {
    let payload = json!({});
    let result = parse_call_tool_result(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidCallToolResult(_))));
}

#[test]
fn parse_list_tools_rejects_output_schema_with_string_type() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "value": { "type": "string" }
                    }
                },
                "outputSchema": {
                    "type": 5
                }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}

#[test]
fn schema_error_formats_messages() {
    let errors = vec![
        SchemaError::UnsupportedSchemaVersion("2025-12-01".to_string()),
        SchemaError::InvalidListTools("bad".to_string()),
        SchemaError::InvalidCallToolRequest("bad".to_string()),
        SchemaError::InvalidCallToolResult("bad".to_string()),
        SchemaError::InvalidToolSchema {
            tool: "echo".to_string(),
            field: "inputSchema".to_string(),
            reason: "bad".to_string(),
        },
    ];
    for error in errors {
        let message = error.to_string();
        assert!(!message.is_empty());
    }
}

#[test]
fn schema_version_label_formats_versions() {
    let label = schema_version_label(&SchemaVersion::V2025_11_25);
    assert_eq!(label.as_ref(), "2025-11-25");
    let custom = SchemaVersion::Other("custom".to_string());
    let label = schema_version_label(&custom);
    assert_eq!(label.as_ref(), "custom");
}

#[test]
fn validate_tool_schema_allows_output_schema() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": { "type": "object" },
                "outputSchema": { "type": "object" }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(result.is_ok());
}

#[test]
fn parse_list_tools_rejects_invalid_output_schema() {
    let payload = json!({
        "tools": [
            {
                "name": "echo",
                "inputSchema": { "type": "object" },
                "outputSchema": { "type": "string" }
            }
        ]
    });
    let result = parse_list_tools(payload, &default_config());
    assert!(matches!(result, Err(SchemaError::InvalidToolSchema { .. })));
}
