use std::fmt;
use std::sync::Arc;

use proptest::prelude::*;
use rmcp::model::Tool;
use serde_json::json;
use serde_json::Value as JsonValue;
use tooltest_core::{
    invocation_sequence_strategy, invocation_strategy, InvocationError, ToolPredicate,
};

fn sample<T: fmt::Debug>(strategy: BoxedStrategy<T>) -> T {
    let mut runner = proptest::test_runner::TestRunner::default();
    strategy
        .new_tree(&mut runner)
        .expect("value tree")
        .current()
}

fn tool_with_schema(name: &str, schema: tooltest_core::JsonObject) -> Tool {
    Tool {
        name: name.to_string().into(),
        title: None,
        description: None,
        input_schema: Arc::new(schema),
        output_schema: None,
        annotations: None,
        icons: None,
        meta: None,
    }
}

fn tool_with_schema_value(name: &str, schema: serde_json::Value) -> Tool {
    tool_with_schema(name, schema.as_object().cloned().expect("schema object"))
}

#[test]
fn invocation_strategy_errors_on_empty_tools() {
    let error = invocation_strategy(&[], None).expect_err("no tools");
    assert!(matches!(error, InvocationError::NoEligibleTools));
}

#[test]
fn invocation_strategy_builds_arguments_from_schema() {
    let schema = json!({
        "type": "object",
        "properties": {
            "query": { "const": "hello" }
        }
    })
    .as_object()
    .cloned()
    .expect("schema object");
    let tool = tool_with_schema("search", schema);
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let invocation = sample(strategy);
    assert_eq!(invocation.name.as_ref(), "search");
    let args = invocation.arguments.expect("arguments");
    assert_eq!(args.get("query"), Some(&json!("hello")));
}

#[test]
fn invocation_strategy_applies_predicate() {
    let schema = json!({
        "type": "object",
        "properties": {
            "flag": { "const": true }
        }
    })
    .as_object()
    .cloned()
    .expect("schema object");
    let tool = tool_with_schema("toggle", schema);
    let predicate: ToolPredicate =
        Arc::new(|name, input| name == "toggle" && input.get("flag") == Some(&json!(true)));
    let strategy = invocation_strategy(&[tool], Some(&predicate)).expect("strategy");
    let invocation = sample(strategy);
    assert_eq!(invocation.name.as_ref(), "toggle");
    let args = invocation.arguments.expect("arguments");
    assert_eq!(args.get("flag"), Some(&json!(true)));
}

#[test]
fn invocation_strategy_rejects_non_object_schema() {
    let tool = tool_with_schema_value("bad", json!({ "type": "string" }));
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "inputSchema type must be object, got string");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_missing_type() {
    let tool = tool_with_schema_value("missing", json!({ "properties": {} }));
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "missing");
            assert_eq!(reason, "inputSchema missing type");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_non_string_type() {
    let tool = tool_with_schema_value("bad", json!({ "type": 5 }));
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "inputSchema type must be a string");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_properties_not_object() {
    let tool = tool_with_schema_value("bad", json!({ "type": "object", "properties": [] }));
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "inputSchema properties must be an object");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_property_schema_not_object() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": 5
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "property 'value' schema must be an object");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_enum_empty() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": { "enum": [] }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "enum must include at least one value");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_error_formats_messages() {
    let message = InvocationError::NoEligibleTools.to_string();
    assert_eq!(message, "no eligible tools to generate");

    let message = InvocationError::UnsupportedSchema {
        tool: "echo".to_string(),
        reason: "bad".to_string(),
    }
    .to_string();
    assert_eq!(message, "unsupported schema for tool 'echo': bad");
}

#[test]
fn invocation_strategy_errors_on_property_missing_type() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": {}
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "schema type must be a string");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_array_missing_items() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "items": { "type": "array" }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "array schema must include object-valued items");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_array_items_not_object() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "items": [] }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "array schema must include object-valued items");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_supports_scalar_types_and_structures() {
    let tool = tool_with_schema_value(
        "mixed",
        json!({
            "type": "object",
            "properties": {
                "fixed": { "const": "value" },
                "choice": { "enum": ["a", "b"] },
                "text": { "type": "string" },
                "num": { "type": "number" },
                "int": { "type": "integer" },
                "flag": { "type": "boolean" },
                "list": { "type": "array", "items": { "const": 2 } },
                "object": { "type": "object", "properties": { "inner": { "const": true } } },
                "empty": { "type": "object" }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert_eq!(args.get("fixed"), Some(&json!("value")));
    assert!(matches!(args.get("choice"), Some(JsonValue::String(_))));
    assert!(matches!(args.get("text"), Some(JsonValue::String(_))));
    assert!(matches!(args.get("num"), Some(JsonValue::Number(_))));
    assert!(matches!(args.get("int"), Some(JsonValue::Number(_))));
    assert!(matches!(args.get("flag"), Some(JsonValue::Bool(_))));
    assert!(matches!(args.get("list"), Some(JsonValue::Array(_))));
    assert!(matches!(args.get("object"), Some(JsonValue::Object(_))));
    assert!(matches!(args.get("empty"), Some(JsonValue::Object(_))));
}

#[test]
fn invocation_strategy_defaults_to_empty_object_when_no_properties() {
    let tool = tool_with_schema_value("empty", json!({ "type": "object" }));
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert!(args.is_empty());
}

#[test]
fn invocation_sequence_strategy_generates_in_range() {
    let tool = tool_with_schema_value(
        "echo",
        json!({
            "type": "object",
            "properties": { "value": { "const": "ok" } }
        }),
    );
    let strategy = invocation_sequence_strategy(&[tool], None, 1..=3).expect("strategy");
    let sequence = sample(strategy);
    assert!((1..=3).contains(&sequence.len()));
}

#[test]
fn invocation_strategy_errors_on_nested_property_schema_not_object() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {
                        "bad": 3
                    }
                }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "property 'bad' schema must be an object");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_unsupported_schema_type() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "null" }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "unsupported schema type 'null'");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_array_item_unsupported_schema_type() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "items": { "type": "null" } }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "unsupported schema type 'null'");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_rejects_inputs_when_predicate_fails() {
    let tool = tool_with_schema_value(
        "reject",
        json!({
            "type": "object",
            "properties": {
                "value": { "const": "nope" }
            }
        }),
    );
    let predicate: ToolPredicate = Arc::new(|_, _| false);
    let strategy = invocation_strategy(&[tool], Some(&predicate)).expect("strategy");
    let mut runner = proptest::test_runner::TestRunner::default();
    let result = strategy.new_tree(&mut runner);
    assert!(result.is_err());
}
