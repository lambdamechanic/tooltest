use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use crate::generator::{
    decode_pointer_segment, invocation_sequence_strategy, invocation_strategy,
    invocation_strategy_from_corpus, path_from_pointer, schema_violations, ConstraintKind,
    InvocationError, PathSegment, ValueCorpus,
};
use crate::{JsonObject, StateMachineConfig, ToolPredicate};
use jsonschema::draft202012;
use nonempty::nonempty;
use proptest::prelude::*;
use rmcp::model::Tool;
use serde_json::json;
use serde_json::Value as JsonValue;

fn sample<T: fmt::Debug>(strategy: BoxedStrategy<T>) -> T {
    let mut runner = proptest::test_runner::TestRunner::default();
    strategy
        .new_tree(&mut runner)
        .expect("value tree")
        .current()
}

fn sample_many<T: fmt::Debug>(strategy: BoxedStrategy<T>, count: usize) -> Vec<T> {
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = strategy
            .new_tree(&mut runner)
            .expect("value tree")
            .current();
        values.push(value);
    }
    values
}

fn tool_with_schema(name: &str, schema: JsonObject) -> Tool {
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

fn schema_key() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::range('a', 'z'), 1..=8)
        .prop_map(|chars| chars.into_iter().collect())
}

fn scalar_json_value() -> impl Strategy<Value = JsonValue> {
    prop_oneof![
        any::<bool>().prop_map(JsonValue::Bool),
        any::<i64>().prop_map(JsonValue::from),
        proptest::collection::vec(proptest::char::range('a', 'z'), 1..=8)
            .prop_map(|chars| JsonValue::String(chars.into_iter().collect())),
    ]
}

fn schema_leaf() -> impl Strategy<Value = JsonValue> {
    prop_oneof![
        Just(json!({ "type": "string" })),
        Just(json!({ "type": "string", "minLength": 1, "maxLength": 4 })),
        Just(json!({ "type": "string", "minLength": 1, "maxLength": 4, "pattern": "a+" })),
        Just(json!({ "type": "number" })),
        Just(json!({ "type": "number", "minimum": 0.0, "maximum": 10.0 })),
        Just(json!({ "type": "integer" })),
        Just(json!({ "type": "integer", "minimum": -3.0, "maximum": 3.0 })),
        Just(json!({ "type": "boolean" })),
        scalar_json_value().prop_map(|value| json!({ "const": value })),
        proptest::collection::vec(scalar_json_value(), 1..=4)
            .prop_map(|values| json!({ "enum": values })),
    ]
}

fn schema_object_with_required(
    properties: BTreeMap<String, JsonValue>,
) -> BoxedStrategy<JsonValue> {
    let keys: Vec<String> = properties.keys().cloned().collect();
    let required_strategy: BoxedStrategy<Vec<String>> = if keys.is_empty() {
        Just(Vec::new()).boxed()
    } else {
        proptest::collection::vec(proptest::sample::select(keys.clone()), 0..=keys.len())
            .prop_map(|mut required| {
                required.sort();
                required.dedup();
                required
            })
            .boxed()
    };

    required_strategy
        .prop_map(move |required| {
            let mut schema = json!({ "type": "object", "properties": properties.clone() });
            if !required.is_empty() {
                schema
                    .as_object_mut()
                    .expect("schema object")
                    .insert("required".to_string(), json!(required));
            }
            schema
        })
        .boxed()
}

fn schema_value_strategy() -> impl Strategy<Value = JsonValue> {
    schema_leaf().prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            proptest::collection::btree_map(schema_key(), inner.clone(), 0..=4)
                .prop_flat_map(schema_object_with_required),
            inner.prop_flat_map(|items| {
                prop_oneof![
                    Just(json!({ "type": "array", "items": items.clone() })),
                    Just(json!({
                        "type": "array",
                        "items": items.clone(),
                        "minItems": 1,
                        "maxItems": 3
                    })),
                    Just(json!({
                        "type": "array",
                        "items": items,
                        "minItems": 0,
                        "maxItems": 0
                    })),
                ]
            }),
        ]
    })
}

fn schema_strategy() -> impl Strategy<Value = JsonValue> {
    proptest::collection::btree_map(schema_key(), schema_value_strategy(), 0..=4)
        .prop_flat_map(schema_object_with_required)
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
            "query": { "const": "hello" },
            "required": { "const": "present" }
        }
    })
    .as_object()
    .cloned()
    .expect("schema object");
    let schema = {
        let mut schema = schema;
        schema.insert("required".to_string(), json!(["required"]));
        schema
    };
    let tool = tool_with_schema("search", schema);
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let invocation = sample(strategy);
    assert_eq!(invocation.name.as_ref(), "search");
    let args = invocation.arguments.expect("arguments");
    assert_eq!(args.get("query"), Some(&json!("hello")));
    assert_eq!(args.get("required"), Some(&json!("present")));
}

#[test]
fn invocation_strategy_respects_oneof_required_properties() {
    let tool = tool_with_schema_value(
        "related",
        json!({
            "type": "object",
            "properties": {
                "vendor": { "type": "string" },
                "product": { "type": "string" }
            },
            "oneOf": [
                { "required": ["vendor"] },
                { "required": ["product"] }
            ]
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let samples = sample_many(strategy, 32);
    for invocation in samples {
        let args = invocation.arguments.expect("arguments");
        assert!(
            args.contains_key("vendor") || args.contains_key("product"),
            "expected vendor or product"
        );
        assert!(!args.is_empty(), "expected non-empty arguments");
    }
}

#[test]
fn state_machine_invocation_strategy_respects_oneof_required_properties() {
    let tool = tool_with_schema_value(
        "related",
        json!({
            "type": "object",
            "properties": {
                "vendor": { "type": "string" },
                "product": { "type": "string" }
            },
            "oneOf": [
                { "required": ["vendor"] },
                { "required": ["product"] }
            ]
        }),
    );
    let config = StateMachineConfig {
        seed_strings: vec!["acme".to_string(), "widget".to_string()],
        ..Default::default()
    };
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(config.seed_strings.clone());
    let strategy = invocation_strategy_from_corpus(&[tool], None, &corpus, false)
        .expect("strategy")
        .expect("callable");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert!(
        args.contains_key("vendor") || args.contains_key("product"),
        "expected vendor or product"
    );
    assert!(!args.is_empty(), "expected non-empty arguments");
}

#[test]
fn invocation_strategy_resolves_ref_in_items_schema() {
    let tool = tool_with_schema_value(
        "related",
        json!({
            "type": "object",
            "$defs": {
                "relatedField": {
                    "type": "string",
                    "enum": ["cveID", "vendorProject"]
                }
            },
            "properties": {
                "fields": {
                    "type": "array",
                    "minItems": 1,
                    "items": { "$ref": "#/$defs/relatedField" }
                }
            },
            "required": ["fields"]
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    let fields = args
        .get("fields")
        .and_then(JsonValue::as_array)
        .expect("fields array");
    assert!(!fields.is_empty());
    for field in fields {
        let value = field.as_str().expect("field string");
        assert!(matches!(value, "cveID" | "vendorProject"));
    }
}

#[test]
fn invocation_strategy_generates_for_kev_related_cves_schema() {
    let schema: JsonValue = serde_json::from_str(include_str!(
        "../../tests/fixtures/kev_get_related_cves_schema.json"
    ))
    .expect("schema json");
    let tool = tool_with_schema_value("get_related_cves", schema);
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let mut runner = proptest::test_runner::TestRunner::default();
    for _ in 0..32 {
        let invocation = strategy
            .new_tree(&mut runner)
            .expect("value tree")
            .current();
        let args = invocation.arguments.expect("arguments");
        assert!(args.contains_key("vendor") || args.contains_key("product"));
    }
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
    let schema = {
        let mut schema = schema;
        schema.insert("required".to_string(), json!(["flag"]));
        schema
    };
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
fn invocation_strategy_respects_min_length() {
    let tool = tool_with_schema_value(
        "short",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "string", "minLength": 5 }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let samples = sample_many(strategy, 64);
    let all_long_enough = samples.iter().all(|invocation| {
        invocation
            .arguments
            .as_ref()
            .and_then(|args| args.get("value"))
            .and_then(JsonValue::as_str)
            .is_some_and(|value| value.chars().count() >= 5)
    });
    assert!(all_long_enough, "expected all values to satisfy minLength");
}

#[test]
fn invocation_strategy_respects_max_length() {
    let tool = tool_with_schema_value(
        "long",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "string", "maxLength": 3 }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let samples = sample_many(strategy, 64);
    let all_short_enough = samples.iter().all(|invocation| {
        invocation
            .arguments
            .as_ref()
            .and_then(|args| args.get("value"))
            .and_then(JsonValue::as_str)
            .is_some_and(|value| value.chars().count() <= 3)
    });
    assert!(all_short_enough, "expected all values to satisfy maxLength");
}

#[test]
fn invocation_strategy_respects_pattern() {
    let tool = tool_with_schema_value(
        "pattern",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "string", "pattern": "a+" }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let regex = regex::Regex::new("a+").expect("regex");
    let samples = sample_many(strategy, 64);
    let all_match = samples.iter().all(|invocation| {
        invocation
            .arguments
            .as_ref()
            .and_then(|args| args.get("value"))
            .and_then(JsonValue::as_str)
            .is_some_and(|value| regex.is_match(value))
    });
    assert!(all_match, "expected all values to satisfy pattern");
}

#[test]
fn invocation_strategy_errors_on_invalid_string_length_bounds() {
    let tool = tool_with_schema_value(
        "invalid",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "string", "minLength": 3, "maxLength": 1 }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "invalid");
            assert_eq!(reason, "maxLength must be >= minLength");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_allows_anchored_pattern() {
    let tool = tool_with_schema_value(
        "anchored",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "string", "pattern": "^a+$" }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let regex = regex::Regex::new("^a+$").expect("regex");
    let samples = sample_many(strategy, 32);
    let all_match = samples.iter().all(|invocation| {
        invocation
            .arguments
            .as_ref()
            .and_then(|args| args.get("value"))
            .and_then(JsonValue::as_str)
            .is_some_and(|value| regex.is_match(value))
    });
    assert!(all_match, "expected all values to satisfy anchored pattern");
}

#[test]
fn invocation_strategy_errors_on_boundary_pattern() {
    let tool = tool_with_schema_value(
        "invalid",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "string", "pattern": "\\bfoo\\b" }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "invalid");
            assert!(reason.contains("word boundary"));
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_respects_number_bounds() {
    let tool = tool_with_schema_value(
        "bounded",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "number", "minimum": 2.0, "maximum": 3.0 }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let samples = sample_many(strategy, 64);
    let all_in_range = samples.iter().all(|invocation| {
        invocation
            .arguments
            .as_ref()
            .and_then(|args| args.get("value"))
            .and_then(JsonValue::as_f64)
            .is_some_and(|value| (2.0..=3.0).contains(&value))
    });
    assert!(all_in_range, "expected all values to satisfy number bounds");
}

#[test]
fn invocation_strategy_errors_on_invalid_number_bounds() {
    let tool = tool_with_schema_value(
        "invalid",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "number", "minimum": 5.0, "maximum": 1.0 }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "invalid");
            assert_eq!(reason, "maximum must be >= minimum");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_invalid_integer_bounds() {
    let tool = tool_with_schema_value(
        "invalid",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": "integer", "minimum": 5.0, "maximum": 1.0 }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "invalid");
            assert_eq!(reason, "maximum must be >= minimum");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_respects_array_bounds() {
    let tool = tool_with_schema_value(
        "bounded",
        json!({
            "type": "object",
            "properties": {
                "value": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 2,
                    "items": { "type": "boolean" }
                }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let samples = sample_many(strategy, 64);
    let all_in_range = samples.iter().all(|invocation| {
        invocation
            .arguments
            .as_ref()
            .and_then(|args| args.get("value"))
            .and_then(JsonValue::as_array)
            .is_some_and(|items| !items.is_empty() && items.len() <= 2)
    });
    assert!(all_in_range, "expected all values to satisfy array bounds");
}

#[test]
fn invocation_strategy_errors_on_invalid_array_bounds() {
    let tool = tool_with_schema_value(
        "invalid",
        json!({
            "type": "object",
            "properties": {
                "value": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 1,
                    "items": { "type": "boolean" }
                }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "invalid");
            assert_eq!(reason, "maxItems must be >= minItems");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_required_unknown_property() {
    let tool = tool_with_schema_value(
        "invalid",
        json!({
            "type": "object",
            "required": ["missing"],
            "properties": {
                "present": { "type": "string" }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "invalid");
            assert_eq!(
                reason,
                "inputSchema required must reference known properties"
            );
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_required_without_properties() {
    let tool = tool_with_schema_value(
        "invalid",
        json!({
            "type": "object",
            "required": ["missing"]
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "invalid");
            assert_eq!(
                reason,
                "inputSchema required must be empty when no properties exist"
            );
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_nested_required_unknown_property() {
    let tool = tool_with_schema_value(
        "invalid",
        json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "required": ["missing"],
                    "properties": { "present": { "type": "string" } }
                }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "invalid");
            assert_eq!(reason, "required must reference known properties");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_nested_required_without_properties() {
    let tool = tool_with_schema_value(
        "invalid",
        json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "required": ["missing"]
                }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "invalid");
            assert_eq!(reason, "required must be empty when no properties exist");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_allows_nested_empty_required_without_properties() {
    let tool = tool_with_schema_value(
        "valid",
        json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "required": []
                }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert!(matches!(args.get("nested"), Some(JsonValue::Object(_))));
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

proptest_async::proptest! {
    #[test]
    fn invocation_strategy_generates_values_matching_schema(schema in schema_strategy()) {
        let schema_object = schema.as_object().cloned().expect("schema object");
        let tool = tool_with_schema("generated", schema_object);
        let strategy = invocation_strategy(&[tool], None).expect("strategy");
        let validator = draft202012::new(&schema).expect("schema compile");

        let properties = schema
            .get("properties")
            .and_then(JsonValue::as_object)
            .cloned()
            .unwrap_or_default();

        let mut runner = proptest::test_runner::TestRunner::default();
        for _ in 0..8 {
            let invocation = strategy.new_tree(&mut runner).expect("value tree").current();
            let args = invocation.arguments.expect("arguments");
            for key in properties.keys() {
                prop_assert!(args.contains_key(key));
            }
            let instance = JsonValue::Object(args);
            prop_assert!(validator.validate(&instance).is_ok());
        }
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
fn invocation_error_exposes_no_source() {
    let error = InvocationError::NoEligibleTools;
    assert!(std::error::Error::source(&error).is_none());
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
            assert_eq!(reason, "schema type must be a string or array of strings");
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
                "empty": { "type": "null" },
                "list": { "type": "array", "items": { "const": 2 } },
                "object": { "type": "object", "properties": { "inner": { "const": true } } },
                "map": { "type": "object" }
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
    assert!(matches!(args.get("empty"), Some(JsonValue::Null)));
    assert!(matches!(args.get("list"), Some(JsonValue::Array(_))));
    assert!(matches!(args.get("object"), Some(JsonValue::Object(_))));
    assert!(matches!(args.get("map"), Some(JsonValue::Object(_))));
}

#[test]
fn invocation_strategy_supports_anyof_union() {
    let tool = tool_with_schema_value(
        "union",
        json!({
            "type": "object",
            "properties": {
                "value": {
                    "anyOf": [
                        { "type": "string", "minLength": 2 },
                        { "type": "number", "minimum": 2.0 }
                    ]
                }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    let value = args.get("value").expect("value");
    let schema = json!({
        "anyOf": [
            { "type": "string", "minLength": 2 },
            { "type": "number", "minimum": 2.0 }
        ]
    });
    let validator = draft202012::new(&schema).expect("schema compile");
    assert!(validator.validate(value).is_ok());
}

#[test]
fn invocation_strategy_supports_oneof_union() {
    let tool = tool_with_schema_value(
        "union",
        json!({
            "type": "object",
            "properties": {
                "value": {
                    "oneOf": [
                        { "type": "string", "minLength": 2 },
                        { "type": "number", "minimum": 2.0 }
                    ]
                }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    let value = args.get("value").expect("value");
    let schema = json!({
        "oneOf": [
            { "type": "string", "minLength": 2 },
            { "type": "number", "minimum": 2.0 }
        ]
    });
    let validator = draft202012::new(&schema).expect("schema compile");
    assert!(validator.validate(value).is_ok());
}

#[test]
fn invocation_strategy_supports_nullable_type_union() {
    let tool = tool_with_schema_value(
        "nullable",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": ["string", "null"], "minLength": 1 }
            }
        }),
    );
    let strategy = invocation_strategy(&[tool], None).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    let value = args.get("value").expect("value");
    let schema = json!({ "type": ["string", "null"], "minLength": 1 });
    let validator = draft202012::new(&schema).expect("schema compile");
    assert!(validator.validate(value).is_ok());
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
fn invocation_strategy_allows_empty_required_without_properties() {
    let tool = tool_with_schema_value("empty", json!({ "type": "object", "required": [] }));
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
fn invocation_sequence_strategy_errors_on_empty_tools() {
    let error = invocation_sequence_strategy(&[], None, 1..=1).expect_err("error");
    assert!(matches!(error, InvocationError::NoEligibleTools));
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
fn invocation_strategy_errors_on_nested_property_missing_type() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {
                        "value": {}
                    }
                }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "schema type must be a string or array of strings");
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
                "value": { "type": "unknown" }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "unsupported schema type 'unknown'");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_anyof_empty() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": { "anyOf": [] }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "anyOf must include at least one schema object");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_oneof_empty() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": { "oneOf": [] }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "oneOf must include at least one schema object");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_anyof_non_object_branch() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": { "anyOf": ["nope"] }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "anyOf[0] schema must be an object");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_oneof_non_object_branch() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": { "oneOf": ["nope"] }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "oneOf[0] schema must be an object");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_anyof_branch_invalid_type() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": {
                    "anyOf": [
                        { "type": "string" },
                        { "type": "unknown" }
                    ]
                }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "unsupported schema type 'unknown'");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_empty_type_union() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": [] }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "schema type array must include at least one string");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_array_items_missing_type() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "list": { "type": "array", "items": {} }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(reason, "schema type must be a string or array of strings");
        }
        _ => panic!("expected UnsupportedSchema"),
    }
}

#[test]
fn invocation_strategy_errors_on_type_union_non_string() {
    let tool = tool_with_schema_value(
        "bad",
        json!({
            "type": "object",
            "properties": {
                "value": { "type": ["string", 5] }
            }
        }),
    );
    let error = invocation_strategy(&[tool], None).expect_err("error");
    match error {
        InvocationError::UnsupportedSchema { tool, reason } => {
            assert_eq!(tool, "bad");
            assert_eq!(
                reason,
                "schema type array must contain strings; found 5 at 1"
            );
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
    let error = invocation_strategy(&[tool], Some(&predicate)).expect_err("error");
    assert!(matches!(error, InvocationError::NoEligibleTools));
}

#[test]
fn schema_violations_detect_constraints() {
    let schema = json!({
        "type": "object",
        "required": ["required"],
        "properties": {
            "const": { "const": "fixed" },
            "enum": { "enum": ["one", "two"] },
            "text": { "type": "string", "minLength": 2, "maxLength": 0, "pattern": "^a+$" },
            "number": { "type": "number", "minimum": 6.0, "maximum": 4.0 },
            "list": { "type": "array", "minItems": 2, "maxItems": 0, "items": { "type": "string", "minLength": 2 } }
        }
    });

    let value = json!({
        "const": "bad",
        "enum": "three",
        "text": "b",
        "number": 5,
        "list": ["x"]
    });

    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Const(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Enum(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MinLength(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MaxLength(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Pattern(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Minimum(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Maximum(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MinItems(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MaxItems(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Required(_))));
}

#[test]
fn schema_violations_reports_enum_bounds_and_required() {
    let schema = json!({
        "type": "object",
        "required": ["required"],
        "properties": {
            "required": { "type": "string" },
            "enum": { "enum": ["one", "two"] },
            "min": { "type": "number", "minimum": 2.0 },
            "max": { "type": "number", "maximum": 2.0 }
        }
    });
    let value = json!({
        "enum": "three",
        "min": 1.0,
        "max": 3.0
    });

    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Enum(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Minimum(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Maximum(_))));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Required(_))));
}

#[test]
fn schema_violations_accepts_matching_string_constraints() {
    let schema = json!({
        "type": "object",
        "properties": {
            "text": { "type": "string", "minLength": 1, "maxLength": 3, "pattern": "^a+$" }
        }
    });
    let value = json!({ "text": "aa" });
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MinLength(_))));
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MaxLength(_))));
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Pattern(_))));
}

#[test]
fn schema_violations_accepts_number_bounds() {
    let schema = json!({
        "type": "object",
        "properties": {
            "number": { "type": "number", "minimum": 1.0, "maximum": 10.0 }
        }
    });
    let value = json!({ "number": 5.0 });
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Minimum(_))));
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Maximum(_))));
}

#[test]
fn schema_violations_accepts_array_bounds() {
    let schema = json!({
        "type": "object",
        "properties": {
            "list": { "type": "array", "minItems": 1, "maxItems": 3 }
        }
    });
    let value = json!({ "list": [1, 2] });
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MinItems(_))));
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MaxItems(_))));
}

#[test]
fn schema_violations_accepts_required_present() {
    let schema = json!({
        "type": "object",
        "required": ["required"],
        "properties": {
            "required": { "type": "string" }
        }
    });
    let value = json!({ "required": "ok" });
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Required(_))));
}

#[test]
fn schema_violations_accepts_anyof_branch() {
    let schema = json!({
        "anyOf": [
            { "type": "string", "minLength": 2 },
            { "type": "number", "minimum": 5.0 }
        ]
    });
    let string_ok = json!("ok");
    let number_ok = json!(6.0);
    assert!(schema_violations(schema.as_object().expect("schema object"), &string_ok).is_empty());
    assert!(schema_violations(schema.as_object().expect("schema object"), &number_ok).is_empty());
}

#[test]
fn schema_violations_accepts_oneof_branch() {
    let schema = json!({
        "oneOf": [
            { "type": "string", "minLength": 2 },
            { "type": "number", "minimum": 5.0 }
        ]
    });
    let string_ok = json!("ok");
    let number_ok = json!(6.0);
    assert!(schema_violations(schema.as_object().expect("schema object"), &string_ok).is_empty());
    assert!(schema_violations(schema.as_object().expect("schema object"), &number_ok).is_empty());
}

#[test]
fn schema_violations_reports_anyof_base_constraints() {
    let schema = json!({
        "anyOf": [
            { "type": "string" },
            { "type": "number" }
        ],
        "maxLength": 2
    });
    let value = json!("toolong");
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MaxLength(2))));
}

#[test]
fn schema_violations_reports_oneof_base_constraints() {
    let schema = json!({
        "oneOf": [
            { "type": "string" },
            { "type": "number" }
        ],
        "maxLength": 1
    });
    let value = json!("toolong");
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::MaxLength(1))));
}

#[test]
fn schema_violations_reports_type_union_miss() {
    let schema = json!({ "type": ["string", "number"], "minLength": 2 });
    let value = json!(true);
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(!violations.is_empty());
}

#[test]
fn schema_violations_rejects_anyof_miss() {
    let schema = json!({
        "anyOf": [
            { "type": "string", "minLength": 4 },
            { "type": "number", "minimum": 10.0 }
        ]
    });
    let value = json!("no");
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(!violations.is_empty());
}

#[test]
fn schema_violations_rejects_oneof_miss() {
    let schema = json!({
        "oneOf": [
            { "type": "string", "minLength": 2 },
            { "type": "number", "minimum": 3.0 }
        ]
    });
    let value = json!(true);
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Type(_))));
}

#[test]
fn schema_violations_rejects_oneof_multiple_matches() {
    let schema = json!({
        "oneOf": [
            { "type": "string", "minLength": 2 },
            { "type": "string", "pattern": "^a+$" }
        ]
    });
    let value = json!("aa");
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::OneOfMatches(2))));
}

#[test]
fn schema_violations_accepts_nullable_type_union() {
    let schema = json!({ "type": ["string", "null"], "minLength": 2 });
    let value = json!(null);
    assert!(schema_violations(schema.as_object().expect("schema object"), &value).is_empty());
}

#[test]
fn schema_violations_accepts_const_and_enum() {
    let schema = json!({
        "type": "object",
        "properties": {
            "const": { "const": "fixed" },
            "enum": { "enum": ["a", "b"] }
        }
    });
    let value = json!({
        "const": "fixed",
        "enum": "a"
    });
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Const(_))));
    assert!(!violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Enum(_))));
}

#[test]
fn schema_violations_skips_non_object_property_schema() {
    let schema = json!({
        "type": "object",
        "properties": {
            "bad": 3
        }
    });
    let value = json!({ "bad": "x" });
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(!violations
        .iter()
        .any(|violation| { violation.path == nonempty![PathSegment::Key("bad".to_string())] }));
}

#[test]
fn schema_violations_covers_type_matching() {
    let cases = vec![
        ("string", json!("text")),
        ("number", json!(1.2)),
        ("integer", json!(1)),
        ("integer", json!(u64::MAX)),
        ("boolean", json!(true)),
        ("array", json!([1])),
        ("object", json!({})),
        ("null", json!(null)),
        ("unknown", json!(null)),
    ];

    for (schema_type, value) in cases {
        let schema = json!({ "type": schema_type });
        let _ = schema_violations(schema.as_object().expect("schema object"), &value);
    }
}

#[test]
fn schema_violations_handles_invalid_pattern() {
    let schema = json!({
        "type": "object",
        "properties": { "value": { "type": "string", "pattern": "[" } }
    });
    let value = json!({ "value": "text" });
    let violations = schema_violations(schema.as_object().expect("schema object"), &value);
    assert!(violations
        .iter()
        .any(|violation| matches!(violation.kind, ConstraintKind::Pattern(_))));
}

#[test]
fn decode_pointer_segment_handles_escapes() {
    let input = std::hint::black_box("a~1b");
    assert_eq!(decode_pointer_segment(input), "a/b");
    let input = std::hint::black_box("a~0b");
    assert_eq!(decode_pointer_segment(input), "a~b");
    let input = std::hint::black_box("a~2b");
    assert_eq!(decode_pointer_segment(input), "a~2b");
    let input = std::hint::black_box("a~");
    assert_eq!(decode_pointer_segment(input), "a~");
}

#[test]
fn path_from_pointer_decodes_indices_and_keys() {
    let path = path_from_pointer("/items/0/a~1b/a~0b");
    assert_eq!(
        path,
        vec![
            PathSegment::Key("items".to_string()),
            PathSegment::Index(0),
            PathSegment::Key("a/b".to_string()),
            PathSegment::Key("a~b".to_string())
        ]
    );
}

#[test]
fn path_from_pointer_empty_returns_empty_vec() {
    let path = path_from_pointer("");
    assert!(path.is_empty());
}

#[test]
fn schema_violations_skips_missing_property_values() {
    let schema = json!({
        "type": "object",
        "properties": {
            "present": { "type": "string", "minLength": 2 },
            "missing": { "type": "string", "minLength": 2 }
        }
    });
    let value = json!({ "present": "ok" });
    let _ = schema_violations(schema.as_object().expect("schema object"), &value);
}
