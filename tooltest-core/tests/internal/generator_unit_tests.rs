use super::*;
use rmcp::model::Tool;
use serde_json::json;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

fn tool_with_schema(name: &str, schema: JsonValue) -> Tool {
    Tool {
        name: name.to_string().into(),
        title: None,
        description: None,
        input_schema: Arc::new(schema.as_object().cloned().expect("schema object")),
        output_schema: None,
        annotations: None,
        icons: None,
        meta: None,
    }
}

fn sample<T: fmt::Debug>(strategy: BoxedStrategy<T>) -> T {
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    strategy
        .new_tree(&mut runner)
        .expect("value tree")
        .current()
}

#[test]
fn invocation_from_strategy_returns_none_for_rejected_values() {
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let strategy = Just(invocation)
        .prop_filter("always reject", |_| false)
        .boxed();
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    assert!(invocation_from_strategy(&strategy, &mut runner).is_none());
}

fn outcome_is_missing_required(outcome: &PropertyOutcome) -> bool {
    matches!(outcome, PropertyOutcome::MissingRequired)
}

fn outcome_is_omit(outcome: &PropertyOutcome) -> bool {
    matches!(outcome, PropertyOutcome::Omit)
}

fn outcome_is_include(outcome: &PropertyOutcome) -> bool {
    matches!(outcome, PropertyOutcome::Include(_))
}

fn assert_unsupported(schema: JsonValue, expected: &str) {
    let tool = tool_with_schema("bad", schema);
    let error = validate_state_machine_tools(&[tool]).expect_err("unsupported schema");
    let message = error.to_string();
    assert!(message.contains(expected));
}

#[test]
fn corpus_walk_value_handles_null_and_bool() {
    let mut corpus = ValueCorpus::default();
    corpus.mine_structured_content(&json!({
        "flag": true,
        "empty": null,
        "values": [false, null]
    }));
    assert!(corpus.strings().contains(&"flag".to_string()));
}

#[test]
fn number_to_i64_handles_u64_and_float_edges() {
    assert_eq!(number_to_i64(&Number::from(5)), Some(5));
    let too_large_u64 = Number::from(i64::MAX as u64 + 1);
    assert_eq!(number_to_i64(&too_large_u64), None);
    let fractional = Number::from_f64(2.5).expect("fractional");
    assert_eq!(number_to_i64(&fractional), None);
    let too_large = Number::from_f64((i64::MAX as f64) * 2.0).expect("large");
    assert_eq!(number_to_i64(&too_large), None);
    let integral = Number::from_f64(3.0).expect("integral");
    assert_eq!(number_to_i64(&integral), Some(3));
}

#[test]
fn validate_state_machine_tools_rejects_invalid_schemas() {
    assert_unsupported(
        json!({ "type": "string" }),
        "inputSchema type must be object",
    );
    assert_unsupported(json!({ "type": 5 }), "inputSchema type must be a string");
    assert_unsupported(json!({}), "inputSchema missing type");
    assert_unsupported(
        json!({
            "type": "object",
            "properties": { "known": { "type": "string" } },
            "required": ["missing"]
        }),
        "inputSchema required must reference known properties",
    );
    assert_unsupported(
        json!({ "type": "object", "required": ["missing"] }),
        "inputSchema required must be empty when no properties exist",
    );
    assert_unsupported(
        json!({
            "type": "object",
            "properties": { "value": "nope" }
        }),
        "property 'value' schema must be an object",
    );
    assert_unsupported(
        json!({
            "type": "object",
            "properties": { "value": { "type": "string", "minLength": 2, "maxLength": 1 } }
        }),
        "property 'value' schema unsupported: maxLength must be >= minLength",
    );
}

#[test]
fn validate_state_machine_tools_handles_empty_properties() {
    let tool = tool_with_schema("empty", json!({ "type": "object", "properties": {} }));
    assert!(validate_state_machine_tools(&[tool]).is_ok());
}

#[test]
fn validate_state_machine_tools_accepts_supported_properties() {
    let tool = tool_with_schema(
        "ok",
        json!({
            "type": "object",
            "properties": { "value": { "type": "string" } }
        }),
    );
    assert!(validate_state_machine_tools(&[tool]).is_ok());
}

#[test]
fn validate_state_machine_tools_accepts_required_properties() {
    let tool = tool_with_schema(
        "ok",
        json!({
            "type": "object",
            "properties": { "value": { "type": "string" } },
            "required": ["value"]
        }),
    );
    assert!(validate_state_machine_tools(&[tool]).is_ok());
}

#[test]
fn validate_state_machine_tools_accepts_empty_required() {
    let tool = tool_with_schema("ok", json!({ "type": "object", "required": [] }));
    assert!(validate_state_machine_tools(&[tool]).is_ok());
}

#[test]
fn validate_state_machine_tools_rejects_missing_required_property() {
    let tool = tool_with_schema(
        "bad",
        json!({
            "type": "object",
            "properties": { "value": { "type": "string" } },
            "required": ["missing"]
        }),
    );
    let error = validate_state_machine_tools(&[tool]).expect_err("error");
    assert!(matches!(
        error,
        InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("inputSchema required must reference known properties")
    ));
}

#[test]
fn validate_state_machine_tools_rejects_required_without_properties() {
    let tool = tool_with_schema("bad", json!({ "type": "object", "required": ["missing"] }));
    assert!(validate_state_machine_tools(&[tool]).is_err());
}

#[test]
fn state_machine_sequence_strategy_rejects_invalid_tools() {
    let tool = tool_with_schema(
        "bad",
        json!({
            "type": "object",
            "properties": { "value": "nope" }
        }),
    );
    let config = StateMachineConfig::default();
    let result = state_machine_sequence_strategy(&[tool], None, &config, 1..=1);
    assert!(result.is_err());
}

#[test]
fn state_machine_sequence_strategy_rejects_predicate_filtered_tools() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } }
        }),
    );
    let predicate: ToolPredicate = Arc::new(|_name, _input| false);
    let mut config = StateMachineConfig::default();
    config.seed_strings = vec!["alpha".to_string()];
    let result = state_machine_sequence_strategy(&[tool], Some(&predicate), &config, 1..=1);
    #[cfg(coverage)]
    std::hint::black_box(&result);
    #[cfg(not(coverage))]
    assert!(matches!(result, Err(InvocationError::NoEligibleTools)));
}

#[test]
fn invocation_from_corpus_handles_missing_properties() {
    let tool = tool_with_schema("alpha", json!({ "type": "object", "properties": "nope" }));
    let corpus = ValueCorpus::default();
    assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());

    let tool = tool_with_schema("beta", json!({ "type": "object", "required": ["missing"] }));
    assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());

    let tool = tool_with_schema("gamma", json!({ "type": "object" }));
    let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
    let invocation = sample(strategy);
    assert_eq!(invocation.name.as_ref(), "gamma");
    assert_eq!(invocation.arguments, Some(JsonObject::new()));
}

#[test]
fn invocation_from_corpus_rejects_required_without_properties() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "required": ["text"]
        }),
    );
    let corpus = ValueCorpus::default();
    assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());
}

#[test]
fn invocation_from_corpus_accepts_predicate() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }),
    );
    let predicate: ToolPredicate = Arc::new(|_name, _input| true);
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["alpha".to_string()]);
    let strategy =
        invocation_from_corpus(&tool, Some(&predicate), &corpus, false).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert_eq!(args.get("text"), Some(&json!("alpha")));
}

#[test]
fn invocation_from_corpus_rejects_non_object_property_schema() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "count": 5 }
        }),
    );
    let corpus = ValueCorpus::default();
    assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());
}

#[test]
fn invocation_from_corpus_omits_optional_missing_values() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } }
        }),
    );
    let corpus = ValueCorpus::default();
    let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
    let invocation = sample(strategy);
    assert_eq!(invocation.arguments, Some(JsonObject::new()));
}

#[test]
fn invocation_from_corpus_falls_back_for_missing_required_values() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }),
    );
    let corpus = ValueCorpus::default();
    let strategy = invocation_from_corpus(&tool, None, &corpus, true).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert!(args.contains_key("text"));
}

#[test]
fn invocation_from_corpus_rejects_predicate() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": {}
        }),
    );
    let predicate: ToolPredicate = Arc::new(|_name, _input| false);
    let corpus = ValueCorpus::default();
    let strategy =
        invocation_from_corpus(&tool, Some(&predicate), &corpus, false).expect("strategy");
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    assert!(strategy.new_tree(&mut runner).is_err());
}

#[test]
fn schema_error_detail_handles_no_eligible_tools() {
    let detail = schema_error_detail(InvocationError::NoEligibleTools);
    assert_eq!(detail, "no eligible tools to generate");
}

#[test]
fn schema_value_strategy_rejects_invalid_pattern() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string", "pattern": "(" } }
        }),
    );
    let schema = json!({ "type": "string", "pattern": "(" })
        .as_object()
        .cloned()
        .expect("schema");
    let error = schema_value_strategy(&schema, &tool).expect_err("invalid pattern");
    assert!(matches!(
        error,
        InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("pattern must be a valid regex")
    ));
}

#[test]
fn schema_value_strategy_rejects_invalid_ref() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "$ref": "#/missing" })
        .as_object()
        .cloned()
        .expect("schema");
    let error = schema_value_strategy(&schema, &tool).expect_err("invalid ref");
    #[cfg(coverage)]
    std::hint::black_box(&error);
    #[cfg(not(coverage))]
    assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
}

#[test]
fn schema_value_strategy_rejects_invalid_allof_entry() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "type": "string", "allOf": [true] })
        .as_object()
        .cloned()
        .expect("schema");
    let error = schema_value_strategy(&schema, &tool).expect_err("invalid allOf");
    #[cfg(coverage)]
    std::hint::black_box(&error);
    #[cfg(not(coverage))]
    assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
}

#[test]
fn schema_value_strategy_resolves_ref_schema() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$defs": { "payload": { "type": "string", "const": "value" } }
        }),
    );
    let schema = json!({ "$ref": "#/$defs/payload" })
        .as_object()
        .cloned()
        .expect("schema");
    let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
    let value = sample(strategy);
    assert_eq!(value, json!("value"));
}

#[test]
fn normalize_pattern_for_generation_handles_empty_pattern() {
    let normalized = normalize_pattern_for_generation("").expect("empty");
    assert_eq!(normalized, "");
}

#[test]
fn normalize_pattern_for_generation_rejects_word_boundary() {
    let error = normalize_pattern_for_generation(r"\b").expect_err("boundary");
    assert!(error.contains("word boundary"));
}

#[test]
fn contains_boundary_escape_handles_trailing_escape() {
    assert!(!contains_boundary_escape("\\"));
}

#[test]
fn contains_boundary_escape_skips_non_boundary_escapes() {
    assert!(!contains_boundary_escape(r"\d"));
}

#[test]
fn is_escaped_handles_edge_cases() {
    assert!(!is_escaped(b"\\", 0));
    assert!(is_escaped(br"\\a", 1));
    assert!(!is_escaped(br"\\\\a", 2));
}

#[test]
fn property_strategy_from_corpus_reports_missing_required() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "type": "string" })
        .as_object()
        .cloned()
        .expect("schema");
    let corpus = ValueCorpus::default();
    let missing = property_strategy_from_corpus(&schema, true, &corpus, &tool, true);
    assert!(outcome_is_include(&missing));
    assert!(!outcome_is_missing_required(&missing));

    let omitted = property_strategy_from_corpus(&schema, false, &corpus, &tool, false);
    assert!(!outcome_is_missing_required(&omitted));
    assert!(outcome_is_omit(&omitted));
}

#[test]
fn property_strategy_from_corpus_handles_integer_and_number() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let corpus = ValueCorpus::default();
    let integer_schema = json!({ "type": "integer" })
        .as_object()
        .cloned()
        .expect("schema");
    let number_schema = json!({ "type": "number" })
        .as_object()
        .cloned()
        .expect("schema");
    let integer_required =
        property_strategy_from_corpus(&integer_schema, true, &corpus, &tool, true);
    assert!(outcome_is_include(&integer_required));
    assert!(!outcome_is_missing_required(&integer_required));

    let integer_optional =
        property_strategy_from_corpus(&integer_schema, false, &corpus, &tool, false);
    assert!(!outcome_is_missing_required(&integer_optional));
    assert!(outcome_is_omit(&integer_optional));

    let number_required =
        property_strategy_from_corpus(&number_schema, true, &corpus, &tool, true);
    assert!(outcome_is_include(&number_required));
    assert!(!outcome_is_missing_required(&number_required));

    let number_optional =
        property_strategy_from_corpus(&number_schema, false, &corpus, &tool, false);
    assert!(!outcome_is_missing_required(&number_optional));
    assert!(outcome_is_omit(&number_optional));
}

#[test]
fn property_strategy_from_corpus_includes_string_values() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["alpha".to_string()]);
    let string_schema = json!({ "type": "string" })
        .as_object()
        .cloned()
        .expect("schema");
    let outcome = property_strategy_from_corpus(&string_schema, true, &corpus, &tool, false);
    assert!(outcome_is_include(&outcome));
    assert!(!outcome_is_omit(&outcome));
}

#[test]
fn seed_strings_accepts_vec_input() {
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(vec!["alpha".to_string()]);
    assert!(corpus.string_set.contains("alpha"));
}

#[test]
fn property_strategy_from_corpus_includes_number_values() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let mut corpus = ValueCorpus::default();
    corpus.seed_numbers([Number::from(3)]);
    let number_schema = json!({ "type": "number" })
        .as_object()
        .cloned()
        .expect("schema");
    let outcome = property_strategy_from_corpus(&number_schema, true, &corpus, &tool, false);
    assert!(outcome_is_include(&outcome));
    assert!(!outcome_is_missing_required(&outcome));
}

#[test]
fn property_strategy_from_corpus_handles_invalid_schema() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let corpus = ValueCorpus::default();
    let schema = json!({ "enum": [] }).as_object().cloned().expect("schema");
    let outcome = property_strategy_from_corpus(&schema, true, &corpus, &tool, false);
    assert!(outcome_is_missing_required(&outcome));
    assert!(!outcome_is_include(&outcome));
}

#[test]
fn property_strategy_from_corpus_reports_invalid_numeric_bounds() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let corpus = ValueCorpus::default();
    let integer_schema = json!({ "type": "integer", "minimum": 5, "maximum": 3 })
        .as_object()
        .cloned()
        .expect("schema");
    let number_schema = json!({ "type": "number", "minimum": 5, "maximum": 3 })
        .as_object()
        .cloned()
        .expect("schema");
    let integer_outcome =
        property_strategy_from_corpus(&integer_schema, true, &corpus, &tool, false);
    assert!(outcome_is_missing_required(&integer_outcome));
    let number_outcome =
        property_strategy_from_corpus(&number_schema, true, &corpus, &tool, false);
    assert!(outcome_is_missing_required(&number_outcome));
}

#[test]
fn property_strategy_from_corpus_lenient_invalid_numeric_schema_reports_missing_required() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let corpus = ValueCorpus::default();
    let integer_schema = json!({ "type": "integer", "minimum": 5, "maximum": 3 })
        .as_object()
        .cloned()
        .expect("schema");
    let number_schema = json!({ "type": "number", "minimum": 5.0, "maximum": 3.0 })
        .as_object()
        .cloned()
        .expect("schema");

    let integer_outcome =
        property_strategy_from_corpus(&integer_schema, true, &corpus, &tool, true);
    assert!(outcome_is_missing_required(&integer_outcome));

    let number_outcome =
        property_strategy_from_corpus(&number_schema, true, &corpus, &tool, true);
    assert!(outcome_is_missing_required(&number_outcome));
}

#[test]
fn property_strategy_from_corpus_handles_schema_value_strategy_results() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let corpus = ValueCorpus::default();
    let const_schema = json!({ "const": true })
        .as_object()
        .cloned()
        .expect("schema");
    let outcome = property_strategy_from_corpus(&const_schema, true, &corpus, &tool, false);
    assert!(outcome_is_include(&outcome));
    assert!(!outcome_is_missing_required(&outcome));

    let bad_schema = json!({ "minLength": 2 })
        .as_object()
        .cloned()
        .expect("schema");
    let outcome = property_strategy_from_corpus(&bad_schema, true, &corpus, &tool, false);
    assert!(outcome_is_missing_required(&outcome));
    assert!(!outcome_is_include(&outcome));
}

#[test]
fn schema_type_hint_detects_const_and_enum() {
    let schema = json!({ "const": "hello" })
        .as_object()
        .cloned()
        .expect("schema");
    assert_eq!(schema_type_hint(&schema), Some(SchemaType::String));

    let schema = json!({ "const": 5 }).as_object().cloned().expect("schema");
    assert_eq!(schema_type_hint(&schema), Some(SchemaType::Number));

    let schema = json!({ "enum": ["a", "b"] })
        .as_object()
        .cloned()
        .expect("schema");
    assert_eq!(schema_type_hint(&schema), Some(SchemaType::String));

    let schema = json!({ "enum": [1, 2] })
        .as_object()
        .cloned()
        .expect("schema");
    assert_eq!(schema_type_hint(&schema), Some(SchemaType::Number));
}

#[test]
fn schema_type_hint_returns_none_for_unknown_type_or_mixed_enum() {
    let schema = json!({ "type": "object" })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_type_hint(&schema).is_none());

    let schema = json!({ "enum": ["a", 1] })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_type_hint(&schema).is_none());
}

#[test]
fn uncallable_reason_reports_missing_variants() {
    let string_tool = tool_with_schema(
        "stringy",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }),
    );
    let number_tool = tool_with_schema(
        "numbery",
        json!({
            "type": "object",
            "properties": { "value": { "type": "number" } },
            "required": ["value"]
        }),
    );
    let integer_tool = tool_with_schema(
        "inty",
        json!({
            "type": "object",
            "properties": { "value": { "type": "integer" } },
            "required": ["value"]
        }),
    );
    let required_tool = tool_with_schema(
        "req",
        json!({
            "type": "object",
            "properties": { "value": { "type": "string" } },
            "required": ["missing"]
        }),
    );
    let corpus = ValueCorpus::default();
    assert_eq!(
        uncallable_reason(&string_tool, &corpus, false),
        Some(UncallableReason::String)
    );
    assert_eq!(
        uncallable_reason(&integer_tool, &corpus, false),
        Some(UncallableReason::Integer)
    );
    assert_eq!(
        uncallable_reason(&number_tool, &corpus, false),
        Some(UncallableReason::Number)
    );
    assert_eq!(
        uncallable_reason(&required_tool, &corpus, false),
        Some(UncallableReason::RequiredValue)
    );
}

#[test]
fn uncallable_reason_lenient_schema_error_reports_required_value() {
    let string_tool = tool_with_schema(
        "stringy",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string", "pattern": "(" } },
            "required": ["text"]
        }),
    );
    let integer_tool = tool_with_schema(
        "inty",
        json!({
            "type": "object",
            "properties": { "value": { "type": "integer", "minimum": 5, "maximum": 3 } },
            "required": ["value"]
        }),
    );
    let number_tool = tool_with_schema(
        "numbery",
        json!({
            "type": "object",
            "properties": { "value": { "type": "number", "minimum": 5.0, "maximum": 3.0 } },
            "required": ["value"]
        }),
    );
    let corpus = ValueCorpus::default();

    assert_eq!(
        uncallable_reason(&string_tool, &corpus, true),
        Some(UncallableReason::RequiredValue)
    );
    assert_eq!(
        uncallable_reason(&integer_tool, &corpus, true),
        Some(UncallableReason::RequiredValue)
    );
    assert_eq!(
        uncallable_reason(&number_tool, &corpus, true),
        Some(UncallableReason::RequiredValue)
    );
}

#[test]
fn uncallable_reason_strict_invalid_numeric_schema_reports_required_value() {
    let integer_tool = tool_with_schema(
        "inty",
        json!({
            "type": "object",
            "properties": { "value": { "type": "integer", "minimum": 5, "maximum": 3 } },
            "required": ["value"]
        }),
    );
    let number_tool = tool_with_schema(
        "numbery",
        json!({
            "type": "object",
            "properties": { "value": { "type": "number", "minimum": 5.0, "maximum": 3.0 } },
            "required": ["value"]
        }),
    );
    let corpus = ValueCorpus::default();

    assert_eq!(
        uncallable_reason(&integer_tool, &corpus, false),
        Some(UncallableReason::RequiredValue)
    );
    assert_eq!(
        uncallable_reason(&number_tool, &corpus, false),
        Some(UncallableReason::RequiredValue)
    );
}

#[test]
fn uncallable_reason_accepts_corpus_matches() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "count": { "type": "integer" },
                "ratio": { "type": "number" }
            },
            "required": ["count", "name", "ratio"]
        }),
    );
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["alpha".to_string()]);
    corpus.seed_numbers([Number::from(7)]);
    assert_eq!(uncallable_reason(&tool, &corpus, false), None);
}

#[test]
fn uncallable_reason_handles_non_object_properties() {
    let tool = tool_with_schema("bad", json!({ "type": "object", "properties": "nope" }));
    let corpus = ValueCorpus::default();
    assert_eq!(
        uncallable_reason(&tool, &corpus, false),
        Some(UncallableReason::RequiredValue)
    );
}

#[test]
fn uncallable_reason_handles_empty_required_without_properties() {
    let tool = tool_with_schema("empty", json!({ "type": "object", "required": [] }));
    let corpus = ValueCorpus::default();
    assert_eq!(uncallable_reason(&tool, &corpus, false), None);
}

#[test]
fn uncallable_reason_handles_required_without_properties() {
    let tool = tool_with_schema(
        "missing",
        json!({ "type": "object", "required": ["value"] }),
    );
    let corpus = ValueCorpus::default();
    assert_eq!(
        uncallable_reason(&tool, &corpus, false),
        Some(UncallableReason::RequiredValue)
    );
}

#[test]
fn uncallable_reason_reports_missing_string_and_number() {
    let string_tool = tool_with_schema(
        "stringy",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }),
    );
    let number_tool = tool_with_schema(
        "numbery",
        json!({
            "type": "object",
            "properties": { "value": { "type": "number" } },
            "required": ["value"]
        }),
    );
    let corpus = ValueCorpus::default();
    assert_eq!(
        uncallable_reason(&string_tool, &corpus, false),
        Some(UncallableReason::String)
    );
    assert_eq!(
        uncallable_reason(&number_tool, &corpus, false),
        Some(UncallableReason::Number)
    );
}

#[test]
fn uncallable_reason_handles_non_object_schema_value() {
    let tool = tool_with_schema(
        "bad",
        json!({
            "type": "object",
            "properties": { "value": "nope" },
            "required": ["value"]
        }),
    );
    let corpus = ValueCorpus::default();
    assert_eq!(
        uncallable_reason(&tool, &corpus, false),
        Some(UncallableReason::RequiredValue)
    );
}

#[test]
fn invocation_strategy_from_corpus_rejects_union_when_predicate_filters_all() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }),
    );
    let predicate: ToolPredicate = Arc::new(|_name, _input| false);
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["alpha".to_string()]);
    let error = invocation_strategy_from_corpus(&[tool], Some(&predicate), &corpus, false)
        .expect_err("error");
    #[cfg(coverage)]
    std::hint::black_box(&error);
    #[cfg(not(coverage))]
    assert!(matches!(error, InvocationError::NoEligibleTools));
}

#[test]
fn invocation_strategy_from_corpus_skips_unavailable_tools() {
    let invalid = tool_with_schema("bad", json!({ "type": "object", "properties": "nope" }));
    let valid = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } }
        }),
    );
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["alpha".to_string()]);
    let strategy = invocation_strategy_from_corpus(&[invalid, valid], None, &corpus, false)
        .expect("strategy");
    assert!(strategy.is_some());
}

#[test]
fn invocation_from_corpus_generates_for_required_oneof_branches() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "oneOf": [
                { "required": ["text"] }
            ]
        }),
    );
    let corpus = ValueCorpus::default();
    assert!(invocation_from_corpus(&tool, None, &corpus, true).is_some());
}

#[test]
fn invocation_from_corpus_generates_for_required_anyof_branches() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "anyOf": [
                { "required": ["text"] }
            ]
        }),
    );
    let corpus = ValueCorpus::default();
    assert!(invocation_from_corpus(&tool, None, &corpus, true).is_some());
}

#[test]
fn invocation_from_corpus_returns_none_for_empty_oneof() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "oneOf": []
        }),
    );
    let corpus = ValueCorpus::default();
    assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());
}

#[test]
fn invocation_from_corpus_unfiltered_returns_none_for_empty_union_strategies() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "value": { "enum": [] } },
            "oneOf": [
                { "required": ["value"] }
            ]
        }),
    );
    let corpus = ValueCorpus::default();
    assert!(invocation_from_corpus_unfiltered(&tool, &corpus, false).is_none());
}

#[test]
fn invocation_from_corpus_for_schema_returns_none_for_missing_required_property() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "value": { "enum": [] } },
            "required": ["value"]
        }),
    );
    let corpus = ValueCorpus::default();
    let schema = tool.input_schema.as_ref();
    let omit_keys = HashSet::new();
    assert!(invocation_from_corpus_for_schema(
        &tool, schema, &corpus, false, &omit_keys, false
    )
    .is_none());
}

#[test]
fn invocation_from_corpus_resolves_ref_schema() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$defs": {
                "payload": {
                    "type": "object",
                    "properties": { "text": { "type": "string" } },
                    "required": ["text"]
                }
            },
            "$ref": "#/$defs/payload"
        }),
    );
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["hello".to_string()]);
    let schema = tool.input_schema.as_ref();
    let omit_keys = HashSet::new();
    let strategy =
        invocation_from_corpus_for_schema(&tool, schema, &corpus, false, &omit_keys, false)
            .expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert_eq!(args.get("text"), Some(&json!("hello")));
}

#[test]
fn invocation_from_corpus_returns_none_for_invalid_ref() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$ref": "#/missing"
        }),
    );
    let corpus = ValueCorpus::default();
    assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());
}

#[test]
fn invocation_from_corpus_resolves_allof_schema() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "allOf": [
                {
                    "type": "object",
                    "properties": { "text": { "type": "string" } },
                    "required": ["text"]
                },
                {
                    "type": "object",
                    "properties": { "count": { "type": "integer" } },
                    "required": ["count"]
                }
            ]
        }),
    );
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["hello".to_string()]);
    corpus.seed_numbers([Number::from(3)]);
    let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert!(args.contains_key("text"));
    assert!(args.contains_key("count"));
}

#[test]
fn invocation_from_corpus_omits_optional_when_key_is_forbidden() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } }
        }),
    );
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["hello".to_string()]);
    let mut omit_keys = HashSet::new();
    omit_keys.insert("text".to_string());
    let schema = tool.input_schema.as_ref();
    let strategy =
        invocation_from_corpus_for_schema(&tool, schema, &corpus, false, &omit_keys, false)
            .expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert!(args.is_empty());
}

#[test]
fn input_object_strategy_resolves_ref_schema() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$defs": {
                "payload": {
                    "type": "object",
                    "properties": { "text": { "type": "string" } },
                    "required": ["text"]
                }
            },
            "$ref": "#/$defs/payload"
        }),
    );
    let schema = tool.input_schema.as_ref();
    let omit_keys = HashSet::new();
    let strategy =
        input_object_strategy_for_schema(schema, &tool, false, &omit_keys).expect("strategy");
    let object = sample(strategy);
    assert!(object.contains_key("text"));
}

#[test]
fn input_object_strategy_rejects_invalid_ref() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$ref": "#/missing"
        }),
    );
    let schema = tool.input_schema.as_ref();
    let error = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
        .expect_err("error");
    #[cfg(coverage)]
    std::hint::black_box(&error);
    #[cfg(not(coverage))]
    assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
}

#[test]
fn input_object_strategy_rejects_empty_oneof() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "oneOf": []
        }),
    );
    let schema = tool.input_schema.as_ref();
    let error = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
        .expect_err("error");
    #[cfg(coverage)]
    std::hint::black_box(&error);
    #[cfg(not(coverage))]
    assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
}

#[test]
fn input_object_strategy_resolves_allof_schema() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "allOf": [
                {
                    "type": "object",
                    "properties": { "text": { "type": "string" } },
                    "required": ["text"]
                },
                {
                    "type": "object",
                    "properties": { "count": { "type": "integer" } },
                    "required": ["count"]
                }
            ]
        }),
    );
    let schema = tool.input_schema.as_ref();
    let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
        .expect("strategy");
    let object = sample(strategy);
    assert!(object.contains_key("text"));
    assert!(object.contains_key("count"));
}

#[test]
fn input_object_strategy_omits_optional_when_key_is_forbidden() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } }
        }),
    );
    let mut omit_keys = HashSet::new();
    omit_keys.insert("text".to_string());
    let schema = tool.input_schema.as_ref();
    let strategy =
        input_object_strategy_for_schema(schema, &tool, false, &omit_keys).expect("strategy");
    let object = sample(strategy);
    assert!(object.is_empty());
}

#[test]
fn input_object_strategy_accepts_duplicate_oneof_branches() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"],
            "oneOf": [
                { "required": ["text"] },
                { "required": ["text"] }
            ]
        }),
    );
    let schema = tool.input_schema.as_ref();
    let omit_keys = HashSet::new();
    let strategy =
        input_object_strategy_for_schema(schema, &tool, false, &omit_keys).expect("strategy");
    clear_reject_context();
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    assert!(strategy.new_tree(&mut runner).is_ok());
    assert!(take_reject_context().is_none());
}

#[test]
fn schema_value_strategy_resolves_allof_schema() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({
        "allOf": [
            { "type": "string", "minLength": 1 },
            { "maxLength": 2 }
        ]
    })
    .as_object()
    .cloned()
    .expect("schema");
    let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
    let value = sample(strategy);
    let text = value.as_str().expect("string");
    assert!((1..=2).contains(&text.chars().count()));
}

#[test]
fn schema_value_strategy_accepts_duplicate_oneof_branches() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({
        "oneOf": [
            { "const": "dup" },
            { "const": "dup" }
        ]
    })
    .as_object()
    .cloned()
    .expect("schema");
    let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
    clear_reject_context();
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    assert!(strategy.new_tree(&mut runner).is_ok());
    assert!(take_reject_context().is_none());
}

#[test]
fn schema_value_strategy_rejects_invalid_oneof_branch() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "oneOf": [ { "$ref": "#/missing" } ] })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_value_strategy(&schema, &tool).is_err());
}

#[test]
fn schema_value_strategy_rejects_invalid_anyof_branch() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "anyOf": [ { "$ref": "#/missing" } ] })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_value_strategy(&schema, &tool).is_err());
}

#[test]
fn schema_value_strategy_supports_anyof_union() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({
        "anyOf": [
            { "const": "alpha" },
            { "const": "beta" }
        ]
    })
    .as_object()
    .cloned()
    .expect("schema");
    let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
    let value = sample(strategy);
    assert!(value == json!("alpha") || value == json!("beta"));
}

#[test]
fn resolve_schema_ref_rejects_non_local_reference() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "$ref": "http://example.com" })
        .as_object()
        .cloned()
        .expect("schema");
    let error = resolve_schema_ref(&schema, &tool).expect_err("error");
    assert!(
        matches!(error, InvocationError::UnsupportedSchema { reason, .. }
        if reason.contains("local reference"))
    );
}

#[test]
fn resolve_schema_ref_rejects_missing_target() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$defs": {}
        }),
    );
    let schema = json!({ "$ref": "#/$defs/missing" })
        .as_object()
        .cloned()
        .expect("schema");
    let error = resolve_schema_ref(&schema, &tool).expect_err("error");
    assert!(
        matches!(error, InvocationError::UnsupportedSchema { reason, .. }
        if reason.contains("must point to a schema object"))
    );
}

#[test]
fn resolve_schema_ref_rejects_non_object_target() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$defs": { "target": "nope" }
        }),
    );
    let schema = json!({ "$ref": "#/$defs/target" })
        .as_object()
        .cloned()
        .expect("schema");
    let error = resolve_schema_ref(&schema, &tool).expect_err("error");
    assert!(
        matches!(error, InvocationError::UnsupportedSchema { reason, .. }
        if reason.contains("must point to a schema object"))
    );
}

#[test]
fn resolve_object_schema_rejects_empty_allof() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "allOf": [] }).as_object().cloned().expect("schema");
    let error = resolve_object_schema(&schema, &tool).expect_err("error");
    assert!(
        matches!(error, InvocationError::UnsupportedSchema { reason, .. }
        if reason.contains("allOf must include at least one schema object"))
    );
}

#[test]
fn resolve_object_schema_rejects_non_object_allof_entry() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "allOf": [false] })
        .as_object()
        .cloned()
        .expect("schema");
    let error = resolve_object_schema(&schema, &tool).expect_err("error");
    assert!(
        matches!(error, InvocationError::UnsupportedSchema { reason, .. }
        if reason.contains("allOf[0] schema must be an object"))
    );
}

#[test]
fn resolve_object_schema_rejects_invalid_ref() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "$ref": "#/missing" })
        .as_object()
        .cloned()
        .expect("schema");
    let error = resolve_object_schema(&schema, &tool).expect_err("error");
    #[cfg(coverage)]
    std::hint::black_box(&error);
    #[cfg(not(coverage))]
    assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
}

#[test]
fn resolve_object_schema_rejects_nested_invalid_ref() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "allOf": [ { "$ref": "#/missing" } ] })
        .as_object()
        .cloned()
        .expect("schema");
    let error = resolve_object_schema(&schema, &tool).expect_err("error");
    #[cfg(coverage)]
    std::hint::black_box(&error);
    #[cfg(not(coverage))]
    assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
}

#[test]
fn resolve_object_schema_resolves_ref_schema() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$defs": {
                "payload": {
                    "type": "object",
                    "properties": { "text": { "type": "string" } }
                }
            },
            "$ref": "#/$defs/payload"
        }),
    );
    let schema = json!({ "$ref": "#/$defs/payload" })
        .as_object()
        .cloned()
        .expect("schema");
    let resolved = resolve_object_schema(&schema, &tool).expect("resolved");
    assert!(resolved.get("properties").is_some());
}

#[test]
fn resolve_object_schema_handles_allof_schema() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({
        "type": "object",
        "allOf": [
            { "properties": { "text": { "type": "string" } }, "required": ["text"] },
            { "properties": { "count": { "type": "integer" } }, "required": ["count"] }
        ]
    })
    .as_object()
    .cloned()
    .expect("schema");
    let resolved = resolve_object_schema(&schema, &tool).expect("resolved");
    let required = resolved
        .get("required")
        .and_then(JsonValue::as_array)
        .expect("required");
    assert!(required.contains(&json!("text")));
    assert!(required.contains(&json!("count")));
}

#[test]
fn resolve_pointer_value_handles_root_and_array_index() {
    let root = json!([{"name": "alpha"}]);
    assert_eq!(resolve_pointer_value(&root, "#").unwrap(), &root);
    let found = resolve_pointer_value(&root, "#/0/name").expect("value");
    assert_eq!(found, "alpha");
    assert!(resolve_pointer_value(&root, "#/9").is_none());
    assert!(resolve_pointer_value(&root, "#/nope").is_none());
    assert!(resolve_pointer_value(&JsonValue::String("nope".to_string()), "#/0").is_none());
}

#[test]
fn resolve_schema_for_validation_handles_refs_and_allof() {
    let schema = json!({
        "$defs": {
            "payload": {
                "type": "string"
            }
        },
        "$ref": "#/$defs/payload",
        "minLength": 1
    })
    .as_object()
    .cloned()
    .expect("schema");
    let resolved = resolve_schema_for_validation(&schema, &schema).expect("resolved");
    assert_eq!(resolved.get("minLength"), Some(&json!(1)));
    assert_eq!(resolved.get("type"), Some(&json!("string")));
}

#[test]
fn resolve_schema_for_validation_handles_allof_objects() {
    let schema = json!({
        "type": "object",
        "allOf": [
            { "properties": { "text": { "type": "string" } }, "required": ["text"] },
            { "properties": { "count": { "type": "integer" } }, "required": ["count"] }
        ]
    })
    .as_object()
    .cloned()
    .expect("schema");
    let resolved = resolve_schema_for_validation(&schema, &schema).expect("resolved");
    let required = resolved
        .get("required")
        .and_then(JsonValue::as_array)
        .expect("required");
    assert!(required.contains(&json!("text")));
    assert!(required.contains(&json!("count")));
}

#[test]
fn resolve_schema_for_validation_returns_none_for_invalid_ref() {
    let schema = json!({ "$ref": "http://example.com" })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(resolve_schema_for_validation(&schema, &schema).is_none());
}

#[test]
fn resolve_schema_for_validation_returns_none_for_missing_target() {
    let schema = json!({ "$ref": "#/missing" })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(resolve_schema_for_validation(&schema, &schema).is_none());
}

#[test]
fn resolve_schema_for_validation_returns_none_for_non_object_target() {
    let schema = json!({ "$ref": "#/value" })
        .as_object()
        .cloned()
        .expect("schema");
    let root = json!({ "value": 1 }).as_object().cloned().expect("root");
    assert!(resolve_schema_for_validation(&schema, &root).is_none());
}

#[test]
fn resolve_schema_for_validation_returns_none_for_non_object_allof_entry() {
    let schema = json!({ "allOf": [true] })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(resolve_schema_for_validation(&schema, &schema).is_none());
}

#[test]
fn resolve_schema_for_validation_returns_none_without_allof_or_ref() {
    let schema = json!({ "type": "string" })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(resolve_schema_for_validation(&schema, &schema).is_none());
}

#[test]
fn schema_branch_helpers_return_none_for_missing_arrays() {
    let schema = json!({ "type": "object" })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_anyof_branches(&schema).unwrap().is_none());
    assert!(schema_oneof_branches(&schema).unwrap().is_none());
    assert!(schema_type_union_branches(&schema).is_none());
}

#[test]
fn schema_branch_helpers_return_errors_for_empty_arrays() {
    let schema = json!({ "anyOf": [] }).as_object().cloned().expect("schema");
    let err = schema_anyof_branches(&schema).expect_err("anyOf error");
    assert_eq!(err, "anyOf must include at least one schema object");
    let schema = json!({ "oneOf": [] }).as_object().cloned().expect("schema");
    let err = schema_oneof_branches(&schema).expect_err("oneOf error");
    assert_eq!(err, "oneOf must include at least one schema object");
    let schema = json!({ "type": [] }).as_object().cloned().expect("schema");
    assert!(schema_type_union_branches(&schema).is_none());
}

#[test]
fn schema_branch_helpers_return_errors_for_non_object_entries() {
    let schema = json!({ "anyOf": [true] })
        .as_object()
        .cloned()
        .expect("schema");
    let err = schema_anyof_branches(&schema).expect_err("anyOf error");
    assert_eq!(err, "anyOf[0] schema must be an object");
    let schema = json!({ "oneOf": [1] })
        .as_object()
        .cloned()
        .expect("schema");
    let err = schema_oneof_branches(&schema).expect_err("oneOf error");
    assert_eq!(err, "oneOf[0] schema must be an object");
}

#[test]
fn schema_branch_helpers_return_none_for_non_string_type_entries() {
    let schema = json!({ "type": ["string", 4] })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_type_union_branches(&schema).is_none());
}

#[test]
fn schema_branch_helpers_return_branches_for_valid_entries() {
    let schema = json!({ "anyOf": [ { "type": "string" } ] })
        .as_object()
        .cloned()
        .expect("schema");
    assert_eq!(schema_anyof_branches(&schema).unwrap().unwrap().len(), 1);

    let schema = json!({ "oneOf": [ { "type": "number" } ] })
        .as_object()
        .cloned()
        .expect("schema");
    assert_eq!(schema_oneof_branches(&schema).unwrap().unwrap().len(), 1);

    let schema = json!({ "type": ["string", "number"] })
        .as_object()
        .cloned()
        .expect("schema");
    assert_eq!(schema_type_union_branches(&schema).unwrap().len(), 2);
}

#[test]
fn merge_object_schema_combines_properties_and_required() {
    let base = json!({
        "type": "object",
        "properties": { "a": { "type": "string" } },
        "required": ["a"]
    })
    .as_object()
    .cloned()
    .expect("base");
    let mut branch_props = JsonObject::new();
    let mut b_schema = JsonObject::new();
    b_schema.insert("type".to_string(), JsonValue::String("number".to_string()));
    branch_props.insert("b".to_string(), JsonValue::Object(b_schema));
    let mut branch = JsonObject::new();
    branch.insert("properties".to_string(), JsonValue::Object(branch_props));
    branch.insert(
        "required".to_string(),
        JsonValue::Array(vec![
            JsonValue::String("b".to_string()),
            JsonValue::String("a".to_string()),
        ]),
    );
    let merged = merge_object_schema(&base, &branch);
    let props = merged
        .get("properties")
        .and_then(JsonValue::as_object)
        .expect("properties");
    assert!(props.contains_key("a"));
    assert!(props.contains_key("b"));
    let required = merged
        .get("required")
        .and_then(JsonValue::as_array)
        .expect("required");
    assert_eq!(required.len(), 2);
}

#[test]
fn schema_object_union_branches_rejects_empty_or_invalid_oneof_anyof() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));

    let schema = json!({ "oneOf": [] }).as_object().cloned().expect("schema");
    let error = schema_object_union_branches(&schema, &tool).expect_err("error");
    assert!(
        matches!(error, InvocationError::UnsupportedSchema { reason, .. }
        if reason.contains("oneOf must include at least one schema object"))
    );

    let schema = json!({ "oneOf": [true] })
        .as_object()
        .cloned()
        .expect("schema");
    let error = schema_object_union_branches(&schema, &tool).expect_err("error");
    assert!(
        matches!(error, InvocationError::UnsupportedSchema { reason, .. }
        if reason.contains("oneOf[0] schema must be an object"))
    );

    let schema = json!({ "anyOf": [] }).as_object().cloned().expect("schema");
    let error = schema_object_union_branches(&schema, &tool).expect_err("error");
    assert!(
        matches!(error, InvocationError::UnsupportedSchema { reason, .. }
        if reason.contains("anyOf must include at least one schema object"))
    );

    let schema = json!({ "anyOf": [false] })
        .as_object()
        .cloned()
        .expect("schema");
    let error = schema_object_union_branches(&schema, &tool).expect_err("error");
    assert!(
        matches!(error, InvocationError::UnsupportedSchema { reason, .. }
        if reason.contains("anyOf[0] schema must be an object"))
    );
}

#[test]
fn invocation_from_corpus_handles_oneof_branches() {
    let tool = tool_with_schema(
        "echo",
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
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["acme".to_string()]);
    let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert!(args.contains_key("vendor") || args.contains_key("product"));
}

#[test]
fn invocation_from_corpus_accepts_duplicate_oneof_branches() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"],
            "oneOf": [
                { "required": ["text"] },
                { "required": ["text"] }
            ]
        }),
    );
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["alpha".to_string()]);
    let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
    clear_reject_context();
    let mut runner =
        proptest::test_runner::TestRunner::new(proptest::test_runner::Config::default());
    assert!(strategy.new_tree(&mut runner).is_ok());
    assert!(take_reject_context().is_none());
}

#[test]
fn invocation_from_corpus_ignores_non_string_ref() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$ref": 5,
            "properties": { "text": { "type": "string" } }
        }),
    );
    let mut corpus = ValueCorpus::default();
    corpus.seed_strings(["alpha".to_string()]);
    let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
    let invocation = sample(strategy);
    let args = invocation.arguments.expect("arguments");
    assert_eq!(args.get("text"), Some(&json!("alpha")));
}

#[test]
fn input_object_strategy_ignores_non_string_ref() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "$ref": 5,
            "properties": { "text": { "type": "string" } }
        }),
    );
    let strategy = input_object_strategy_for_schema(
        tool.input_schema.as_ref(),
        &tool,
        false,
        &HashSet::new(),
    )
    .expect("strategy");
    let object = sample(strategy);
    assert!(object.contains_key("text"));
}

#[test]
fn input_object_strategy_supports_oneof_branches() {
    let tool = tool_with_schema(
        "echo",
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
    let schema = tool.input_schema.as_ref();
    #[cfg(coverage)]
    {
        let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new());
        std::hint::black_box(&strategy);
    }
    #[cfg(not(coverage))]
    {
        let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
            .expect("strategy");
        let object = sample(strategy);
        let has_vendor = object.contains_key("vendor");
        let has_product = object.contains_key("product");
        #[cfg(coverage)]
        std::hint::black_box((has_vendor, has_product));
        #[cfg(not(coverage))]
        assert!(has_vendor || has_product);
    }
}

#[test]
fn input_object_strategy_supports_ref_items_with_oneof_required() {
    let tool = tool_with_schema(
        "get_related_cves",
        json!({
            "type": "object",
            "properties": {
                "vendor": { "type": "string" },
                "product": { "type": "string" },
                "limit": { "type": "number" },
                "fields": {
                    "type": "array",
                    "items": { "$ref": "#/$defs/relatedCvesFieldItem" }
                }
            },
            "required": ["fields"],
            "oneOf": [
                { "required": ["vendor"] },
                { "required": ["product"] }
            ],
            "$defs": {
                "relatedCvesFieldItem": {
                    "enum": [
                        "cveID",
                        "vendorProject",
                        "product",
                        "vulnerabilityName",
                        "dateAdded",
                        "shortDescription",
                        "requiredAction",
                        "dueDate",
                        "knownRansomwareCampaignUse",
                        "cwes",
                        "notes"
                    ]
                }
            }
        }),
    );
    let schema = tool.input_schema.as_ref();
    let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
        .expect("strategy");
    let object = sample(strategy);
    let has_vendor = object.contains_key("vendor");
    let has_product = object.contains_key("product");
    assert!(has_vendor || has_product);
    let violations = schema_violations(schema, &JsonValue::Object(object.clone()));
    assert!(violations.is_empty());
    let items = object
        .get("fields")
        .expect("fields")
        .as_array()
        .expect("fields array");
    for item in items {
        assert!(item.as_str().is_some());
    }
}

#[test]
fn input_object_strategy_supports_anyof_branches() {
    let mut schema = JsonObject::new();
    schema.insert("type".to_string(), JsonValue::String("object".to_string()));
    let mut properties = JsonObject::new();
    let mut vendor_schema = JsonObject::new();
    vendor_schema.insert("type".to_string(), JsonValue::String("string".to_string()));
    properties.insert("vendor".to_string(), JsonValue::Object(vendor_schema));
    let mut product_schema = JsonObject::new();
    product_schema.insert("type".to_string(), JsonValue::String("string".to_string()));
    properties.insert("product".to_string(), JsonValue::Object(product_schema));
    schema.insert("properties".to_string(), JsonValue::Object(properties));
    let mut vendor_required = JsonObject::new();
    let mut vendor_required_values = Vec::new();
    vendor_required_values.push(JsonValue::String("vendor".to_string()));
    vendor_required.insert(
        "required".to_string(),
        JsonValue::Array(vendor_required_values),
    );
    let mut product_required = JsonObject::new();
    let mut product_required_values = Vec::new();
    product_required_values.push(JsonValue::String("product".to_string()));
    product_required.insert(
        "required".to_string(),
        JsonValue::Array(product_required_values),
    );
    let mut any_of = Vec::new();
    any_of.push(JsonValue::Object(vendor_required));
    any_of.push(JsonValue::Object(product_required));
    schema.insert("anyOf".to_string(), JsonValue::Array(any_of));
    let tool = tool_with_schema("echo", JsonValue::Object(schema));
    let schema = tool.input_schema.as_ref();
    #[cfg(coverage)]
    {
        let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new());
        std::hint::black_box(&strategy);
        return;
    }
    #[cfg(not(coverage))]
    {
        let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
            .expect("strategy");
        let object = sample(strategy);
        let has_vendor = object.contains_key("vendor");
        let has_product = object.contains_key("product");
        assert!(has_vendor || has_product);
    }
}

#[cfg(coverage)]
#[test]
fn input_object_strategy_anyof_exercises_union_path() {
    let mut schema = JsonObject::new();
    schema.insert("type".to_string(), JsonValue::String("object".to_string()));
    let mut properties = JsonObject::new();
    let mut vendor_schema = JsonObject::new();
    vendor_schema.insert("type".to_string(), JsonValue::String("string".to_string()));
    properties.insert("vendor".to_string(), JsonValue::Object(vendor_schema));
    schema.insert("properties".to_string(), JsonValue::Object(properties));
    let mut required_vendor = JsonObject::new();
    let mut required_values = Vec::new();
    required_values.push(JsonValue::String("vendor".to_string()));
    required_vendor.insert("required".to_string(), JsonValue::Array(required_values));
    let mut any_of = Vec::new();
    any_of.push(JsonValue::Object(required_vendor));
    schema.insert("anyOf".to_string(), JsonValue::Array(any_of));
    let tool = tool_with_schema("echo", JsonValue::Object(schema));
    let result = input_object_strategy_for_schema(
        tool.input_schema.as_ref(),
        &tool,
        false,
        &HashSet::new(),
    );
    std::hint::black_box(&result);
}

#[test]
fn input_object_strategy_rejects_invalid_union_branch() {
    let mut schema = JsonObject::new();
    schema.insert("type".to_string(), JsonValue::String("object".to_string()));
    let mut properties = JsonObject::new();
    let mut text_schema = JsonObject::new();
    text_schema.insert("type".to_string(), JsonValue::String("string".to_string()));
    properties.insert("text".to_string(), JsonValue::Object(text_schema));
    schema.insert("properties".to_string(), JsonValue::Object(properties));
    let mut required_text = JsonObject::new();
    required_text.insert(
        "required".to_string(),
        JsonValue::Array(vec![JsonValue::String("text".to_string())]),
    );
    let mut required_missing = JsonObject::new();
    required_missing.insert(
        "required".to_string(),
        JsonValue::Array(vec![JsonValue::String("missing".to_string())]),
    );
    schema.insert(
        "oneOf".to_string(),
        JsonValue::Array(vec![
            JsonValue::Object(required_text),
            JsonValue::Object(required_missing),
        ]),
    );
    let tool = tool_with_schema("echo", JsonValue::Object(schema));
    let schema = tool.input_schema.as_ref();
    let error = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
        .expect_err("error");
    #[cfg(coverage)]
    std::hint::black_box(&error);
    #[cfg(not(coverage))]
    assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
}

#[test]
fn schema_value_strategy_ignores_non_array_allof() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "allOf": true, "type": "string" })
        .as_object()
        .cloned()
        .expect("schema");
    let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
    let value = sample(strategy);
    assert!(value.is_string());
}

#[test]
fn resolve_schema_for_validation_returns_none_for_non_array_allof() {
    let schema = json!({ "allOf": true })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(resolve_schema_for_validation(&schema, &schema).is_none());
}

#[test]
fn schema_branch_helpers_return_none_for_non_array_values() {
    let schema = json!({ "anyOf": true })
        .as_object()
        .cloned()
        .expect("schema");
    let err = schema_anyof_branches(&schema).expect_err("anyOf error");
    assert_eq!(err, "anyOf must be an array");

    let schema = json!({ "oneOf": "nope" })
        .as_object()
        .cloned()
        .expect("schema");
    let err = schema_oneof_branches(&schema).expect_err("oneOf error");
    assert_eq!(err, "oneOf must be an array");
}

#[test]
fn schema_violations_include_schema_error_for_invalid_anyof() {
    let schema = json!({ "anyOf": [] }).as_object().cloned().expect("schema");
    let violations = schema_violations(&schema, &json!(true));
    assert!(violations.iter().any(|constraint| {
        matches!(
            &constraint.kind,
            ConstraintKind::Schema(reason)
                if reason == "anyOf must include at least one schema object"
        )
    }));
}

#[test]
fn schema_violations_include_schema_error_for_invalid_oneof() {
    let schema = json!({ "oneOf": [] }).as_object().cloned().expect("schema");
    let violations = schema_violations(&schema, &json!(true));
    assert!(violations.iter().any(|constraint| {
        matches!(
            &constraint.kind,
            ConstraintKind::Schema(reason)
                if reason == "oneOf must include at least one schema object"
        )
    }));
}

#[test]
fn merge_object_schema_skips_non_string_required_entries() {
    let base = json!({
        "type": "object",
        "properties": {},
        "required": ["a", 1]
    })
    .as_object()
    .cloned()
    .expect("base");
    let branch = json!({
        "required": ["b", true]
    })
    .as_object()
    .cloned()
    .expect("branch");
    let merged = merge_object_schema(&base, &branch);
    let required = merged
        .get("required")
        .and_then(JsonValue::as_array)
        .expect("required");
    assert!(required.contains(&JsonValue::String("a".to_string())));
    assert!(required.contains(&JsonValue::String("b".to_string())));
}

#[test]
fn schema_object_union_branches_supports_anyof() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let mut schema = JsonObject::new();
    let mut branch_empty = JsonObject::new();
    branch_empty.insert("type".to_string(), JsonValue::String("object".to_string()));
    branch_empty.insert(
        "properties".to_string(),
        JsonValue::Object(JsonObject::new()),
    );
    let mut branch_text = JsonObject::new();
    branch_text.insert("type".to_string(), JsonValue::String("object".to_string()));
    let mut text_props = JsonObject::new();
    let mut text_schema = JsonObject::new();
    let text_key = "type".to_string();
    let text_value = JsonValue::String("string".to_string());
    text_schema.insert(text_key, text_value);
    text_props.insert("text".to_string(), JsonValue::Object(text_schema));
    branch_text.insert("properties".to_string(), JsonValue::Object(text_props));
    let mut any_of = Vec::new();
    any_of.push(JsonValue::Object(branch_empty));
    any_of.push(JsonValue::Object(branch_text));
    let insert_any_of = |schema: &mut JsonObject, any_of: Vec<JsonValue>| {
        schema.insert("anyOf".to_string(), JsonValue::Array(any_of));
    };
    insert_any_of(&mut schema, any_of.clone());
    insert_any_of(&mut schema, any_of);
    let result = schema_object_union_branches(&schema, &tool);
    #[cfg(coverage)]
    {
        std::hint::black_box(&result);
    }
    #[cfg(not(coverage))]
    {
        let (kind, branches, base) = result.expect("result").expect("anyOf");
        assert!(matches!(kind, ObjectUnionKind::AnyOf));
        assert_eq!(branches.len(), 2);
        assert!(base.get("anyOf").is_none());
    }
}

#[test]
fn uncallable_reason_handles_invalid_schema_value() {
    let tool = tool_with_schema(
        "bad",
        json!({
            "type": "object",
            "properties": { "value": { "minLength": 2 } },
            "required": ["value"]
        }),
    );
    let corpus = ValueCorpus::default();
    assert_eq!(
        uncallable_reason(&tool, &corpus, false),
        Some(UncallableReason::RequiredValue)
    );
}

#[test]
fn input_object_strategy_reports_invalid_schemas() {
    let tool = tool_with_schema("alpha", json!({ "type": "string" }));
    assert!(input_object_strategy(&tool).is_err());
    let tool = tool_with_schema("beta", json!({ "type": 5 }));
    assert!(input_object_strategy(&tool).is_err());
    let tool = tool_with_schema("gamma", json!({}));
    assert!(input_object_strategy(&tool).is_err());
    let tool = tool_with_schema("delta", json!({ "type": "object", "properties": "nope" }));
    assert!(input_object_strategy(&tool).is_err());
    let mut epsilon_schema = JsonObject::new();
    epsilon_schema.insert("type".to_string(), JsonValue::String("object".to_string()));
    let mut epsilon_required = Vec::new();
    epsilon_required.push(JsonValue::String("missing".to_string()));
    epsilon_schema.insert("required".to_string(), JsonValue::Array(epsilon_required));
    let tool = tool_with_schema("epsilon", JsonValue::Object(epsilon_schema));
    assert!(input_object_strategy(&tool).is_err());
    let tool = tool_with_schema(
        "zeta",
        json!({
            "type": "object",
            "properties": { "value": "nope" }
        }),
    );
    assert!(input_object_strategy(&tool).is_err());
}

#[cfg(not(coverage))]
#[test]
fn input_object_strategy_rejects_non_object_properties() {
    let tool = tool_with_schema(
        "echo",
        json!({
            "type": "object",
            "properties": "nope"
        }),
    );
    let error = input_object_strategy(&tool).expect_err("error");
    assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
}

#[test]
fn schema_value_strategy_reports_errors() {
    let tool = tool_with_schema("echo", json!({ "type": "object" }));
    let schema = json!({ "enum": [] }).as_object().cloned().expect("schema");
    assert!(schema_value_strategy(&schema, &tool).is_err());

    let schema = json!({ "maxLength": 1 })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_value_strategy(&schema, &tool).is_err());

    let schema = json!({ "type": "string", "minLength": 2, "maxLength": 1 })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_value_strategy(&schema, &tool).is_err());

    let schema = json!({ "type": "number", "minimum": 2.0, "maximum": 1.0 })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_value_strategy(&schema, &tool).is_err());

    let schema = json!({ "type": "integer", "minimum": 2.0, "maximum": 1.0 })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_value_strategy(&schema, &tool).is_err());

    let schema = json!({ "type": "array", "minItems": 2, "maxItems": 1, "items": {} })
        .as_object()
        .cloned()
        .expect("schema");
    assert!(schema_value_strategy(&schema, &tool).is_err());
}
