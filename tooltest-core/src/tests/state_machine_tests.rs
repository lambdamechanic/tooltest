use std::fmt;
use std::sync::Arc;

use crate::generator::{
    invocation_strategy_from_corpus, state_machine_sequence_strategy, ValueCorpus,
};
use crate::StateMachineConfig;
use proptest::prelude::*;
use rmcp::model::Tool;
use serde_json::{json, Number, Value as JsonValue};

fn number(value: f64) -> Number {
    Number::from_f64(value).expect("number")
}

fn sample<T: fmt::Debug>(strategy: BoxedStrategy<T>) -> T {
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    strategy
        .new_tree(&mut runner)
        .expect("value tree")
        .current()
}

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

#[test]
fn corpus_seeding_preserves_order_and_dedupes() {
    let mut corpus = ValueCorpus::default();

    corpus.seed_numbers([Number::from(1), Number::from(2), Number::from(1)]);
    corpus.seed_strings(["alpha".to_string(), "beta".to_string(), "alpha".to_string()]);

    assert_eq!(corpus.numbers().len(), 2);
    assert_eq!(corpus.numbers()[0], Number::from(1));
    assert_eq!(corpus.numbers()[1], Number::from(2));
    assert_eq!(corpus.strings(), &["alpha".to_string(), "beta".to_string()]);
    assert_eq!(corpus.integers(), &[1, 2]);
}

#[test]
fn corpus_mines_keys_values_with_deterministic_order() {
    let mut corpus = ValueCorpus::default();
    let payload = json!({
        "b": { "d": "x", "c": 2 },
        "a": ["y", { "z": 3 }]
    });

    corpus.mine_structured_content(&payload);

    assert_eq!(
        corpus.strings(),
        &[
            "a".to_string(),
            "y".to_string(),
            "z".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "x".to_string()
        ]
    );
    assert_eq!(corpus.numbers(), &[Number::from(3), Number::from(2)]);
    assert_eq!(corpus.integers(), &[3, 2]);
}

#[test]
fn corpus_only_adds_integral_numbers_to_integer_set() {
    let mut corpus = ValueCorpus::default();

    corpus.seed_numbers([number(1.0), number(2.5), Number::from(3)]);
    corpus.mine_structured_content(&JsonValue::Array(vec![
        JsonValue::Number(number(4.0)),
        JsonValue::Number(number(5.75)),
    ]));

    assert_eq!(corpus.numbers().len(), 5);
    assert_eq!(corpus.integers(), &[1, 3, 4]);
}

#[test]
fn state_machine_generator_uses_integer_corpus_values() {
    let tool = tool_with_schema(
        "count",
        json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            },
            "required": ["count"]
        }),
    );
    let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(7)]);
    let mut corpus = ValueCorpus::default();
    corpus.seed_numbers(config.seed_numbers.clone());
    let strategy = invocation_strategy_from_corpus(&[tool], None, &corpus, false)
        .expect("strategy")
        .expect("callable");
    let invocation = sample(strategy);
    let args = invocation.arguments.as_ref().expect("args");
    assert_eq!(args.get("count"), Some(&json!(7)));
}

#[test]
fn state_machine_generator_returns_empty_when_no_callable_tools() {
    let config = StateMachineConfig::default();
    let strategy = state_machine_sequence_strategy(&[], None, &config, 1..=3).expect("strategy");

    let sequence = sample(strategy);
    assert!(sequence.transitions.is_empty());
}

#[test]
fn state_machine_generator_returns_transitions_when_callable() {
    let tool = tool_with_schema("echo", json!({ "type": "object", "properties": {} }));
    let config = StateMachineConfig::default();
    let strategy =
        state_machine_sequence_strategy(&[tool], None, &config, 1..=1).expect("strategy");

    let sequence = sample(strategy);
    assert_eq!(sequence.transitions.len(), 1);
    assert!(matches!(
        sequence.transitions.first(),
        Some(crate::generator::StateMachineTransition::Invoke(_))
    ));
}

#[test]
fn state_machine_generator_supports_kev_schema_without_seeds() {
    let schema: JsonValue = serde_json::from_str(include_str!(
        "../../tests/fixtures/kev_get_related_cves_schema.json"
    ))
    .expect("schema json");
    let tool = tool_with_schema("get_related_cves", schema);
    let config = StateMachineConfig::default();
    let strategy =
        state_machine_sequence_strategy(&[tool], None, &config, 1..=1).expect("strategy");

    let sequence = sample(strategy);
    assert_eq!(sequence.transitions.len(), 1);
    let invocation = match sequence.transitions.first() {
        Some(crate::generator::StateMachineTransition::Invoke(invocation)) => invocation,
        Some(crate::generator::StateMachineTransition::Skip { .. }) => {
            panic!("expected invocation")
        }
        None => panic!("expected transition"),
    };
    let args = invocation.arguments.as_ref().expect("arguments");
    assert!(args.contains_key("vendor") || args.contains_key("product"));
}
