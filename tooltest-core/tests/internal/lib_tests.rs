use std::sync::Arc;

use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CallToolRequestParam,
    CallToolResult, CoverageRule, PreRunHook, ResponseAssertion, RunConfig, SchemaConfig,
    SchemaVersion, StateMachineConfig, StdioConfig, ToolPredicate, TraceEntry,
};
use serde_json::json;

#[test]
fn schema_config_defaults_to_latest() {
    let config = SchemaConfig::default();
    assert_eq!(config.version, SchemaVersion::V2025_11_25);
}

#[test]
fn stdio_config_new_sets_defaults() {
    let config = StdioConfig::new("mcp-server");
    assert_eq!(config.command, "mcp-server");
    assert!(config.args.is_empty());
    assert!(config.env.is_empty());
    assert!(config.cwd.is_none());
}

#[test]
fn run_config_builders_wire_fields() {
    let schema = SchemaConfig {
        version: SchemaVersion::Other("2025-12-01".to_string()),
    };
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: Some("search".to_string()),
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/query".to_string(),
                expected: json!("hello"),
            }],
        })],
    };
    let predicate: ToolPredicate = Arc::new(|name, input| {
        name == "search" && input.pointer("/query") == Some(&json!("hello"))
    });

    let config = RunConfig::new()
        .with_schema(schema.clone())
        .with_predicate(predicate)
        .with_assertions(assertions.clone());

    assert_eq!(config.schema, schema);
    assert!(config.predicate.is_some());
    assert_eq!(config.assertions.rules.len(), 1);
    let predicate = config.predicate.as_ref().expect("predicate set");
    assert!(predicate("search", &json!({"query": "hello"})));
    assert!(!predicate("search", &json!({"query": "nope"})));

    let debug = format!("{config:?}");
    assert!(debug.contains("predicate: true"));
}

#[test]
fn run_config_default_matches_new() {
    let config = RunConfig::new();
    let default_config = RunConfig::default();
    assert_eq!(config.schema, default_config.schema);
    assert_eq!(
        config.predicate.is_some(),
        default_config.predicate.is_some()
    );
    assert_eq!(
        config.assertions.rules.len(),
        default_config.assertions.rules.len()
    );
}

#[test]
fn state_machine_config_sets_seed_strings() {
    let config = StateMachineConfig::default().with_seed_strings(vec!["alpha".to_string()]);
    assert_eq!(config.seed_strings, vec!["alpha".to_string()]);
}

#[test]
fn state_machine_config_sets_lenient_sourcing() {
    let config = StateMachineConfig::default().with_lenient_sourcing(true);
    assert!(config.lenient_sourcing);
}

#[test]
fn state_machine_config_sets_dump_corpus() {
    let config = StateMachineConfig::default().with_dump_corpus(true);
    assert!(config.dump_corpus);
}

#[test]
fn state_machine_config_sets_log_corpus_deltas() {
    let config = StateMachineConfig::default().with_log_corpus_deltas(true);
    assert!(config.log_corpus_deltas);
}

#[test]
fn state_machine_config_sets_mine_text() {
    let config = StateMachineConfig::default().with_mine_text(true);
    assert!(config.mine_text);
}

#[test]
fn coverage_rule_no_uncalled_tools_builder() {
    let rule = CoverageRule::no_uncalled_tools();
    assert!(matches!(rule, CoverageRule::NoUncalledTools));
}

#[test]
fn coverage_rule_min_calls_builder() {
    let rule = CoverageRule::min_calls_per_tool(3);
    assert!(matches!(rule, CoverageRule::MinCallsPerTool { min: 3 }));
}

#[test]
fn coverage_rule_percent_called_builder() {
    let rule = CoverageRule::percent_called(75.0);
    assert!(matches!(rule, CoverageRule::PercentCalled { min_percent } if min_percent == 75.0));
}

#[test]
fn trace_entry_list_tools_is_not_tool_call() {
    let entry = TraceEntry::list_tools();
    assert!(entry.as_tool_call().is_none());
}

#[test]
fn trace_entry_list_tools_with_failure_sets_reason() {
    let entry = TraceEntry::list_tools_with_failure("oops".to_string());
    assert!(matches!(
        entry,
        TraceEntry::ListTools {
            failure_reason: Some(reason)
        } if reason == "oops"
    ));
}

#[test]
fn trace_entry_tool_call_variants_report_payloads() {
    let invocation = CallToolRequestParam {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let entry = TraceEntry::tool_call(invocation.clone());
    let (seen_invocation, response) = entry.as_tool_call().expect("tool call");
    assert_eq!(seen_invocation.name.as_ref(), "echo");
    assert!(response.is_none());

    let response_payload = CallToolResult::structured(json!({ "status": "ok" }));
    let entry = TraceEntry::tool_call_with_response(invocation, response_payload.clone());
    let (_seen_invocation, response) = entry.as_tool_call().expect("tool call");
    assert!(matches!(response, Some(payload) if payload == &response_payload));
}

#[test]
fn run_config_applies_pre_run_hook_stdio_context() {
    let mut config = RunConfig::new().with_pre_run_hook(PreRunHook::new("echo ok"));
    let mut env = std::collections::BTreeMap::new();
    env.insert("FOO".to_string(), "BAR".to_string());
    let endpoint = StdioConfig {
        command: "server".to_string(),
        args: Vec::new(),
        env: env.clone(),
        cwd: Some("/tmp".to_string()),
    };

    config.apply_stdio_pre_run_context(&endpoint);

    let hook = config.pre_run_hook.as_ref().expect("hook");
    assert_eq!(hook.env, env);
    assert_eq!(hook.cwd.as_deref(), Some("/tmp"));
}
