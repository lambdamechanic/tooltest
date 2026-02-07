use std::sync::Arc;

use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CallToolRequestParam,
    CallToolResult, CoverageRule, PreRunHook, ResponseAssertion, RunConfig, RunWarningCode,
    SchemaConfig, SchemaVersion, StateMachineConfig, StdioConfig, ToolPredicate, TraceEntry,
    TraceSink,
};
use serde_json::json;

struct NoopTraceSink;

impl TraceSink for NoopTraceSink {
    fn record(&self, _case_index: u64, _trace: &[TraceEntry]) {}
}

#[test]
fn schema_config_defaults_to_latest() {
    let config = SchemaConfig::default();
    assert_eq!(config.version, SchemaVersion::V2025_11_25);
}

#[test]
fn stdio_config_new_sets_defaults() {
    let config = StdioConfig::new("mcp-server").expect("stdio config");
    assert_eq!(config.command(), "mcp-server");
    assert!(config.args.is_empty());
    assert!(config.env.is_empty());
    assert!(config.cwd.is_none());
}

#[test]
fn stdio_config_rejects_empty_command() {
    let error = StdioConfig::new("  ").expect_err("expected error");
    assert!(error.contains("stdio command must not be empty"));

    let error = serde_json::from_str::<StdioConfig>(r#"{"command":"  "}"#).unwrap_err();
    assert!(error.to_string().contains("stdio command must not be empty"));
}

#[test]
fn config_deserialization_rejects_non_string_fields() {
    let error = serde_json::from_str::<StdioConfig>(r#"{"command":123}"#).unwrap_err();
    assert!(error.to_string().contains("expected a string"));

    let error = serde_json::from_str::<crate::HttpConfig>(r#"{"url":123}"#).unwrap_err();
    assert!(error.to_string().contains("expected a string"));
}

#[test]
fn config_deserialization_accepts_valid_values() {
    let config: StdioConfig = serde_json::from_str(
        r#"{"command":"server","args":["--flag"],"env":{"KEY":"VALUE"},"cwd":"/tmp"}"#,
    )
    .expect("stdio config");
    assert_eq!(config.command(), "server");
    assert_eq!(config.args, vec!["--flag".to_string()]);
    assert_eq!(config.env.get("KEY").map(String::as_str), Some("VALUE"));
    assert_eq!(config.cwd.as_deref(), Some("/tmp"));

    let config: crate::HttpConfig =
        serde_json::from_str(r#"{"url":"http://localhost:3000/mcp","auth_token":"token"}"#)
            .expect("http config");
    assert_eq!(config.url(), "http://localhost:3000/mcp");
    assert_eq!(config.auth_token.as_deref(), Some("token"));
}

#[test]
fn http_config_validates_url() {
    let config = crate::HttpConfig::new("http://localhost:3000/mcp").expect("http config");
    assert_eq!(config.url(), "http://localhost:3000/mcp");

    let error = crate::HttpConfig::new("localhost:3000/mcp").expect_err("expected error");
    assert!(error.contains("invalid http url"));

    let error = serde_json::from_str::<crate::HttpConfig>(r#"{"url":"file:///tmp/mcp"}"#)
        .unwrap_err();
    assert!(error.to_string().contains("missing host"));
}

#[test]
fn run_config_rejects_uncallable_limit_under_one() {
    let error = RunConfig::new()
        .with_uncallable_limit(0)
        .expect_err("expected error");
    assert!(error.contains("uncallable-limit must be at least 1"));

    let config = RunConfig::new()
        .with_uncallable_limit(2)
        .expect("valid config");
    assert_eq!(config.uncallable_limit(), 2);
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
        .with_assertions(assertions.clone())
        .with_in_band_error_forbidden(true)
        .with_full_trace(true)
        .with_trace_sink(Arc::new(NoopTraceSink));

    assert_eq!(config.schema, schema);
    assert!(config.predicate.is_some());
    assert_eq!(config.assertions.rules.len(), 1);
    assert!(config.in_band_error_forbidden);
    assert!(config.full_trace);
    assert!(config.trace_sink.is_some());
    let predicate = config.predicate.as_ref().expect("predicate set");
    assert!(predicate("search", &json!({"query": "hello"})));
    assert!(!predicate("search", &json!({"query": "nope"})));

    let debug = format!("{config:?}");
    assert!(debug.contains("predicate: true"));
    assert!(debug.contains("trace_sink: true"));
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
    assert_eq!(
        config.in_band_error_forbidden,
        default_config.in_band_error_forbidden
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
fn run_warning_code_extracts_lint_id() {
    let lint = RunWarningCode::lint("missing_structured_content");
    assert_eq!(lint.lint_id(), Some("missing_structured_content"));
    let other = RunWarningCode("custom_warning".to_string());
    assert_eq!(other.lint_id(), None);
}

#[test]
#[allow(deprecated)]
fn run_warning_code_missing_structured_content_builder() {
    let code = RunWarningCode::missing_structured_content();
    assert_eq!(code.as_str(), "missing_structured_content");
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
    let mut endpoint = StdioConfig::new("server").expect("endpoint");
    endpoint.env = env.clone();
    endpoint.cwd = Some("/tmp".to_string());

    config.apply_stdio_pre_run_context(&endpoint);

    let hook = config.pre_run_hook.as_ref().expect("hook");
    assert_eq!(hook.env, env);
    assert_eq!(hook.cwd.as_deref(), Some("/tmp"));
}
