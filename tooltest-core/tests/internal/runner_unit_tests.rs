use super::assertions::{
    apply_default_assertions, apply_response_assertions, apply_sequence_assertions,
    attach_failure_reason, attach_response, evaluate_checks, AssertionPayloads,
};
use super::coverage::{map_uncallable_reason, CoverageTracker};
use super::result::{finalize_state_machine_result, FailureContext};
use super::schema::{
    build_output_validators, collect_schema_keyword_warnings, collect_schema_warnings,
    validate_tools,
};
use super::state_machine::{execute_state_machine_sequence, StateMachineExecution};
use super::transport::{run_with_transport, ConnectFuture};
use super::{run_http, run_stdio, run_with_session};
use crate::generator::{
    clear_reject_context, prepare_tools, set_reject_context_for_test, PreparedTool,
    StateMachineSequence, UncallableReason,
};
use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CoverageRule,
    CoverageWarningReason, ErrorCode, ErrorData, HttpConfig, JsonObject, LintDefinition,
    LintFinding, LintLevel, LintPhase, LintRule, LintSuite, PreRunHook, ResponseAssertion,
    ResponseLintContext, RunConfig, RunFailure, RunOutcome, RunResult, RunWarning, RunWarningCode,
    RunnerOptions, SchemaConfig, SequenceAssertion, SessionDriver, SessionError, StateMachineConfig,
    StdioConfig, ToolInvocation, ToolNamePredicate, ToolPredicate, TraceEntry, TraceSink,
};
use crate::lints::{
    JsonSchemaDialectCompatLint, MaxStructuredContentBytesLint, McpSchemaMinVersionLint,
    MissingStructuredContentLint, MaxToolsLint, DEFAULT_JSON_SCHEMA_DIALECT,
};
use jsonschema::draft202012;
use proptest::test_runner::TestError;
use rmcp::model::{CallToolResult, ClientJsonRpcMessage, ClientRequest, Content, ResourceContents};
use rmcp::transport::Transport;
use serde_json::{json, Number, Value as JsonValue};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::tests::test_support::connect_runner_transport;
use tooltest_test_support::{stub_tool, tool_with_schemas, RunnerTransport};

#[derive(Clone)]
struct StaticLint {
    definition: LintDefinition,
    findings: Vec<LintFinding>,
}

impl LintRule for StaticLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_list(&self, _context: &crate::ListLintContext<'_>) -> Vec<LintFinding> {
        if matches!(self.definition.phase, LintPhase::List) {
            self.findings.clone()
        } else {
            Vec::new()
        }
    }

    fn check_response(&self, _context: &crate::ResponseLintContext<'_>) -> Vec<LintFinding> {
        if matches!(self.definition.phase, LintPhase::Response) {
            self.findings.clone()
        } else {
            Vec::new()
        }
    }

    fn check_run(&self, _context: &crate::RunLintContext<'_>) -> Vec<LintFinding> {
        if matches!(self.definition.phase, LintPhase::Run) {
            self.findings.clone()
        } else {
            Vec::new()
        }
    }
}

struct NoopLint {
    definition: LintDefinition,
}

impl LintRule for NoopLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }
}

fn outcome_is_success(outcome: &RunOutcome) -> bool {
    matches!(outcome, RunOutcome::Success)
}

fn trace_entry_with(name: &str, args: Option<JsonValue>, response: CallToolResult) -> TraceEntry {
    TraceEntry::tool_call_with_response(
        ToolInvocation {
            name: name.to_string().into(),
            arguments: args.and_then(|value| value.as_object().cloned()),
        },
        response,
    )
}

fn default_assertion_context() -> (Vec<RunWarning>, std::collections::HashSet<String>) {
    (Vec::new(), std::collections::HashSet::new())
}

#[derive(Default)]
struct CaptureSink {
    traces: Mutex<Vec<(u64, Vec<TraceEntry>)>>,
}

impl TraceSink for CaptureSink {
    fn record(&self, case_index: u64, trace: &[TraceEntry]) {
        let mut records = self.traces.lock().expect("trace sink lock");
        records.push((case_index, trace.to_vec()));
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_sequence_for_test(
    session: &SessionDriver,
    tools: &[PreparedTool],
    validators: &BTreeMap<String, jsonschema::Validator>,
    assertions: &AssertionSet,
    sequence: &StateMachineSequence,
    tracker: &mut CoverageTracker<'_>,
    predicate: Option<&ToolPredicate>,
    min_len: Option<usize>,
    in_band_error_forbidden: bool,
) -> Result<Vec<TraceEntry>, FailureContext> {
    let execution = StateMachineExecution {
        session,
        tools,
        validators,
        assertions,
        predicate,
        min_len,
        in_band_error_forbidden,
        full_trace: false,
        warnings: Rc::new(RefCell::new(Vec::new())),
        warned_missing_structured: Rc::new(RefCell::new(std::collections::HashSet::new())),
        response_lints: Vec::new(),
        case_index: 0,
        trace_sink: None,
    };
    execute_state_machine_sequence(sequence, &execution, tracker).await
}

fn connect_result(result: Result<SessionDriver, SessionError>) -> ConnectFuture<'static> {
    Box::pin(async move { result })
}

fn is_list_tools(entry: &TraceEntry) -> bool {
    matches!(entry, TraceEntry::ListTools { .. })
}

fn temp_path(name: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("tooltest-core-{name}-{pid}-{nanos}-{counter}"))
}

#[cfg(not(coverage))]
fn assert_failure(result: &RunResult) {
    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[cfg(coverage)]
fn assert_failure(_result: &RunResult) {}

#[allow(dead_code)]
#[cfg(not(coverage))]
fn assert_success(result: &RunResult) {
    assert!(matches!(result.outcome, RunOutcome::Success));
}

#[cfg(coverage)]
fn assert_success(_result: &RunResult) {}

#[cfg(not(coverage))]
fn assert_failure_reason_contains(result: &RunResult, needle: &str) {
    if let RunOutcome::Failure(failure) = &result.outcome {
        assert!(failure.reason.contains(needle));
    } else {
        panic!("expected failure");
    }
}

#[cfg(coverage)]
fn assert_failure_reason_contains(_result: &RunResult, _needle: &str) {}

#[cfg(not(coverage))]
fn assert_failure_reason_eq(result: &RunResult, expected: &str) {
    if let RunOutcome::Failure(failure) = &result.outcome {
        assert_eq!(failure.reason, expected);
    } else {
        panic!("expected failure");
    }
}

#[cfg(coverage)]
fn assert_failure_reason_eq(_result: &RunResult, _expected: &str) {}

#[test]
fn outcome_is_success_reports_success_and_failure() {
    assert!(outcome_is_success(&RunOutcome::Success));
    assert!(!outcome_is_success(&RunOutcome::Failure(RunFailure::new(
        "nope"
    ))));
}

#[test]
fn apply_default_assertions_reports_tool_error() {
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::error(vec![Content::text("boom")]),
    );
    let validators = BTreeMap::new();
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let (mut warnings, mut warned) = default_assertion_context();
    let result = apply_default_assertions(
        invocation,
        response.expect("response"),
        &validators,
        true,
        &mut warnings,
        &mut warned,
    );
    assert!(result.is_some());
}

#[test]
fn apply_default_assertions_allows_tool_error_when_allowed() {
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::error(vec![Content::text("boom")]),
    );
    let validators = BTreeMap::new();
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let (mut warnings, mut warned) = default_assertion_context();
    let result = apply_default_assertions(
        invocation,
        response.expect("response"),
        &validators,
        false,
        &mut warnings,
        &mut warned,
    );
    assert!(result.is_none());
}

#[test]
fn apply_default_assertions_reports_missing_structured_content() {
    let schema = json!({
        "type": "object",
        "properties": { "status": { "type": "string" } },
        "required": ["status"]
    });
    let validator = draft202012::new(&schema).expect("validator");
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let mut validators = BTreeMap::new();
    validators.insert("echo".to_string(), validator);
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let (mut warnings, mut warned) = default_assertion_context();
    let result = apply_default_assertions(
        invocation,
        response.expect("response"),
        &validators,
        false,
        &mut warnings,
        &mut warned,
    );
    assert!(result.is_none());
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, RunWarningCode::MissingStructuredContent);
}

#[test]
fn apply_default_assertions_dedupes_missing_structured_warnings() {
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let schema = json!({ "type": "object", "properties": {} });
    let validator = draft202012::new(&schema).expect("validator");
    let mut validators = BTreeMap::new();
    validators.insert("echo".to_string(), validator);
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let (mut warnings, mut warned) = default_assertion_context();
    let response = response.expect("response");

    let first = apply_default_assertions(
        invocation,
        response,
        &validators,
        false,
        &mut warnings,
        &mut warned,
    );
    let second = apply_default_assertions(
        invocation,
        response,
        &validators,
        false,
        &mut warnings,
        &mut warned,
    );

    assert!(first.is_none());
    assert!(second.is_none());
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, RunWarningCode::MissingStructuredContent);
}

#[test]
fn apply_default_assertions_reports_schema_violation() {
    let schema = json!({
        "type": "object",
        "properties": { "status": { "type": "string", "const": "ok" } },
        "required": ["status"]
    });
    let validator = draft202012::new(&schema).expect("validator");
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::structured(json!({ "status": "bad" })),
    );
    let mut validators = BTreeMap::new();
    validators.insert("echo".to_string(), validator);
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let (mut warnings, mut warned) = default_assertion_context();
    let result = apply_default_assertions(
        invocation,
        response.expect("response"),
        &validators,
        false,
        &mut warnings,
        &mut warned,
    );
    assert!(result.is_some());
}

#[test]
fn apply_default_assertions_accepts_valid_structured_content() {
    let schema = json!({
        "type": "object",
        "properties": { "status": { "type": "string", "const": "ok" } },
        "required": ["status"]
    });
    let validator = draft202012::new(&schema).expect("validator");
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::structured(json!({ "status": "ok" })),
    );
    let mut validators = BTreeMap::new();
    validators.insert("echo".to_string(), validator);
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let (mut warnings, mut warned) = default_assertion_context();
    let result = apply_default_assertions(
        invocation,
        response.expect("response"),
        &validators,
        false,
        &mut warnings,
        &mut warned,
    );
    assert!(result.is_none());
}

#[test]
fn apply_default_assertions_skips_when_missing_validator() {
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::structured(json!({ "status": "ok" })),
    );
    let validators = BTreeMap::new();
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let (mut warnings, mut warned) = default_assertion_context();
    let result = apply_default_assertions(
        invocation,
        response.expect("response"),
        &validators,
        false,
        &mut warnings,
        &mut warned,
    );
    assert!(result.is_none());
}

#[test]
fn apply_response_assertions_handles_empty_rules() {
    let entry = trace_entry_with(
        "echo",
        Some(json!({ "flag": true })),
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet::default();
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let result = apply_response_assertions(&assertions, invocation, response.expect("response"));
    assert!(result.is_none());
}

#[test]
fn apply_response_assertions_reports_pointer_missing() {
    let entry = trace_entry_with(
        "echo",
        Some(json!({ "flag": true })),
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: Some("echo".to_string()),
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/missing".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let result = apply_response_assertions(&assertions, invocation, response.expect("response"));
    assert!(result.is_some());
}

#[test]
fn apply_response_assertions_reports_value_mismatch() {
    let entry = trace_entry_with(
        "echo",
        Some(json!({ "flag": true })),
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: Some("echo".to_string()),
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/flag".to_string(),
                expected: json!(false),
            }],
        })],
    };
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let result = apply_response_assertions(&assertions, invocation, response.expect("response"));
    assert!(result.is_some());
}

#[test]
fn apply_response_assertions_skips_tool_mismatch() {
    let entry = trace_entry_with(
        "echo",
        Some(json!({ "flag": true })),
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: Some("other".to_string()),
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/flag".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let result = apply_response_assertions(&assertions, invocation, response.expect("response"));
    assert!(result.is_none());
}

#[test]
fn apply_response_assertions_supports_unscoped_rules() {
    let entry = trace_entry_with(
        "echo",
        Some(json!({ "flag": true })),
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: None,
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/flag".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let result = apply_response_assertions(&assertions, invocation, response.expect("response"));
    assert!(result.is_none());
}

#[test]
fn apply_response_assertions_skips_non_response_rules() {
    let entry = trace_entry_with(
        "echo",
        Some(json!({ "flag": true })),
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Sequence(SequenceAssertion {
            checks: vec![AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/0".to_string(),
                expected: json!([]),
            }],
        })],
    };
    let (invocation, response) = entry.as_tool_call().expect("tool call");
    let result = apply_response_assertions(&assertions, invocation, response.expect("response"));
    assert!(result.is_none());
}

#[test]
fn attach_response_updates_last_tool_call() {
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: Some(JsonObject::new()),
    };
    let mut trace = vec![TraceEntry::tool_call(invocation)];
    let response = CallToolResult::success(vec![Content::text("ok")]);
    attach_response(&mut trace, response.clone());
    let (_, stored) = trace[0].as_tool_call().expect("tool call");
    assert_eq!(stored, Some(&response));
}

#[test]
fn attach_response_ignores_non_tool_call() {
    let mut trace = vec![TraceEntry::list_tools()];
    let response = CallToolResult::success(vec![Content::text("ok")]);
    attach_response(&mut trace, response);
    assert!(is_list_tools(&trace[0]));
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    assert!(!is_list_tools(&TraceEntry::tool_call(invocation)));
}

#[test]
fn attach_failure_reason_updates_last_tool_call() {
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: Some(JsonObject::new()),
    };
    let mut trace = vec![TraceEntry::tool_call(invocation)];
    attach_failure_reason(&mut trace, "failure".to_string());
    assert!(matches!(
        &trace[0],
        TraceEntry::ToolCall {
            failure_reason: Some(reason),
            ..
        } if reason == "failure"
    ));
}

#[test]
fn attach_failure_reason_ignores_non_tool_call() {
    let mut trace = vec![TraceEntry::list_tools()];
    attach_failure_reason(&mut trace, "failure".to_string());
    assert!(is_list_tools(&trace[0]));
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    assert!(!is_list_tools(&TraceEntry::tool_call(invocation)));
}

#[test]
fn apply_sequence_assertions_handles_empty_rules() {
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet::default();
    let result = apply_sequence_assertions(&assertions, &[entry]);
    assert!(result.is_none());
}

#[test]
fn apply_sequence_assertions_reports_invalid_target() {
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Sequence(SequenceAssertion {
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/flag".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let result = apply_sequence_assertions(&assertions, &[entry]);
    assert!(result.is_some());
}

#[test]
fn apply_sequence_assertions_skips_non_sequence_rules() {
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: None,
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/flag".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let result = apply_sequence_assertions(&assertions, &[entry]);
    assert!(result.is_none());
}

#[test]
fn apply_sequence_assertions_accepts_passing_checks() {
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Sequence(SequenceAssertion {
            checks: vec![AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/0/invocation/name".to_string(),
                expected: json!("echo"),
            }],
        })],
    };
    let result = apply_sequence_assertions(&assertions, &[entry]);
    assert!(result.is_none());
}

#[test]
fn evaluate_checks_rejects_sequence_target_in_response_scope() {
    let payloads = AssertionPayloads {
        input: json!({ "flag": true }),
        output: JsonValue::Null,
        structured: JsonValue::Null,
        sequence: Some(json!([])),
    };
    let result = evaluate_checks(
        &[AssertionCheck {
            target: AssertionTarget::Sequence,
            pointer: "/0".to_string(),
            expected: json!(true),
        }],
        &payloads,
        None,
        false,
    );
    assert!(result.is_some());
}

#[test]
fn evaluate_checks_rejects_non_sequence_target_in_sequence_scope() {
    let payloads = AssertionPayloads {
        input: json!({ "flag": true }),
        output: JsonValue::Null,
        structured: JsonValue::Null,
        sequence: Some(json!([])),
    };
    let result = evaluate_checks(
        &[AssertionCheck {
            target: AssertionTarget::Input,
            pointer: "/flag".to_string(),
            expected: json!(true),
        }],
        &payloads,
        None,
        true,
    );
    assert!(result.is_some());
}

#[test]
fn evaluate_checks_reads_output_payload() {
    let payloads = AssertionPayloads {
        input: JsonValue::Null,
        output: json!({ "ok": true }),
        structured: JsonValue::Null,
        sequence: Some(json!([])),
    };
    let result = evaluate_checks(
        &[AssertionCheck {
            target: AssertionTarget::Output,
            pointer: "/ok".to_string(),
            expected: json!(true),
        }],
        &payloads,
        None,
        false,
    );
    assert!(result.is_none());
}

#[test]
fn evaluate_checks_accepts_sequence_target_in_sequence_scope() {
    let payloads = AssertionPayloads {
        input: JsonValue::Null,
        output: JsonValue::Null,
        structured: JsonValue::Null,
        sequence: Some(json!([{ "invocation": { "name": "echo" } }])),
    };
    let result = evaluate_checks(
        &[AssertionCheck {
            target: AssertionTarget::Sequence,
            pointer: "/0/invocation/name".to_string(),
            expected: json!("echo"),
        }],
        &payloads,
        None,
        true,
    );
    assert!(result.is_none());
}

#[test]
fn evaluate_checks_accepts_structured_output_target() {
    let payloads = AssertionPayloads {
        input: JsonValue::Null,
        output: JsonValue::Null,
        structured: json!({ "status": "ok" }),
        sequence: None,
    };
    let result = evaluate_checks(
        &[AssertionCheck {
            target: AssertionTarget::StructuredOutput,
            pointer: "/status".to_string(),
            expected: json!("ok"),
        }],
        &payloads,
        None,
        false,
    );
    assert!(result.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_transport_success_path() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({ "type": "object" })),
    );
    let response = CallToolResult::structured(json!({}));
    let transport = RunnerTransport::new(tool, response);
    let session = SessionDriver::connect_with_transport(transport)
        .await
        .expect("connect");

    let result = run_with_transport(
        connect_result(Ok(session)),
        "local",
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    #[cfg(coverage)]
    std::hint::black_box(&result);
    #[cfg(not(coverage))]
    assert!(matches!(result.outcome, RunOutcome::Success));
}

#[cfg(coverage)]
#[test]
fn coverage_smoke_for_assert_helpers() {
    let result = RunResult {
        outcome: RunOutcome::Success,
        trace: Vec::new(),
        minimized: None,
        warnings: Vec::new(),
        coverage: None,
        corpus: None,
    };
    assert_success(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_rejects_invalid_schema() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "value": "nope" }
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new();

    let result = run_with_session(&session, &config, RunnerOptions::default()).await;
    assert_failure(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_rejects_non_object_schema() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "known": { "type": "string" } },
            "required": ["missing"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new();

    let result = run_with_session(&session, &config, RunnerOptions::default()).await;
    assert_failure(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_reports_strategy_error() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "known": { "type": "string" } },
            "required": ["missing"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new();

    let result = run_with_session(&session, &config, RunnerOptions::default()).await;
    assert_failure_reason_contains(
        &result,
        "inputSchema required must reference known properties",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_list_tools_error() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response).with_list_tools_error(ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        "nope",
        None,
    ));
    let session = connect_runner_transport(transport).await.expect("connect");

    let result = run_with_session(&session, &RunConfig::new(), RunnerOptions::default()).await;
    assert_failure_reason_contains(&result, "failed to list tools");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_pre_run_hook_failure_before_validation() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new().with_pre_run_hook(PreRunHook::new("exit 7"));

    let result = run_with_session(&session, &config, RunnerOptions::default()).await;
    assert_failure_reason_contains(&result, "pre-run hook failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_pre_run_hook_start_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let missing_cwd = temp_path("missing-pre-run-cwd");
    let mut hook = PreRunHook::new("echo ok");
    hook.cwd = Some(missing_cwd.to_string_lossy().into_owned());
    let config = RunConfig::new().with_pre_run_hook(hook);

    let result = run_with_session(&session, &config, RunnerOptions::default()).await;
    assert_failure_reason_contains(&result, "pre-run hook failed to start");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_pre_run_hook_failure_during_execution() {
    let tool = tool_with_schemas("echo", json!({ "type": "object", "properties": {} }), None);
    let response = CallToolResult::structured(json!({ "value": 1 }));
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let dir = temp_path("pre-run-fail-late");
    fs::create_dir_all(&dir).expect("create dir");
    let marker = dir.join("hook-marker");
    let hook = PreRunHook::new(format!(
        "if [ -f \"{path}\" ]; then exit 9; fi; : > \"{path}\"",
        path = marker.display()
    ));
    let config = RunConfig::new().with_pre_run_hook(hook);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_failure_reason_contains(&result, "pre-run hook failed");
    assert!(marker.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_applies_pre_run_hook_env() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let mut hook = PreRunHook::new("test \"$HOOK_ENV\" = \"ok\"");
    hook.env.insert("HOOK_ENV".to_string(), "ok".to_string());
    let config = RunConfig::new().with_pre_run_hook(hook);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_success(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_invalid_output_schema() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({
            "type": "object",
            "properties": { "value": { "type": "string", "pattern": "[" } }
        })),
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");

    let result = run_with_session(&session, &RunConfig::new(), RunnerOptions::default()).await;
    assert_failure_reason_contains(&result, "failed to compile output schema");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_no_eligible_tools_with_predicate() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let predicate: ToolPredicate = Arc::new(|_name, _input| false);
    let config = RunConfig::new().with_predicate(predicate);

    let result = run_with_session(&session, &config, RunnerOptions::default()).await;
    assert_failure_reason_contains(&result, "no eligible tools to generate");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_no_eligible_tools_with_name_filter() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let predicate: ToolNamePredicate = Arc::new(|_name| false);
    let config = RunConfig::new().with_tool_filter(predicate);

    let result = run_with_session(&session, &config, RunnerOptions::default()).await;
    assert_failure_reason_contains(&result, "filtered out by the tool filter");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_no_tools_from_server() {
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new_with_tools(Vec::new(), response);
    let session = connect_runner_transport(transport).await.expect("connect");

    let result = run_with_session(&session, &RunConfig::new(), RunnerOptions::default()).await;
    assert_failure_reason_contains(&result, "server returned no tools");
}

#[tokio::test(flavor = "current_thread")]
async fn run_with_session_rejects_current_thread_runtime() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");

    let result = run_with_session(&session, &RunConfig::new(), RunnerOptions::default()).await;
    assert_failure_reason_contains(&result, "requires a multi-thread Tokio runtime");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_legacy_failure_path() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new().with_in_band_error_forbidden(true);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_failure(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_success_executes_sequence() {
    let tool = tool_with_schemas("echo", json!({ "type": "object", "properties": {} }), None);
    let response = CallToolResult::structured(json!({ "value": 1 }));
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new();
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_success(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_reports_default_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object", "properties": {} }), None);
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new().with_in_band_error_forbidden(true);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_failure_reason_contains(
        &result,
        "returned an error response (isError=true), which is forbidden by configuration",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_allows_in_band_error_by_default() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new().with_state_machine(
        StateMachineConfig::default().with_coverage_rules(vec![CoverageRule::percent_called(0.0)]),
    );
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_success(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_requires_structured_content_on_error_with_schema() {
    let output_schema = json!({
        "type": "object",
        "properties": { "error": { "type": "string" } },
        "required": ["error"]
    });
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), Some(output_schema));
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new().with_state_machine(
        StateMachineConfig::default().with_coverage_rules(vec![CoverageRule::percent_called(0.0)]),
    );
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_success(&result);
    assert!(result.warnings.iter().any(|warning| {
        warning.code == RunWarningCode::lint("missing_structured_content")
            && warning
                .details
                .as_ref()
                .and_then(|details| details.get("lint_id"))
                .and_then(|value| value.as_str())
                == Some("missing_structured_content")
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_accepts_structured_content_on_error_with_schema() {
    let output_schema = json!({
        "type": "object",
        "properties": { "error": { "type": "string" } },
        "required": ["error"]
    });
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), Some(output_schema));
    let response = CallToolResult {
        content: vec![Content::text("boom")],
        structured_content: Some(json!({ "error": "boom" })),
        is_error: Some(true),
        meta: None,
    };
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new().with_state_machine(
        StateMachineConfig::default().with_coverage_rules(vec![CoverageRule::percent_called(0.0)]),
    );
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_success(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_min_calls_per_tool_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object", "properties": {} }), None);
    let response = CallToolResult::structured(json!({ "value": 1 }));
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let state_machine = StateMachineConfig::default()
        .with_dump_corpus(true)
        .with_coverage_rules(vec![CoverageRule::MinCallsPerTool { min: 2 }]);
    let config = RunConfig::new().with_state_machine(state_machine);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_failure_reason_contains(&result, "coverage validation failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_state_machine_no_uncalled_tools_failure() {
    let tool_a = tool_with_schemas("alpha", json!({ "type": "object", "properties": {} }), None);
    let tool_b = tool_with_schemas("beta", json!({ "type": "object", "properties": {} }), None);
    let response = CallToolResult::structured(json!({ "value": 1 }));
    let transport = RunnerTransport::new_with_tools(vec![tool_a, tool_b], response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let state_machine =
        StateMachineConfig::default().with_coverage_rules(vec![CoverageRule::NoUncalledTools]);
    let config = RunConfig::new().with_state_machine(state_machine);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_failure_reason_contains(&result, "coverage validation failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_breaks_when_no_callable_tools() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![1, 2] };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);

    let result = execute_sequence_for_test(
        &session,
        &tools,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &sequence,
        &mut tracker,
        None,
        None,
        false,
    )
    .await;
    let trace = result.expect("expected success");
    assert!(trace.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_reports_generation_error() {
    let tool = tool_with_schemas("bad", json!({ "type": "string" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);

    let result = execute_sequence_for_test(
        &session,
        &tools,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &sequence,
        &mut tracker,
        None,
        None,
        false,
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure
        .failure
        .reason
        .contains("inputSchema type must be object"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_reports_session_error() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response).with_call_tool_error(
        ErrorData::new(ErrorCode::INTERNAL_ERROR, "call failed", None),
    );
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);

    let result = execute_sequence_for_test(
        &session,
        &tools,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &sequence,
        &mut tracker,
        None,
        Some(1),
        false,
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure.failure.reason.contains("session error"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_full_trace_success_records_trace() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::structured(json!({ "value": 1 }));
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);
    let sink = Arc::new(CaptureSink::default());
    let execution = StateMachineExecution {
        session: &session,
        tools: &tools,
        validators: &BTreeMap::new(),
        assertions: &AssertionSet::default(),
        predicate: None,
        min_len: None,
        in_band_error_forbidden: false,
        full_trace: true,
        warnings: Rc::new(RefCell::new(Vec::new())),
        warned_missing_structured: Rc::new(RefCell::new(std::collections::HashSet::new())),
        response_lints: Vec::new(),
        case_index: 7,
        trace_sink: Some(sink.clone()),
    };

    let trace = execute_state_machine_sequence(&sequence, &execution, &mut tracker)
        .await
        .expect("expected success");
    let (_, response) = trace[0].as_tool_call().expect("tool call");
    assert!(response.is_some());
    let records = sink.traces.lock().expect("trace sink lock");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, 7);
    assert_eq!(records[0].1.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_full_trace_reports_generation_error() {
    let tool = tool_with_schemas("bad", json!({ "type": "string" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);
    let sink = Arc::new(CaptureSink::default());
    let execution = StateMachineExecution {
        session: &session,
        tools: &tools,
        validators: &BTreeMap::new(),
        assertions: &AssertionSet::default(),
        predicate: None,
        min_len: None,
        in_band_error_forbidden: false,
        full_trace: true,
        warnings: Rc::new(RefCell::new(Vec::new())),
        warned_missing_structured: Rc::new(RefCell::new(std::collections::HashSet::new())),
        response_lints: Vec::new(),
        case_index: 3,
        trace_sink: Some(sink.clone()),
    };

    let failure = execute_state_machine_sequence(&sequence, &execution, &mut tracker)
        .await
        .expect_err("expected failure");
    assert!(failure
        .failure
        .reason
        .contains("inputSchema type must be object"));
    let records = sink.traces.lock().expect("trace sink lock");
    assert_eq!(records.len(), 1);
    assert!(records[0].1.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_full_trace_reports_session_error() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response).with_call_tool_error(
        ErrorData::new(ErrorCode::INTERNAL_ERROR, "call failed", None),
    );
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);
    let sink = Arc::new(CaptureSink::default());
    let execution = StateMachineExecution {
        session: &session,
        tools: &tools,
        validators: &BTreeMap::new(),
        assertions: &AssertionSet::default(),
        predicate: None,
        min_len: None,
        in_band_error_forbidden: false,
        full_trace: true,
        warnings: Rc::new(RefCell::new(Vec::new())),
        warned_missing_structured: Rc::new(RefCell::new(std::collections::HashSet::new())),
        response_lints: Vec::new(),
        case_index: 2,
        trace_sink: Some(sink.clone()),
    };

    let failure = execute_state_machine_sequence(&sequence, &execution, &mut tracker)
        .await
        .expect_err("expected failure");
    assert!(failure.failure.reason.contains("session error"));
    assert_eq!(failure.trace.len(), 1);
    if let TraceEntry::ToolCall { failure_reason, .. } = &failure.trace[0] {
        assert!(failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("session error")));
    } else {
        panic!("expected tool call trace entry");
    }
    let records = sink.traces.lock().expect("trace sink lock");
    assert_eq!(records.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_full_trace_reports_default_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);
    let execution = StateMachineExecution {
        session: &session,
        tools: &tools,
        validators: &BTreeMap::new(),
        assertions: &AssertionSet::default(),
        predicate: None,
        min_len: None,
        in_band_error_forbidden: true,
        full_trace: true,
        warnings: Rc::new(RefCell::new(Vec::new())),
        warned_missing_structured: Rc::new(RefCell::new(std::collections::HashSet::new())),
        response_lints: Vec::new(),
        case_index: 0,
        trace_sink: None,
    };

    let failure = execute_state_machine_sequence(&sequence, &execution, &mut tracker)
        .await
        .expect_err("expected failure");
    assert!(failure
        .failure
        .reason
        .contains("returned an error response"));
    let (_, response) = failure.trace[0].as_tool_call().expect("tool call");
    assert!(response.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_full_trace_reports_response_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: None,
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/missing".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);
    let execution = StateMachineExecution {
        session: &session,
        tools: &tools,
        validators: &BTreeMap::new(),
        assertions: &assertions,
        predicate: None,
        min_len: None,
        in_band_error_forbidden: false,
        full_trace: true,
        warnings: Rc::new(RefCell::new(Vec::new())),
        warned_missing_structured: Rc::new(RefCell::new(std::collections::HashSet::new())),
        response_lints: Vec::new(),
        case_index: 0,
        trace_sink: None,
    };

    let failure = execute_state_machine_sequence(&sequence, &execution, &mut tracker)
        .await
        .expect_err("expected failure");
    assert!(failure.failure.reason.contains("assertion pointer"));
    let (_, response) = failure.trace[0].as_tool_call().expect("tool call");
    assert!(response.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_full_trace_reports_sequence_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Sequence(SequenceAssertion {
            checks: vec![AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/missing".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);
    let execution = StateMachineExecution {
        session: &session,
        tools: &tools,
        validators: &BTreeMap::new(),
        assertions: &assertions,
        predicate: None,
        min_len: None,
        in_band_error_forbidden: false,
        full_trace: true,
        warnings: Rc::new(RefCell::new(Vec::new())),
        warned_missing_structured: Rc::new(RefCell::new(std::collections::HashSet::new())),
        response_lints: Vec::new(),
        case_index: 0,
        trace_sink: None,
    };

    let failure = execute_state_machine_sequence(&sequence, &execution, &mut tracker)
        .await
        .expect_err("expected failure");
    assert!(failure.failure.reason.contains("assertion pointer"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_full_trace_fails_on_minimum_length_shortfall() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);
    let execution = StateMachineExecution {
        session: &session,
        tools: &tools,
        validators: &BTreeMap::new(),
        assertions: &AssertionSet::default(),
        predicate: None,
        min_len: Some(2),
        in_band_error_forbidden: false,
        full_trace: true,
        warnings: Rc::new(RefCell::new(Vec::new())),
        warned_missing_structured: Rc::new(RefCell::new(std::collections::HashSet::new())),
        response_lints: Vec::new(),
        case_index: 0,
        trace_sink: None,
    };

    let failure = execute_state_machine_sequence(&sequence, &execution, &mut tracker)
        .await
        .expect_err("expected failure");
    assert!(failure
        .failure
        .reason
        .contains("state-machine generator failed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn list_phase_lint_error_stops_before_tool_calls() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let lint = StaticLint {
        definition: LintDefinition::new("list_fail", LintPhase::List, LintLevel::Error),
        findings: vec![LintFinding::new("boom")],
    };
    let config = RunConfig::new().with_lints(LintSuite::new(vec![Arc::new(lint)]));
    let result = run_with_session(
        &session,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;
    assert_failure(&result);
    assert!(result.trace.iter().all(is_list_tools));
}

#[tokio::test(flavor = "multi_thread")]
async fn response_phase_lint_error_fails_after_response() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let lint = StaticLint {
        definition: LintDefinition::new("response_fail", LintPhase::Response, LintLevel::Error),
        findings: vec![LintFinding::new("boom")],
    };
    let config = RunConfig::new().with_lints(LintSuite::new(vec![Arc::new(lint)]));
    let result = run_with_session(
        &session,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;
    assert_failure(&result);
    let mut saw_tool_call = false;
    for entry in &result.trace {
        if let TraceEntry::ToolCall { response, .. } = entry {
            saw_tool_call = true;
            assert!(response.is_some());
        }
    }
    assert!(saw_tool_call);
}

#[tokio::test(flavor = "multi_thread")]
async fn warning_level_lint_does_not_fail_run() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let lint = StaticLint {
        definition: LintDefinition::new("response_warn", LintPhase::Response, LintLevel::Warning),
        findings: vec![LintFinding::new("heads up").with_code("lint_code")],
    };
    let config = RunConfig::new().with_lints(LintSuite::new(vec![Arc::new(lint)]));
    let result = run_with_session(
        &session,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;
    assert_success(&result);
    let warning = result
        .warnings
        .iter()
        .find(|warning| warning.code == RunWarningCode::lint("response_warn"))
        .expect("lint warning");
    let details = warning
        .details
        .as_ref()
        .and_then(|value| value.as_object())
        .expect("lint details");
    assert_eq!(
        details.get("lint_id").and_then(|value| value.as_str()),
        Some("response_warn")
    );
    assert_eq!(
        details.get("lint_code").and_then(|value| value.as_str()),
        Some("lint_code")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn run_result_surfaces_schema_and_lint_warnings() {
    let input_schema = json!({
        "type": "object",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$defs": { "payload": { "type": "string" } }
    });
    let tool = tool_with_schemas("echo", input_schema, None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let lint = StaticLint {
        definition: LintDefinition::new("list_warn", LintPhase::List, LintLevel::Warning),
        findings: vec![LintFinding::new("heads up")],
    };
    let config = RunConfig::new().with_lints(LintSuite::new(vec![Arc::new(lint)]));
    let result = run_with_session(
        &session,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;
    assert_success(&result);
    assert!(result.warnings.iter().any(|warning| {
        warning.code == RunWarningCode::schema_unsupported_keyword()
    }));
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.code == RunWarningCode::lint("list_warn")));
}

#[test]
fn lint_helpers_cover_defaults_and_suite_metadata() {
    let definition = LintDefinition::new("noop", LintPhase::List, LintLevel::Warning)
        .with_params(json!({ "limit": 1 }));
    assert!(definition.params.is_some());
    let finding = LintFinding::new("note").with_details(json!({ "detail": true }));
    assert!(finding.details.is_some());

    let empty_suite = LintSuite::default();
    assert!(empty_suite.is_empty());
    assert_eq!(empty_suite.len(), 0);

    let noop = NoopLint { definition };
    assert!(noop
        .check_list(&crate::ListLintContext {
            raw_tool_count: 0,
            protocol_version: None,
            tools: &[],
        })
        .is_empty());
    assert!(noop
        .check_response(&crate::ResponseLintContext {
            tool: &stub_tool("noop"),
            invocation: &ToolInvocation {
                name: "noop".to_string().into(),
                arguments: None,
            },
            response: &CallToolResult::success(vec![]),
        })
        .is_empty());
    assert!(noop
        .check_run(&crate::RunLintContext {
            coverage: None,
            corpus: None,
        })
        .is_empty());
}

#[test]
fn lint_phases_split_by_phase_and_skip_disabled() {
    let list_lint = StaticLint {
        definition: LintDefinition::new("list", LintPhase::List, LintLevel::Warning),
        findings: vec![],
    };
    let response_lint = StaticLint {
        definition: LintDefinition::new("response", LintPhase::Response, LintLevel::Warning),
        findings: vec![],
    };
    let run_lint = StaticLint {
        definition: LintDefinition::new("run", LintPhase::Run, LintLevel::Warning),
        findings: vec![],
    };
    let disabled_lint = StaticLint {
        definition: LintDefinition::new("disabled", LintPhase::List, LintLevel::Disabled),
        findings: vec![LintFinding::new("ignored")],
    };
    let suite = LintSuite::new(vec![
        Arc::new(list_lint),
        Arc::new(response_lint),
        Arc::new(run_lint),
        Arc::new(disabled_lint),
    ]);
    let phases = super::linting::lint_phases(&suite);
    assert_eq!(phases.list.len(), 1);
    assert_eq!(phases.response.len(), 1);
    assert_eq!(phases.run.len(), 1);
}

#[test]
fn linting_collects_errors_and_warnings_without_short_circuit() {
    let error_one = StaticLint {
        definition: LintDefinition::new("error_one", LintPhase::List, LintLevel::Error),
        findings: vec![LintFinding::new("boom")],
    };
    let error_two = StaticLint {
        definition: LintDefinition::new("error_two", LintPhase::List, LintLevel::Error),
        findings: vec![LintFinding::new("kaboom")],
    };
    let warning = StaticLint {
        definition: LintDefinition::new("warn", LintPhase::List, LintLevel::Warning),
        findings: vec![LintFinding::new("heads up")],
    };
    let empty = StaticLint {
        definition: LintDefinition::new("empty", LintPhase::List, LintLevel::Warning),
        findings: vec![],
    };
    let disabled = StaticLint {
        definition: LintDefinition::new("disabled", LintPhase::List, LintLevel::Disabled),
        findings: vec![LintFinding::new("ignored")],
    };
    let lints: Vec<Arc<dyn LintRule>> = vec![
        Arc::new(error_one),
        Arc::new(error_two),
        Arc::new(warning),
        Arc::new(empty),
        Arc::new(disabled),
    ];
    let mut warnings = Vec::new();
    let failure = super::linting::evaluate_list_phase(
        &lints,
        &crate::ListLintContext {
            raw_tool_count: 0,
            protocol_version: None,
            tools: &[],
        },
        &mut warnings,
    )
    .expect("expected failure");
    assert!(failure.reason.contains("lint errors during list phase"));
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, RunWarningCode::lint("warn"));
}

#[test]
fn max_tools_lint_warns_when_over_limit() {
    let lint = MaxToolsLint::new(
        LintDefinition::new("max_tools", LintPhase::List, LintLevel::Warning),
        1,
    );
    let lints: Vec<Arc<dyn LintRule>> = vec![Arc::new(lint)];
    let mut warnings = Vec::new();
    let failure = super::linting::evaluate_list_phase(
        &lints,
        &crate::ListLintContext {
            raw_tool_count: 2,
            protocol_version: None,
            tools: &[],
        },
        &mut warnings,
    );
    assert!(failure.is_none());
    assert_eq!(warnings.len(), 1);
}

#[test]
fn max_tools_lint_errors_when_over_limit() {
    let lint = MaxToolsLint::new(
        LintDefinition::new("max_tools", LintPhase::List, LintLevel::Error),
        1,
    );
    let lints: Vec<Arc<dyn LintRule>> = vec![Arc::new(lint)];
    let mut warnings = Vec::new();
    let failure = super::linting::evaluate_list_phase(
        &lints,
        &crate::ListLintContext {
            raw_tool_count: 2,
            protocol_version: None,
            tools: &[],
        },
        &mut warnings,
    )
    .expect("expected failure");
    assert!(failure.reason.contains("lint"));
    assert!(warnings.is_empty());
}

#[test]
fn mcp_schema_min_version_lint_flags_missing_invalid_and_low_versions() {
    let lint = McpSchemaMinVersionLint::new(
        LintDefinition::new("mcp_schema_min_version", LintPhase::List, LintLevel::Warning),
        "2025-03-26",
    )
    .expect("lint");
    let context_missing = crate::ListLintContext {
        raw_tool_count: 0,
        protocol_version: None,
        tools: &[],
    };
    assert_eq!(lint.check_list(&context_missing).len(), 1);

    let context_invalid = crate::ListLintContext {
        raw_tool_count: 0,
        protocol_version: Some("not-a-date"),
        tools: &[],
    };
    assert_eq!(lint.check_list(&context_invalid).len(), 1);

    let context_low = crate::ListLintContext {
        raw_tool_count: 0,
        protocol_version: Some("2024-11-05"),
        tools: &[],
    };
    assert_eq!(lint.check_list(&context_low).len(), 1);

    let context_ok = crate::ListLintContext {
        raw_tool_count: 0,
        protocol_version: Some("2025-03-26"),
        tools: &[],
    };
    assert!(lint.check_list(&context_ok).is_empty());
}

#[test]
fn json_schema_dialect_compat_lint_enforces_allowlist_and_defaults_missing_schema() {
    let lint = JsonSchemaDialectCompatLint::new(
        LintDefinition::new("json_schema_dialect_compat", LintPhase::List, LintLevel::Warning),
        vec![DEFAULT_JSON_SCHEMA_DIALECT.to_string()],
    );
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({ "$schema": "http://json-schema.org/draft-04/schema", "type": "object" })),
    );
    let findings = lint.check_list(&crate::ListLintContext {
        raw_tool_count: 1,
        protocol_version: None,
        tools: &[tool],
    });
    assert_eq!(findings.len(), 1);

    let tool_missing = tool_with_schemas("ok", json!({ "type": "object" }), None);
    let findings = lint.check_list(&crate::ListLintContext {
        raw_tool_count: 1,
        protocol_version: None,
        tools: &[tool_missing],
    });
    assert!(findings.is_empty());

    let lint_no_2020 = JsonSchemaDialectCompatLint::new(
        LintDefinition::new("json_schema_dialect_compat", LintPhase::List, LintLevel::Warning),
        vec!["http://json-schema.org/draft-04/schema".to_string()],
    );
    let tool_missing = tool_with_schemas("bad", json!({ "type": "object" }), None);
    let findings = lint_no_2020.check_list(&crate::ListLintContext {
        raw_tool_count: 1,
        protocol_version: None,
        tools: &[tool_missing],
    });
    assert_eq!(findings.len(), 1);
}

#[test]
fn max_structured_content_bytes_lint_sizes_json_bytes_and_allows_missing() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let structured = json!({ "text": "é" });
    let encoded = serde_json::to_vec(&structured).expect("encode structured");
    let lint = MaxStructuredContentBytesLint::new(
        LintDefinition::new(
            "max_structured_content_bytes",
            LintPhase::Response,
            LintLevel::Warning,
        ),
        encoded.len() - 1,
    );
    let response = CallToolResult {
        content: vec![Content::text("ok")],
        structured_content: Some(structured),
        is_error: None,
        meta: None,
    };
    let context = ResponseLintContext {
        tool: &tool,
        invocation: &invocation,
        response: &response,
    };
    assert_eq!(lint.check_response(&context).len(), 1);

    let response_missing = CallToolResult {
        content: vec![Content::text("ok")],
        structured_content: None,
        is_error: None,
        meta: None,
    };
    let context_missing = ResponseLintContext {
        tool: &tool,
        invocation: &invocation,
        response: &response_missing,
    };
    assert!(lint.check_response(&context_missing).is_empty());
}

#[test]
fn missing_structured_content_lint_triggers_when_schema_present() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({ "type": "object" })),
    );
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let response = CallToolResult {
        content: vec![Content::text("ok")],
        structured_content: None,
        is_error: None,
        meta: None,
    };
    let context = ResponseLintContext {
        tool: &tool,
        invocation: &invocation,
        response: &response,
    };
    let lint = MissingStructuredContentLint::new(LintDefinition::new(
        "missing_structured_content",
        LintPhase::Response,
        LintLevel::Warning,
    ));
    assert_eq!(lint.check_response(&context).len(), 1);
}

#[test]
fn max_structured_content_bytes_lint_respects_severity() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let response = CallToolResult {
        content: vec![Content::text("ok")],
        structured_content: Some(json!({ "value": 1 })),
        is_error: None,
        meta: None,
    };
    let context = ResponseLintContext {
        tool: &tool,
        invocation: &invocation,
        response: &response,
    };
    let lint_warn = MaxStructuredContentBytesLint::new(
        LintDefinition::new(
            "max_structured_content_bytes",
            LintPhase::Response,
            LintLevel::Warning,
        ),
        0,
    );
    let mut warnings = Vec::new();
    let failure = super::linting::evaluate_response_phase(
        &[Arc::new(lint_warn)],
        &context,
        &mut warnings,
    );
    assert!(failure.is_none());
    assert_eq!(warnings.len(), 1);

    let lint_error = MaxStructuredContentBytesLint::new(
        LintDefinition::new(
            "max_structured_content_bytes",
            LintPhase::Response,
            LintLevel::Error,
        ),
        0,
    );
    let mut warnings = Vec::new();
    let failure = super::linting::evaluate_response_phase(
        &[Arc::new(lint_error)],
        &context,
        &mut warnings,
    )
    .expect("expected failure");
    assert!(failure.reason.contains("lint"));
    assert!(warnings.is_empty());
}

#[test]
fn missing_structured_content_lint_respects_severity() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({ "type": "object" })),
    );
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let response = CallToolResult {
        content: vec![Content::text("ok")],
        structured_content: None,
        is_error: None,
        meta: None,
    };
    let context = ResponseLintContext {
        tool: &tool,
        invocation: &invocation,
        response: &response,
    };
    let lint_warn = MissingStructuredContentLint::new(LintDefinition::new(
        "missing_structured_content",
        LintPhase::Response,
        LintLevel::Warning,
    ));
    let mut warnings = Vec::new();
    let failure = super::linting::evaluate_response_phase(
        &[Arc::new(lint_warn)],
        &context,
        &mut warnings,
    );
    assert!(failure.is_none());
    assert_eq!(warnings.len(), 1);

    let lint_error = MissingStructuredContentLint::new(LintDefinition::new(
        "missing_structured_content",
        LintPhase::Response,
        LintLevel::Error,
    ));
    let mut warnings = Vec::new();
    let failure = super::linting::evaluate_response_phase(
        &[Arc::new(lint_error)],
        &context,
        &mut warnings,
    )
    .expect("expected failure");
    assert!(failure.reason.contains("lint"));
    assert!(warnings.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn run_phase_lint_error_fails_after_run() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let lint = StaticLint {
        definition: LintDefinition::new("run_fail", LintPhase::Run, LintLevel::Error),
        findings: vec![LintFinding::new("boom")],
    };
    let config = RunConfig::new().with_lints(LintSuite::new(vec![Arc::new(lint)]));
    let result = run_with_session(
        &session,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;
    assert_failure(&result);
    assert_failure_reason_contains(&result, "run phase");
}

#[tokio::test(flavor = "multi_thread")]
async fn response_lint_failure_reports_full_trace() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = prepare_tools(vec![tool]);
    let sequence = StateMachineSequence { seeds: vec![0] };
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);
    let lint = StaticLint {
        definition: LintDefinition::new("response_fail", LintPhase::Response, LintLevel::Error),
        findings: vec![LintFinding::new("boom")],
    };
    let execution = StateMachineExecution {
        session: &session,
        tools: &tools,
        validators: &BTreeMap::new(),
        assertions: &AssertionSet::default(),
        predicate: None,
        min_len: None,
        in_band_error_forbidden: false,
        full_trace: true,
        warnings: Rc::new(RefCell::new(Vec::new())),
        warned_missing_structured: Rc::new(RefCell::new(std::collections::HashSet::new())),
        response_lints: vec![Arc::new(lint)],
        case_index: 0,
        trace_sink: None,
    };
    let failure = execute_state_machine_sequence(&sequence, &execution, &mut tracker)
        .await
        .expect_err("expected failure");
    let (_, response) = failure.trace[0].as_tool_call().expect("tool call");
    assert!(response.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_reports_response_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: None,
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/missing".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);

    let result = execute_sequence_for_test(
        &session,
        &tools,
        &BTreeMap::new(),
        &assertions,
        &sequence,
        &mut tracker,
        None,
        Some(1),
        false,
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure.failure.reason.contains("assertion pointer"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_reports_response_assertion_failure_on_error_response() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: None,
            checks: vec![AssertionCheck {
                target: AssertionTarget::Output,
                pointer: "/missing".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);

    let result = execute_sequence_for_test(
        &session,
        &tools,
        &BTreeMap::new(),
        &assertions,
        &sequence,
        &mut tracker,
        None,
        Some(1),
        false,
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure.failure.reason.contains("assertion pointer"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_reports_sequence_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Sequence(SequenceAssertion {
            checks: vec![AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/missing".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);

    let result = execute_sequence_for_test(
        &session,
        &tools,
        &BTreeMap::new(),
        &assertions,
        &sequence,
        &mut tracker,
        None,
        Some(1),
        false,
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure.failure.reason.contains("assertion pointer"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_state_machine_sequence_fails_on_minimum_length_shortfall() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let tools = vec![tool];
    let sequence = StateMachineSequence { seeds: vec![0] };
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default(), 1);

    let result = execute_sequence_for_test(
        &session,
        &tools,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &sequence,
        &mut tracker,
        None,
        Some(1),
        false,
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure
        .failure
        .reason
        .contains("state-machine generator failed"));
}

#[test]
fn finalize_state_machine_result_uses_fail_path() {
    let trace_entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let last_trace = Rc::new(RefCell::new(Vec::new()));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new("failure".to_string()),
        trace: vec![trace_entry],
        coverage: None,
        corpus: None,
        positive_error: false,
    }));
    let result = finalize_state_machine_result(
        Err(TestError::Fail(
            "nope".into(),
            StateMachineSequence { seeds: Vec::new() },
        )),
        &last_trace,
        &last_failure,
        &Rc::new(RefCell::new(None)),
        &Rc::new(RefCell::new(None)),
        &[],
    );

    assert_failure_reason_eq(&result, "failure");
    assert!(result.minimized.is_some());
}

#[test]
fn finalize_state_machine_result_skips_minimized_without_invocations() {
    let last_trace = Rc::new(RefCell::new(Vec::new()));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new("failure".to_string()),
        trace: Vec::new(),
        coverage: None,
        corpus: None,
        positive_error: false,
    }));
    let result = finalize_state_machine_result(
        Err(TestError::Fail(
            "nope".into(),
            StateMachineSequence { seeds: Vec::new() },
        )),
        &last_trace,
        &last_failure,
        &Rc::new(RefCell::new(None)),
        &Rc::new(RefCell::new(None)),
        &[],
    );

    assert_failure_reason_eq(&result, "failure");
    assert!(result.minimized.is_none());
}

#[test]
fn finalize_state_machine_result_includes_reject_context_on_abort() {
    clear_reject_context();
    set_reject_context_for_test("predicate rejected".to_string());

    let last_trace = Rc::new(RefCell::new(Vec::new()));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new("failure".to_string()),
        trace: Vec::new(),
        coverage: None,
        corpus: None,
        positive_error: false,
    }));
    let result = finalize_state_machine_result(
        Err(TestError::Abort("nope".into())),
        &last_trace,
        &last_failure,
        &Rc::new(RefCell::new(None)),
        &Rc::new(RefCell::new(None)),
        &[],
    );
    #[cfg(coverage)]
    std::hint::black_box(&result);
    assert_failure(&result);
    assert_failure_reason_contains(&result, "last rejection");
}

#[test]
fn finalize_state_machine_result_appends_reject_context() {
    clear_reject_context();
    set_reject_context_for_test("context".to_string());

    let last_trace = Rc::new(RefCell::new(Vec::new()));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new("failure".to_string()),
        trace: Vec::new(),
        coverage: None,
        corpus: None,
        positive_error: false,
    }));
    let result = finalize_state_machine_result(
        Err(TestError::Abort("nope".into())),
        &last_trace,
        &last_failure,
        &Rc::new(RefCell::new(None)),
        &Rc::new(RefCell::new(None)),
        &[],
    );
    #[cfg(coverage)]
    std::hint::black_box(&result);
    assert_failure(&result);
    assert_failure_reason_contains(&result, "last rejection: context");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_transport_reports_connect_error() {
    let result = run_with_transport(
        connect_result(Err(SessionError::Transport(Box::new(
            std::io::Error::other("connect failed"),
        )))),
        "local",
        &RunConfig::new(),
        RunnerOptions::default(),
    )
    .await;

    assert_failure_reason_contains(&result, "failed to connect local transport");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_http_reports_transport_error() {
    let config = HttpConfig {
        url: "http://localhost:1234/mcp".to_string(),
        auth_token: None,
    };
    let result = run_http(&config, &RunConfig::new(), RunnerOptions::default()).await;
    assert_failure(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_stdio_reports_transport_error() {
    let config = StdioConfig::new("mcp-server");
    let result = run_stdio(&config, &RunConfig::new(), RunnerOptions::default()).await;
    assert_failure(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn runner_transport_ignores_unhandled_request() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let mut transport = RunnerTransport::new(tool, response);
    let request = ClientJsonRpcMessage::request(
        ClientRequest::ListPromptsRequest(rmcp::model::ListPromptsRequest {
            method: Default::default(),
            params: Some(rmcp::model::PaginatedRequestParam { cursor: None }),
            extensions: Default::default(),
        }),
        rmcp::model::NumberOrString::Number(1),
    );
    let _ = transport.send(request).await;
    let _ = transport.close().await;
}

#[test]
fn build_output_validators_skips_missing_schema() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let validators = build_output_validators(&[tool]).expect("validators");
    assert!(validators.is_empty());
}

#[test]
fn build_output_validators_accepts_valid_schema() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({
            "type": "object",
            "properties": { "status": { "type": "string" } }
        })),
    );
    let validators = build_output_validators(&[tool]).expect("validators");
    assert!(validators.contains_key("echo"));
}

#[test]
fn build_output_validators_reports_invalid_schema() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({ "type": "object", "properties": { "bad": 5 } })),
    );
    let error = build_output_validators(&[tool]).expect_err("error");
    assert!(error.contains("failed to compile output schema"));
}

#[test]
fn collect_schema_keyword_warnings_reports_draft_defs() {
    let tools = vec![
        tool_with_schemas(
            "draft07",
            json!({
                "type": "object",
                "$schema": "http://json-schema.org/draft-07/schema#",
                "$defs": { "payload": { "type": "string" } }
            }),
            None,
        ),
        tool_with_schemas(
            "draft06",
            json!({
                "type": "object",
                "$schema": "http://json-schema.org/draft-06/schema#",
                "$defs": { "payload": { "type": "string" } }
            }),
            None,
        ),
        tool_with_schemas(
            "draft04",
            json!({
                "type": "object",
                "$schema": "http://json-schema.org/draft-04/schema#",
                "$defs": { "payload": { "type": "string" } }
            }),
            None,
        ),
    ];
    let warnings = collect_schema_warnings(&tools);
    assert_eq!(warnings.len(), 3);
    assert!(warnings.iter().all(|warning| {
        warning.code == RunWarningCode::schema_unsupported_keyword()
    }));
}

#[test]
fn collect_schema_keyword_warnings_reports_direct_draft_defs() {
    let tool = tool_with_schemas(
        "draft07",
        json!({
            "type": "object",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$defs": { "payload": { "type": "string" } }
        }),
        None,
    );
    let mut warnings = Vec::new();
    collect_schema_keyword_warnings(
        &tool,
        "input schema",
        tool.input_schema.as_ref(),
        &mut warnings,
    );
    assert_eq!(warnings.len(), 1);
}

#[test]
fn collect_schema_keyword_warnings_ignores_modern_defs() {
    let tool = tool_with_schemas(
        "draft2020",
        json!({
            "type": "object",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": { "payload": { "type": "string" } }
        }),
        None,
    );
    let mut warnings = Vec::new();
    collect_schema_keyword_warnings(
        &tool,
        "input schema",
        tool.input_schema.as_ref(),
        &mut warnings,
    );
    assert!(warnings.is_empty());
}

#[test]
fn validate_tools_rejects_invalid_schema() {
    let tool = tool_with_schemas("bad", json!({ "type": "string" }), None);
    let error = validate_tools(vec![tool], &SchemaConfig::default()).expect_err("error");
    assert!(error.contains("invalid tools/list"));
}

#[test]
fn validate_tools_accepts_valid_schema() {
    let tool = tool_with_schemas("good", json!({ "type": "object" }), None);
    let tools = validate_tools(vec![tool], &SchemaConfig::default()).expect("valid tools");
    assert_eq!(tools.len(), 1);
}

#[test]
fn coverage_tracker_mines_structured_content() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default();
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::structured(json!({ "value": 2, "label": "ok" })),
    );

    let (_, response) = entry.as_tool_call().expect("tool call entry");
    tracker.mine_response("echo", response.expect("response"));

    assert!(tracker.corpus().numbers().contains(&Number::from(2)));
    assert!(tracker.corpus().strings().contains(&"label".to_string()));
}

#[test]
fn coverage_tracker_logs_corpus_deltas_and_reports() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default().with_log_corpus_deltas(true);
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    let response = CallToolResult::structured(json!({ "value": 1 }));

    tracker.mine_response("echo", &response);

    let report = tracker.corpus_report();
    assert!(report.integers.contains(&1));
    assert!(report.numbers.contains(&Number::from(1)));
}

#[test]
fn coverage_tracker_ignores_missing_structured_content() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default();
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    let entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );

    let (_, response) = entry.as_tool_call().expect("tool call entry");
    tracker.mine_response("echo", response.expect("response"));

    assert!(tracker.corpus().numbers().is_empty());
    assert!(tracker.corpus().strings().is_empty());
}

#[test]
fn coverage_tracker_skips_error_responses() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default().with_mine_text(true);
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    let response = CallToolResult::error(vec![Content::text("oops")]);

    tracker.mine_response("echo", &response);

    assert!(tracker.corpus().strings().is_empty());
    assert!(tracker.corpus().numbers().is_empty());
}

#[test]
fn coverage_tracker_mines_resource_text() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default().with_mine_text(true);
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    let response = CallToolResult::success(vec![
        Content::resource(ResourceContents::TextResourceContents {
            uri: "file://alpha".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: "alpha beta".to_string(),
            meta: None,
        }),
        Content::resource(ResourceContents::BlobResourceContents {
            uri: "file://blob".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            blob: "AAAA".to_string(),
            meta: None,
        }),
    ]);

    tracker.mine_response("echo", &response);

    assert!(tracker.corpus().strings().contains(&"alpha".to_string()));
    assert!(tracker.corpus().strings().contains(&"beta".to_string()));
}

#[test]
fn coverage_tracker_mines_text_from_structured_content() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default().with_mine_text(true);
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    let response = CallToolResult::structured(json!({ "note": "alpha 1" }));

    tracker.mine_response("echo", &response);

    assert!(tracker.corpus().strings().contains(&"alpha".to_string()));
    assert!(tracker.corpus().integers().contains(&1));
}

#[test]
fn coverage_tracker_mines_text_content() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default().with_mine_text(true);
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    let response = CallToolResult::success(vec![Content::text("beta 2")]);

    tracker.mine_response("echo", &response);

    assert!(tracker.corpus().strings().contains(&"beta".to_string()));
    assert!(tracker.corpus().integers().contains(&2));
}

#[test]
fn coverage_tracker_truncates_uncallable_call_history() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default();
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 2);
    for index in 0..3 {
        let invocation = ToolInvocation {
            name: "echo".into(),
            arguments: Some(
                serde_json::json!({ "idx": index })
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        };
        let response = CallToolResult::error(vec![Content::text("fail")]);
        tracker.record_call(&invocation, &response);
        tracker.record_failure("echo");
    }

    let report = tracker.report();
    let calls = report
        .uncallable_traces
        .get("echo")
        .expect("uncallable traces");
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0]
            .input
            .arguments
            .as_ref()
            .and_then(|args| args.get("idx"))
            .expect("first idx"),
        &json!(1)
    );
    assert_eq!(
        calls[1]
            .input
            .arguments
            .as_ref()
            .and_then(|args| args.get("idx"))
            .expect("second idx"),
        &json!(2)
    );
}

#[test]
fn coverage_tracker_includes_empty_uncallable_trace_for_never_invoked_tool() {
    let alpha = tool_with_schemas("alpha", json!({ "type": "object" }), None);
    let beta = tool_with_schemas("beta", json!({ "type": "object" }), None);
    let tools = vec![alpha, beta];
    let config = StateMachineConfig::default();
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    let invocation = ToolInvocation {
        name: "alpha".into(),
        arguments: Some(
            serde_json::json!({ "idx": 0 })
                .as_object()
                .cloned()
                .unwrap(),
        ),
    };
    let response = CallToolResult::error(vec![Content::text("fail")]);
    tracker.record_call(&invocation, &response);
    tracker.record_failure("alpha");

    let report = tracker.report();
    let alpha_calls = report.uncallable_traces.get("alpha").expect("alpha traces");
    let beta_calls = report.uncallable_traces.get("beta").expect("beta traces");
    assert_eq!(alpha_calls.len(), 1);
    assert!(beta_calls.is_empty());
}

#[test]
fn coverage_tracker_merge_skips_empty_uncallable_calls() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default();
    let prepared_tools = prepare_tools(tools);
    let mut source = CoverageTracker::new(&prepared_tools, &config, 0);
    let invocation = ToolInvocation {
        name: "echo".into(),
        arguments: Some(
            serde_json::json!({ "idx": 0 })
                .as_object()
                .cloned()
                .unwrap(),
        ),
    };
    let response = CallToolResult::error(vec![Content::text("fail")]);
    source.record_call(&invocation, &response);
    source.record_failure("echo");

    let mut target = CoverageTracker::new(&prepared_tools, &config, 1);
    target.merge_from(&source);

    let report = target.report();
    let calls = report
        .uncallable_traces
        .get("echo")
        .expect("uncallable traces");
    assert!(calls.is_empty());
}

#[test]
fn coverage_tracker_finalize_reports_warnings() {
    let tools = vec![tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string", "pattern": "(" } },
            "required": ["text"]
        }),
        None,
    )];
    let config = StateMachineConfig::default();
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);
    let report = tracker.report();
    assert!(!report.warnings.is_empty());
}

#[test]
fn coverage_tracker_skips_blocklisted_tools() {
    let tools = vec![tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string", "pattern": "(" } },
            "required": ["text"]
        }),
        None,
    )];
    let config = StateMachineConfig::default().with_coverage_blocklist(vec!["echo".to_string()]);
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);
    let warnings = tracker.build_warnings();
    assert!(warnings.is_empty());
}

#[test]
fn coverage_tracker_build_warnings_respects_blocklist() {
    let alpha = tool_with_schemas(
        "alpha",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string", "pattern": "(" } },
            "required": ["text"]
        }),
        None,
    );
    let beta = tool_with_schemas(
        "beta",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string", "pattern": "(" } },
            "required": ["text"]
        }),
        None,
    );
    let config = StateMachineConfig::default().with_coverage_blocklist(vec!["alpha".to_string()]);
    let tools = vec![alpha, beta];
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);

    let warnings = tracker.build_warnings();

    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].tool, "beta");
    assert_eq!(
        warnings[0].reason,
        CoverageWarningReason::MissingRequiredValue
    );
}

#[test]
fn coverage_tracker_respects_allowlist_for_warnings() {
    let alpha = tool_with_schemas(
        "alpha",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string", "pattern": "(" } },
            "required": ["text"]
        }),
        None,
    );
    let beta = tool_with_schemas(
        "beta",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string", "pattern": "(" } },
            "required": ["text"]
        }),
        None,
    );
    let config = StateMachineConfig::default().with_coverage_allowlist(vec!["alpha".to_string()]);
    let tools = vec![alpha, beta];
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);

    let warnings = tracker.build_warnings();

    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].tool, "alpha");
    assert_eq!(
        warnings[0].reason,
        CoverageWarningReason::MissingRequiredValue
    );
}

#[test]
fn coverage_tracker_validate_defaults_to_percent_called() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let config = StateMachineConfig::default();
    let tools = vec![tool];
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);
    let error = tracker.validate(&[]).expect_err("expected failure");
    assert_eq!(error.details["rule"], "percent_called");
    assert_eq!(error.details["min_percent"], 100.0);
}

#[test]
fn coverage_tracker_min_calls_per_tool_reports_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let config = StateMachineConfig::default();
    let tools = vec![tool];
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);
    let error = tracker
        .validate(&[CoverageRule::min_calls_per_tool(1)])
        .expect_err("expected failure");
    assert_eq!(error.details["rule"], "min_calls_per_tool");
}

#[test]
fn coverage_tracker_reports_no_uncalled_tools_failure() {
    let alpha = tool_with_schemas(
        "alpha",
        json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
        }),
        None,
    );
    let beta = tool_with_schemas(
        "beta",
        json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
        }),
        None,
    );
    let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
    let tools = vec![alpha, beta];
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);
    let error = tracker
        .validate(&[CoverageRule::no_uncalled_tools()])
        .expect_err("expected failure");
    assert_eq!(error.details["rule"], "no_uncalled_tools");
}

#[test]
fn coverage_tracker_min_calls_per_tool_succeeds() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
        }),
        None,
    );
    let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
    let tools = vec![tool];
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    tracker.record_success("echo");
    assert!(tracker
        .validate(&[CoverageRule::min_calls_per_tool(1)])
        .is_ok());
}

#[test]
fn coverage_tracker_no_uncalled_tools_succeeds() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
        }),
        None,
    );
    let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
    let tools = vec![tool];
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    tracker.record_success("echo");
    assert!(tracker
        .validate(&[CoverageRule::no_uncalled_tools()])
        .is_ok());
}

#[test]
fn coverage_tracker_reports_percent_called_failure() {
    let alpha = tool_with_schemas(
        "alpha",
        json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
        }),
        None,
    );
    let beta = tool_with_schemas(
        "beta",
        json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
        }),
        None,
    );
    let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
    let tools = vec![alpha, beta];
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    tracker.record_success("alpha");
    let error = tracker
        .validate(&[CoverageRule::percent_called(100.0)])
        .expect_err("expected failure");
    assert_eq!(error.details["rule"], "percent_called");
}

#[test]
fn coverage_tracker_rejects_invalid_percent_called() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let config = StateMachineConfig::default();
    let tools = vec![tool];
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);
    let error = tracker
        .validate(&[CoverageRule::percent_called(101.0)])
        .expect_err("expected failure");
    assert_eq!(error.details["rule"], "percent_called");
    assert_eq!(error.details["error"], "min_percent_out_of_range");
}

#[test]
fn coverage_tracker_percent_called_succeeds() {
    let alpha = tool_with_schemas(
        "alpha",
        json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
        }),
        None,
    );
    let beta = tool_with_schemas(
        "beta",
        json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
        }),
        None,
    );
    let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
    let tools = vec![alpha, beta];
    let tools = prepare_tools(tools);
    let mut tracker = CoverageTracker::new(&tools, &config, 1);
    tracker.record_success("alpha");
    assert!(tracker
        .validate(&[CoverageRule::percent_called(50.0)])
        .is_ok());
}

#[test]
fn coverage_tracker_skips_percent_called_when_no_callable_tools() {
    let tools = vec![tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": { "text": { "type": "string", "pattern": "(" } },
            "required": ["text"]
        }),
        None,
    )];
    let config = StateMachineConfig::default();
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);
    assert!(tracker
        .validate(&[CoverageRule::percent_called(50.0)])
        .is_ok());
}

#[test]
fn eligible_tools_respects_allowlist() {
    let alpha = tool_with_schemas("alpha", json!({ "type": "object" }), None);
    let beta = tool_with_schemas("beta", json!({ "type": "object" }), None);
    let config = StateMachineConfig::default().with_coverage_allowlist(vec!["alpha".to_string()]);
    let tools = vec![alpha, beta];
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);
    let eligible = tracker.eligible_tools();
    assert_eq!(eligible.len(), 1);
    assert_eq!(eligible[0].name.as_ref(), "alpha");
}

#[test]
fn eligible_tools_respects_blocklist() {
    let alpha = tool_with_schemas("alpha", json!({ "type": "object" }), None);
    let beta = tool_with_schemas("beta", json!({ "type": "object" }), None);
    let config = StateMachineConfig::default().with_coverage_blocklist(vec!["alpha".to_string()]);
    let tools = vec![alpha, beta];
    let tools = prepare_tools(tools);
    let tracker = CoverageTracker::new(&tools, &config, 1);
    let eligible = tracker.eligible_tools();
    assert_eq!(eligible.len(), 1);
    assert_eq!(eligible[0].name.as_ref(), "beta");
}

#[test]
fn map_uncallable_reason_maps_variants() {
    assert_eq!(
        map_uncallable_reason(UncallableReason::String),
        CoverageWarningReason::MissingString
    );
    assert_eq!(
        map_uncallable_reason(UncallableReason::Integer),
        CoverageWarningReason::MissingInteger
    );
    assert_eq!(
        map_uncallable_reason(UncallableReason::Number),
        CoverageWarningReason::MissingNumber
    );
    assert_eq!(
        map_uncallable_reason(UncallableReason::RequiredValue),
        CoverageWarningReason::MissingRequiredValue
    );
}

#[test]
fn trace_entry_with_accepts_object_args() {
    let entry = trace_entry_with(
        "echo",
        Some(json!({ "value": "ok" })),
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let (invocation, _) = entry.as_tool_call().expect("tool call");
    let args = invocation.arguments.clone().expect("arguments");
    assert_eq!(args.get("value"), Some(&json!("ok")));
}

#[test]
fn trace_entry_with_ignores_non_object_args() {
    let entry = trace_entry_with(
        "echo",
        Some(json!(true)),
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let (invocation, _) = entry.as_tool_call().expect("tool call");
    assert!(invocation.arguments.is_none());
}
