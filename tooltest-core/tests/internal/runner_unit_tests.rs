use super::assertions::{
    apply_default_assertions, apply_response_assertions, apply_sequence_assertions,
    attach_failure_reason, attach_response, evaluate_checks, AssertionPayloads,
};
use super::coverage::{map_uncallable_reason, CoverageTracker};
use super::result::{finalize_run_result, finalize_state_machine_result, FailureContext};
use super::schema::{
    build_output_validators, collect_schema_keyword_warnings, collect_schema_warnings,
    validate_tools,
};
use super::sequence::{execute_sequence, execute_sequence_with_coverage};
use super::state_machine::execute_state_machine_sequence;
use super::transport::{run_with_transport, ConnectFuture};
use super::{run_http, run_stdio, run_with_session};
use crate::generator::{
    clear_reject_context, set_reject_context_for_test, StateMachineSequence, UncallableReason,
};
use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CorpusReport, CoverageReport,
    CoverageRule, CoverageWarningReason, ErrorCode, ErrorData, HttpConfig, JsonObject,
    ResponseAssertion, RunConfig, RunFailure, RunOutcome, RunResult, RunWarningCode, RunnerOptions,
    SchemaConfig, SequenceAssertion, SessionDriver, SessionError, StateMachineConfig, StdioConfig,
    ToolInvocation, ToolPredicate, TraceEntry,
};
use jsonschema::draft202012;
use proptest::test_runner::TestError;
use rmcp::model::{CallToolResult, ClientJsonRpcMessage, ClientRequest, Content, ResourceContents};
use rmcp::transport::Transport;
use serde_json::{json, Number, Value as JsonValue};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use tooltest_test_support::{tool_with_schemas, RunnerTransport};

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

async fn connect_runner_transport(
    transport: RunnerTransport,
) -> Result<SessionDriver, SessionError> {
    SessionDriver::connect_with_transport::<
        RunnerTransport,
        std::convert::Infallible,
        rmcp::transport::TransportAdapterIdentity,
    >(transport)
    .await
}

fn connect_result(result: Result<SessionDriver, SessionError>) -> ConnectFuture<'static> {
    Box::pin(async move { result })
}

fn is_list_tools(entry: &TraceEntry) -> bool {
    matches!(entry, TraceEntry::ListTools { .. })
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
fn finalize_run_result_uses_abort_path() {
    let trace_entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let last_trace = Rc::new(RefCell::new(vec![trace_entry]));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new(String::new()),
        trace: Vec::new(),
        coverage: None,
        corpus: None,
    }));
    let result = finalize_run_result(
        Err(TestError::Abort("nope".into())),
        &last_trace,
        &last_failure,
        &Rc::new(RefCell::new(None)),
        &Rc::new(RefCell::new(None)),
        &[],
    );

    #[cfg(coverage)]
    std::hint::black_box(&result);
    #[cfg(not(coverage))]
    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    assert_eq!(result.trace.len(), 1);
    assert!(result.minimized.is_none());
}

#[test]
fn finalize_run_result_success_includes_coverage_and_corpus() {
    let last_trace = Rc::new(RefCell::new(Vec::new()));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new(String::new()),
        trace: Vec::new(),
        coverage: None,
        corpus: None,
    }));
    let mut counts = BTreeMap::new();
    counts.insert("echo".to_string(), 1u64);
    let coverage = CoverageReport {
        counts,
        warnings: Vec::new(),
    };
    let corpus = CorpusReport {
        numbers: vec![Number::from(1)],
        integers: vec![1],
        strings: vec!["alpha".to_string()],
    };
    let result = finalize_run_result(
        Ok(()),
        &last_trace,
        &last_failure,
        &Rc::new(RefCell::new(Some(coverage.clone()))),
        &Rc::new(RefCell::new(Some(corpus.clone()))),
        &[],
    );

    assert!(outcome_is_success(&result.outcome));
    assert!(result.trace.is_empty());
    let coverage_report = result.coverage.expect("coverage");
    assert_eq!(coverage_report.counts.get("echo").copied(), Some(1));
    assert!(coverage_report.warnings.is_empty());

    let corpus_report = result.corpus.expect("corpus");
    assert_eq!(corpus_report.numbers, corpus.numbers);
    assert_eq!(corpus_report.integers, corpus.integers);
    assert_eq!(corpus_report.strings, corpus.strings);
}

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
    let result = apply_default_assertions(invocation, response.expect("response"), &validators);
    assert!(result.is_some());
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
    let result = apply_default_assertions(invocation, response.expect("response"), &validators);
    assert!(result.is_some());
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
    let result = apply_default_assertions(invocation, response.expect("response"), &validators);
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
    let result = apply_default_assertions(invocation, response.expect("response"), &validators);
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
    let result = apply_default_assertions(invocation, response.expect("response"), &validators);
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
async fn execute_sequence_reports_session_error() {
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
    let transport = RunnerTransport::new(tool, response).with_call_tool_error(ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        "call failed",
        None,
    ));
    let session = connect_runner_transport(transport).await.expect("connect");
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let result = execute_sequence(
        &session,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &[invocation],
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure.failure.reason.contains("session error"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_reports_default_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let result = execute_sequence(
        &session,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &[invocation],
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure
        .failure
        .reason
        .contains("returned an error response"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_reports_response_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
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
    let result = execute_sequence(&session, &BTreeMap::new(), &assertions, &[invocation]).await;
    let failure = result.expect_err("expected failure");
    assert!(failure.failure.reason.contains("assertion pointer"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_reports_sequence_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let assertions = AssertionSet {
        rules: vec![AssertionRule::Sequence(SequenceAssertion {
            checks: vec![AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/missing".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let result = execute_sequence(&session, &BTreeMap::new(), &assertions, &[invocation]).await;
    let failure = result.expect_err("expected failure");
    assert!(failure.failure.reason.contains("assertion pointer"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_succeeds_with_valid_response() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({
            "type": "object",
            "properties": { "status": { "type": "string", "const": "ok" } },
            "required": ["status"]
        })),
    );
    let response = CallToolResult::structured(json!({ "status": "ok" }));
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let validators = build_output_validators(&[tool]).expect("validators");
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: Some(JsonObject::new()),
    };

    let result = execute_sequence(
        &session,
        &validators,
        &AssertionSet::default(),
        &[invocation],
    )
    .await;

    let trace = result.expect("expected success");
    assert_eq!(trace.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_succeeds_with_empty_sequence() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let session = connect_runner_transport(transport).await.expect("connect");

    let result = execute_sequence(&session, &BTreeMap::new(), &AssertionSet::default(), &[]).await;

    let trace = result.expect("expected success");
    assert!(trace.is_empty());
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
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &RunConfig::new(), options).await;
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
    let config = RunConfig::new();
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = run_with_session(&session, &config, options).await;
    assert_failure_reason_contains(&result, "returned an error response");
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
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default());

    let result = execute_state_machine_sequence(
        &session,
        &tools,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &sequence,
        &mut tracker,
        None,
        None,
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
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default());

    let result = execute_state_machine_sequence(
        &session,
        &tools,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &sequence,
        &mut tracker,
        None,
        None,
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
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default());

    let result = execute_state_machine_sequence(
        &session,
        &tools,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &sequence,
        &mut tracker,
        None,
        Some(1),
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure.failure.reason.contains("session error"));
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
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default());

    let result = execute_state_machine_sequence(
        &session,
        &tools,
        &BTreeMap::new(),
        &assertions,
        &sequence,
        &mut tracker,
        None,
        Some(1),
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
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default());

    let result = execute_state_machine_sequence(
        &session,
        &tools,
        &BTreeMap::new(),
        &assertions,
        &sequence,
        &mut tracker,
        None,
        Some(1),
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
    let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default());

    let result = execute_state_machine_sequence(
        &session,
        &tools,
        &BTreeMap::new(),
        &AssertionSet::default(),
        &sequence,
        &mut tracker,
        None,
        Some(1),
    )
    .await;
    let failure = result.expect_err("expected failure");
    assert!(failure
        .failure
        .reason
        .contains("state-machine generator failed"));
}

#[test]
fn finalize_run_result_uses_fail_path() {
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: None,
    };
    let trace_entry = trace_entry_with(
        "echo",
        None,
        CallToolResult::success(vec![Content::text("ok")]),
    );
    let last_trace = Rc::new(RefCell::new(vec![trace_entry]));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new("failure".to_string()),
        trace: Vec::new(),
        coverage: None,
        corpus: None,
    }));
    let result = finalize_run_result(
        Err(TestError::Fail("nope".into(), vec![invocation])),
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
fn finalize_run_result_includes_reject_context_on_abort() {
    clear_reject_context();
    set_reject_context_for_test("predicate rejected".to_string());

    let last_trace = Rc::new(RefCell::new(Vec::new()));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new("failure".to_string()),
        trace: Vec::new(),
        coverage: None,
        corpus: None,
    }));
    let result = finalize_run_result(
        Err(TestError::Abort("nope".into())),
        &last_trace,
        &last_failure,
        &Rc::new(RefCell::new(None)),
        &Rc::new(RefCell::new(None)),
        &[],
    );
    assert_failure_reason_contains(&result, "last rejection");
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
    assert!(warnings
        .iter()
        .all(|warning| warning.code == RunWarningCode::SchemaUnsupportedKeyword));
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
    let mut tracker = CoverageTracker::new(&tools, &config);
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
    let mut tracker = CoverageTracker::new(&tools, &config);
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
    let mut tracker = CoverageTracker::new(&tools, &config);
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
    let mut tracker = CoverageTracker::new(&tools, &config);
    let response = CallToolResult::error(vec![Content::text("oops")]);

    tracker.mine_response("echo", &response);

    assert!(tracker.corpus().strings().is_empty());
    assert!(tracker.corpus().numbers().is_empty());
}

#[test]
fn coverage_tracker_mines_resource_text() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default().with_mine_text(true);
    let mut tracker = CoverageTracker::new(&tools, &config);
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
    let mut tracker = CoverageTracker::new(&tools, &config);
    let response = CallToolResult::structured(json!({ "note": "alpha 1" }));

    tracker.mine_response("echo", &response);

    assert!(tracker.corpus().strings().contains(&"alpha".to_string()));
    assert!(tracker.corpus().integers().contains(&1));
}

#[test]
fn coverage_tracker_mines_text_content() {
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let config = StateMachineConfig::default().with_mine_text(true);
    let mut tracker = CoverageTracker::new(&tools, &config);
    let response = CallToolResult::success(vec![Content::text("beta 2")]);

    tracker.mine_response("echo", &response);

    assert!(tracker.corpus().strings().contains(&"beta".to_string()));
    assert!(tracker.corpus().integers().contains(&2));
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
    let tracker = CoverageTracker::new(&tools, &config);
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
    let tracker = CoverageTracker::new(&tools, &config);
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
    let tracker = CoverageTracker::new(&tools, &config);

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
    let tracker = CoverageTracker::new(&tools, &config);

    let warnings = tracker.build_warnings();

    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].tool, "alpha");
    assert_eq!(
        warnings[0].reason,
        CoverageWarningReason::MissingRequiredValue
    );
}

#[test]
fn coverage_tracker_validate_returns_ok_when_rules_empty() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let config = StateMachineConfig::default();
    let tools = vec![tool];
    let tracker = CoverageTracker::new(&tools, &config);
    assert!(tracker.validate(&[]).is_ok());
}

#[test]
fn coverage_tracker_min_calls_per_tool_reports_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let config = StateMachineConfig::default();
    let tools = vec![tool];
    let tracker = CoverageTracker::new(&tools, &config);
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
    let tracker = CoverageTracker::new(&tools, &config);
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
    let mut tracker = CoverageTracker::new(&tools, &config);
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
    let mut tracker = CoverageTracker::new(&tools, &config);
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
    let mut tracker = CoverageTracker::new(&tools, &config);
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
    let tracker = CoverageTracker::new(&tools, &config);
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
    let mut tracker = CoverageTracker::new(&tools, &config);
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
    let tracker = CoverageTracker::new(&tools, &config);
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
    let tracker = CoverageTracker::new(&tools, &config);
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
    let tracker = CoverageTracker::new(&tools, &config);
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

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_with_coverage_reports_session_error() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response).with_call_tool_error(ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        "call failed",
        None,
    ));
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = StateMachineConfig::default();
    let mut tracker = CoverageTracker::new(&tools, &config);

    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: Some(JsonObject::new()),
    };
    let result = execute_sequence_with_coverage(
        &session,
        &BTreeMap::new(),
        &AssertionSet { rules: Vec::new() },
        &[invocation],
        &mut tracker,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_with_coverage_reports_response_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = StateMachineConfig::default();
    let mut tracker = CoverageTracker::new(&tools, &config);

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
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: Some(JsonObject::new()),
    };
    let result = execute_sequence_with_coverage(
        &session,
        &BTreeMap::new(),
        &assertions,
        &[invocation],
        &mut tracker,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_with_coverage_reports_sequence_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = StateMachineConfig::default();
    let mut tracker = CoverageTracker::new(&tools, &config);

    let assertions = AssertionSet {
        rules: vec![AssertionRule::Sequence(SequenceAssertion {
            checks: vec![AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/missing".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: Some(JsonObject::new()),
    };
    let result = execute_sequence_with_coverage(
        &session,
        &BTreeMap::new(),
        &assertions,
        &[invocation],
        &mut tracker,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_with_coverage_reports_default_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool, response);
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = StateMachineConfig::default();
    let mut tracker = CoverageTracker::new(&tools, &config);
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: Some(JsonObject::new()),
    };

    let result = execute_sequence_with_coverage(
        &session,
        &BTreeMap::new(),
        &AssertionSet { rules: Vec::new() },
        &[invocation],
        &mut tracker,
    )
    .await;

    let failure = result.expect_err("expected failure");
    assert!(failure
        .failure
        .reason
        .contains("returned an error response"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_with_coverage_reports_error_response() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult {
        content: vec![Content::text("boom")],
        structured_content: None,
        is_error: Some(true),
        meta: None,
    };
    let transport = RunnerTransport::new(tool, response);
    let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
    let session = connect_runner_transport(transport).await.expect("connect");
    let config = StateMachineConfig::default();
    let mut tracker = CoverageTracker::new(&tools, &config);
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: Some(JsonObject::new()),
    };

    let result = execute_sequence_with_coverage(
        &session,
        &BTreeMap::new(),
        &AssertionSet { rules: Vec::new() },
        &[invocation],
        &mut tracker,
    )
    .await;

    let failure = result.expect_err("expected failure");
    assert!(failure
        .failure
        .reason
        .contains("returned an error response"));
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_sequence_with_coverage_succeeds_and_tracks() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({
            "type": "object",
            "properties": { "status": { "type": "string", "const": "ok" } },
            "required": ["status"]
        })),
    );
    let response = CallToolResult::structured(json!({ "status": "ok" }));
    let transport = RunnerTransport::new(tool.clone(), response);
    let session = connect_runner_transport(transport).await.expect("connect");
    let validators = build_output_validators(&[tool.clone()]).expect("validators");
    let config = StateMachineConfig::default();
    let tools = vec![tool];
    let mut tracker = CoverageTracker::new(&tools, &config);
    let invocation = ToolInvocation {
        name: "echo".to_string().into(),
        arguments: Some(JsonObject::new()),
    };

    let result = execute_sequence_with_coverage(
        &session,
        &validators,
        &AssertionSet { rules: Vec::new() },
        &[invocation],
        &mut tracker,
    )
    .await;

    let trace = result.expect("expected success");
    assert_eq!(trace.len(), 1);
    assert_eq!(tracker.counts().get("echo").copied(), Some(1));
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
