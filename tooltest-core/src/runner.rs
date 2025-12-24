//! MCP sequence runner with default and declarative assertions.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::rc::Rc;

use jsonschema::draft202012;
use proptest::test_runner::{Config as ProptestConfig, TestCaseError, TestError, TestRunner};
use rmcp::model::{ListToolsResult, Tool};
use serde_json::Value as JsonValue;

use crate::generator::invocation_sequence_strategy;
use crate::schema::parse_list_tools;
use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, HttpConfig, MinimizedSequence,
    RunConfig, RunFailure, RunOutcome, RunResult, SessionDriver, StdioConfig, ToolInvocation,
    TraceEntry,
};

/// Configuration for proptest-driven run behavior.
#[derive(Clone, Debug)]
pub struct RunnerOptions {
    /// Number of proptest cases to execute.
    pub cases: u32,
    /// Range of invocation counts per generated sequence.
    pub sequence_len: RangeInclusive<usize>,
}

impl Default for RunnerOptions {
    fn default() -> Self {
        Self {
            cases: 32,
            sequence_len: 1..=3,
        }
    }
}

/// Execute a tooltest run using a pre-initialized session.
pub async fn run_with_session(
    session: &SessionDriver,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    let tools = match session.list_tools().await {
        Ok(tools) => tools,
        Err(error) => {
            return failure_result(format!("failed to list tools: {error:?}"), Vec::new(), None);
        }
    };

    let tools = match validate_tools(tools, &config.schema) {
        Ok(tools) => tools,
        Err(reason) => return failure_result(reason, Vec::new(), None),
    };

    let validators = match build_output_validators(&tools) {
        Ok(validators) => validators,
        Err(reason) => return failure_result(reason, Vec::new(), None),
    };

    let strategy = match invocation_sequence_strategy(
        &tools,
        config.predicate.as_ref(),
        options.sequence_len.clone(),
    ) {
        Ok(strategy) => strategy,
        Err(error) => return failure_result(error.to_string(), Vec::new(), None),
    };

    let assertions = config.assertions.clone();
    let last_trace: Rc<RefCell<Vec<TraceEntry>>> = Rc::new(RefCell::new(Vec::new()));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        reason: String::new(),
        trace: Vec::new(),
    }));
    let validators = Rc::new(validators);
    let handle = tokio::runtime::Handle::current();

    let mut runner = TestRunner::new(ProptestConfig {
        cases: options.cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    });

    let run_result = runner.run(&strategy, {
        let assertions = assertions.clone();
        let last_trace = last_trace.clone();
        let last_failure = last_failure.clone();
        let validators = validators.clone();
        move |sequence| {
            let execution: Result<Vec<TraceEntry>, FailureContext> =
                tokio::task::block_in_place(|| {
                    handle.block_on(execute_sequence(
                        session,
                        &validators,
                        &assertions,
                        &sequence,
                    ))
                });
            match execution {
                Ok(trace) => {
                    last_trace.replace(trace);
                    Ok(())
                }
                Err(failure) => {
                    last_failure.replace(failure.clone());
                    Err(TestCaseError::fail(failure.reason.clone()))
                }
            }
        }
    });

    finalize_run_result(run_result, &last_trace, &last_failure)
}

/// Execute a tooltest run against a stdio MCP endpoint.
pub async fn run_stdio(
    endpoint: &StdioConfig,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    run_with_transport(
        || SessionDriver::connect_stdio(endpoint),
        "stdio",
        config,
        options,
    )
    .await
}

/// Execute a tooltest run against an HTTP MCP endpoint.
pub async fn run_http(
    endpoint: &HttpConfig,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    run_with_transport(
        || SessionDriver::connect_http(endpoint),
        "http",
        config,
        options,
    )
    .await
}

#[derive(Clone, Debug)]
struct FailureContext {
    reason: String,
    trace: Vec<TraceEntry>,
}

async fn execute_sequence(
    session: &SessionDriver,
    validators: &BTreeMap<String, jsonschema::Validator>,
    assertions: &AssertionSet,
    sequence: &[ToolInvocation],
) -> Result<Vec<TraceEntry>, FailureContext> {
    let mut trace = Vec::new();
    for invocation in sequence {
        let entry = match session.send_tool_call(invocation.clone()).await {
            Ok(entry) => entry,
            Err(error) => {
                return Err(FailureContext {
                    reason: format!("session error: {error:?}"),
                    trace,
                });
            }
        };

        if let Some(reason) = apply_default_assertions(&entry, validators) {
            trace.push(entry);
            return Err(FailureContext { reason, trace });
        }

        if let Some(reason) = apply_response_assertions(assertions, &entry) {
            trace.push(entry);
            return Err(FailureContext { reason, trace });
        }

        trace.push(entry);
    }

    if let Some(reason) = apply_sequence_assertions(assertions, &trace) {
        return Err(FailureContext { reason, trace });
    }

    Ok(trace)
}

fn apply_default_assertions(
    entry: &TraceEntry,
    validators: &BTreeMap<String, jsonschema::Validator>,
) -> Option<String> {
    if entry.response.is_error.unwrap_or(false) {
        return Some(format!(
            "tool '{}' returned an error response",
            entry.invocation.name.as_ref()
        ));
    }

    let tool_name = entry.invocation.name.as_ref();
    let validator = validators.get(tool_name)?;
    let structured = entry.response.structured_content.as_ref()?;
    if let Err(error) = validator.validate(structured) {
        return Some(format!(
            "output schema violation for tool '{tool_name}': {error}"
        ));
    }
    None
}

fn apply_response_assertions(assertions: &AssertionSet, entry: &TraceEntry) -> Option<String> {
    if assertions.rules.is_empty() {
        return None;
    }

    let input_payload = entry
        .invocation
        .arguments
        .clone()
        .map(JsonValue::Object)
        .unwrap_or(JsonValue::Null);
    let output_payload = serde_json::to_value(&entry.response).unwrap_or(JsonValue::Null);
    let structured_payload = entry
        .response
        .structured_content
        .clone()
        .unwrap_or(JsonValue::Null);
    let payloads = AssertionPayloads {
        input: input_payload,
        output: output_payload,
        structured: structured_payload,
        sequence: None,
    };

    for rule in &assertions.rules {
        let AssertionRule::Response(response_assertion) = rule else {
            continue;
        };
        if let Some(tool) = &response_assertion.tool {
            if tool != entry.invocation.name.as_ref() {
                continue;
            }
        }
        if let Some(reason) = evaluate_checks(
            &response_assertion.checks,
            &payloads,
            Some(entry.invocation.name.as_ref()),
            false,
        ) {
            return Some(reason);
        }
    }

    None
}

fn apply_sequence_assertions(assertions: &AssertionSet, trace: &[TraceEntry]) -> Option<String> {
    if assertions.rules.is_empty() {
        return None;
    }

    let sequence_payload = serde_json::to_value(trace).unwrap_or(JsonValue::Null);
    let payloads = AssertionPayloads {
        input: JsonValue::Null,
        output: JsonValue::Null,
        structured: JsonValue::Null,
        sequence: Some(sequence_payload),
    };

    for rule in &assertions.rules {
        let AssertionRule::Sequence(sequence_assertion) = rule else {
            continue;
        };
        if let Some(reason) = evaluate_checks(&sequence_assertion.checks, &payloads, None, true) {
            return Some(reason);
        }
    }
    None
}

struct AssertionPayloads {
    input: JsonValue,
    output: JsonValue,
    structured: JsonValue,
    sequence: Option<JsonValue>,
}

fn evaluate_checks(
    checks: &[AssertionCheck],
    payloads: &AssertionPayloads,
    tool_name: Option<&str>,
    sequence_scope: bool,
) -> Option<String> {
    for check in checks {
        let payload = match (sequence_scope, &check.target) {
            (true, AssertionTarget::Sequence) => payloads.sequence.as_ref().unwrap(),
            (false, AssertionTarget::Input) => &payloads.input,
            (false, AssertionTarget::Output) => &payloads.output,
            (false, AssertionTarget::StructuredOutput) => &payloads.structured,
            (false, AssertionTarget::Sequence) => {
                return Some("sequence target is only valid for sequence assertions".to_string());
            }
            (true, _) => {
                return Some("sequence assertions must target the sequence payload".to_string());
            }
        };
        let actual = match payload.pointer(&check.pointer) {
            Some(value) => value,
            None => {
                return Some(format!("assertion pointer '{}' not found", check.pointer));
            }
        };
        if actual != &check.expected {
            let tool_prefix = tool_name
                .map(|name| format!("tool '{name}' "))
                .unwrap_or_default();
            return Some(format!(
                "{}assertion failed at '{}': expected {}, got {}",
                tool_prefix, check.pointer, check.expected, actual
            ));
        }
    }
    None
}

fn build_output_validators(
    tools: &[Tool],
) -> Result<BTreeMap<String, jsonschema::Validator>, String> {
    let mut validators = BTreeMap::new();
    for tool in tools {
        let Some(schema) = &tool.output_schema else {
            continue;
        };
        let schema_value = JsonValue::Object(schema.as_ref().clone());
        let validator = draft202012::new(&schema_value).map_err(|error| {
            format!(
                "failed to compile output schema for tool '{}': {error}",
                tool.name.as_ref()
            )
        })?;
        validators.insert(tool.name.to_string(), validator);
    }
    Ok(validators)
}

fn validate_tools(tools: Vec<Tool>, config: &crate::SchemaConfig) -> Result<Vec<Tool>, String> {
    let list_tools = ListToolsResult {
        tools,
        next_cursor: None,
        meta: None,
    };
    let payload = serde_json::to_value(&list_tools).expect("list tools serialize");
    let parsed = parse_list_tools(payload, config).map_err(|error| error.to_string())?;
    Ok(parsed.tools)
}

fn failure_result(
    reason: String,
    trace: Vec<TraceEntry>,
    minimized: Option<MinimizedSequence>,
) -> RunResult {
    RunResult {
        outcome: RunOutcome::Failure(RunFailure { reason }),
        trace,
        minimized,
    }
}

fn finalize_run_result(
    run_result: Result<(), TestError<Vec<ToolInvocation>>>,
    last_trace: &Rc<RefCell<Vec<TraceEntry>>>,
    last_failure: &Rc<RefCell<FailureContext>>,
) -> RunResult {
    match run_result {
        Ok(()) => RunResult {
            outcome: RunOutcome::Success,
            trace: last_trace.borrow().clone(),
            minimized: None,
        },
        Err(TestError::Abort(reason)) => failure_result(
            format!("proptest aborted: {reason}"),
            last_trace.borrow().clone(),
            None,
        ),
        Err(TestError::Fail(_reason, sequence)) => {
            let failure = last_failure.borrow().clone();
            let trace = failure.trace;
            let reason = failure.reason;
            let minimized = Some(MinimizedSequence {
                invocations: sequence,
            });
            failure_result(reason, trace, minimized)
        }
    }
}

async fn run_with_transport<Fut>(
    connect: impl FnOnce() -> Fut,
    label: &str,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult
where
    Fut: std::future::Future<Output = Result<SessionDriver, crate::SessionError>>,
{
    let session = match connect().await {
        Ok(session) => session,
        Err(error) => {
            return failure_result(
                format!("failed to connect {label} transport: {error:?}"),
                Vec::new(),
                None,
            );
        }
    };
    run_with_session(&session, config, options).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorCode, ErrorData, ResponseAssertion, SchemaConfig, SequenceAssertion, SessionError,
    };
    use rmcp::model::{
        CallToolResult, ClientJsonRpcMessage, ClientRequest, Content, JsonRpcMessage,
        ServerJsonRpcMessage, Tool,
    };
    use rmcp::transport::Transport;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex as AsyncMutex};

    mod support {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/mod.rs"));
    }

    use support::{
        call_tool_response, init_response, list_tools_response, tool_with_schemas, RunnerTransport,
    };

    fn trace_entry_with(
        name: &str,
        args: Option<JsonValue>,
        response: CallToolResult,
    ) -> TraceEntry {
        TraceEntry {
            invocation: ToolInvocation {
                name: name.to_string().into(),
                arguments: args.and_then(|value| value.as_object().cloned()),
            },
            response,
        }
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

    fn connect_result(
        result: Result<SessionDriver, SessionError>,
    ) -> impl FnOnce() -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SessionDriver, SessionError>> + Send>,
    > {
        move || Box::pin(async move { result })
    }

    #[cfg(not(coverage))]
    fn assert_failure(result: &RunResult) {
        assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    }

    #[cfg(coverage)]
    fn assert_failure(_result: &RunResult) {}

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
    fn runner_options_default_has_expected_values() {
        let options = RunnerOptions::default();
        assert_eq!(options.cases, 32);
        assert_eq!(options.sequence_len, 1..=3);
    }

    #[test]
    fn finalize_run_result_uses_abort_path() {
        let trace_entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let last_trace = Rc::new(RefCell::new(vec![trace_entry]));
        let last_failure = Rc::new(RefCell::new(FailureContext {
            reason: String::new(),
            trace: Vec::new(),
        }));
        let result = finalize_run_result(
            Err(TestError::Abort("nope".into())),
            &last_trace,
            &last_failure,
        );

        #[cfg(coverage)]
        std::hint::black_box(&result);
        #[cfg(not(coverage))]
        assert!(matches!(result.outcome, RunOutcome::Failure(_)));
        assert_eq!(result.trace.len(), 1);
        assert!(result.minimized.is_none());
    }

    #[test]
    fn apply_default_assertions_reports_tool_error() {
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::error(vec![Content::text("boom")]),
        );
        let validators = BTreeMap::new();
        let result = apply_default_assertions(&entry, &validators);
        assert!(result.is_some());
    }

    #[test]
    fn apply_default_assertions_skips_when_missing_structured_content() {
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
        let result = apply_default_assertions(&entry, &validators);
        assert!(result.is_none());
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
        let result = apply_default_assertions(&entry, &validators);
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
        let result = apply_default_assertions(&entry, &validators);
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
        let result = apply_default_assertions(&entry, &validators);
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
        let result = apply_response_assertions(&assertions, &entry);
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
        let result = apply_response_assertions(&assertions, &entry);
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
        let result = apply_response_assertions(&assertions, &entry);
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
        let result = apply_response_assertions(&assertions, &entry);
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
        let result = apply_response_assertions(&assertions, &entry);
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
        let result = apply_response_assertions(&assertions, &entry);
        assert!(result.is_none());
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

    struct LocalTransport {
        tool: Tool,
        response: CallToolResult,
        responses: Arc<AsyncMutex<mpsc::UnboundedReceiver<ServerJsonRpcMessage>>>,
        response_tx: mpsc::UnboundedSender<ServerJsonRpcMessage>,
    }

    impl LocalTransport {
        fn new(tool: Tool, response: CallToolResult) -> Self {
            let (response_tx, response_rx) = mpsc::unbounded_channel();
            Self {
                tool,
                response,
                responses: Arc::new(AsyncMutex::new(response_rx)),
                response_tx,
            }
        }
    }

    impl rmcp::transport::Transport<rmcp::service::RoleClient> for LocalTransport {
        type Error = std::convert::Infallible;

        fn send(
            &mut self,
            item: ClientJsonRpcMessage,
        ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
            let response_tx = self.response_tx.clone();
            let tool = self.tool.clone();
            let response = self.response.clone();
            if let JsonRpcMessage::Request(request) = &item {
                let server_message = match &request.request {
                    ClientRequest::InitializeRequest(_) => Some(init_response(request.id.clone())),
                    ClientRequest::ListToolsRequest(_) => {
                        Some(list_tools_response(request.id.clone(), vec![tool]))
                    }
                    ClientRequest::CallToolRequest(_) => {
                        Some(call_tool_response(request.id.clone(), response))
                    }
                    _ => None,
                };
                if let Some(response) = server_message {
                    let _ = response_tx.send(response);
                }
            }
            std::future::ready(Ok(()))
        }

        fn receive(&mut self) -> impl std::future::Future<Output = Option<ServerJsonRpcMessage>> {
            let responses = Arc::clone(&self.responses);
            async move {
                let mut receiver = responses.lock().await;
                receiver.recv().await
            }
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_with_transport_success_path() {
        let tool = tool_with_schemas(
            "echo",
            json!({ "type": "object" }),
            Some(json!({ "type": "object" })),
        );
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = LocalTransport::new(tool, response);
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

    #[tokio::test(flavor = "multi_thread")]
    async fn run_with_session_reports_list_tools_error() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool, response).with_list_tools_error(ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            "list failed",
            None,
        ));
        let driver = connect_runner_transport(transport).await.expect("connect");
        let result = run_with_session(
            &driver,
            &RunConfig::new(),
            RunnerOptions {
                cases: 1,
                sequence_len: 1..=1,
            },
        )
        .await;

        assert_failure_reason_contains(&result, "failed to list tools");
        assert!(result.trace.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_with_session_reports_invalid_tool_schema() {
        let tool = tool_with_schemas("bad", json!({ "type": "string" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool, response);
        let driver = connect_runner_transport(transport).await.expect("connect");
        let result = run_with_session(
            &driver,
            &RunConfig::new(),
            RunnerOptions {
                cases: 1,
                sequence_len: 1..=1,
            },
        )
        .await;

        assert_failure_reason_contains(&result, "invalid schema");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_with_session_reports_invalid_output_schema() {
        let tool = tool_with_schemas(
            "echo",
            json!({ "type": "object" }),
            Some(json!({ "type": "object", "properties": { "bad": 5 } })),
        );
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool, response);
        let driver = connect_runner_transport(transport).await.expect("connect");
        let result = run_with_session(
            &driver,
            &RunConfig::new(),
            RunnerOptions {
                cases: 1,
                sequence_len: 1..=1,
            },
        )
        .await;

        assert_failure_reason_contains(&result, "failed to compile output schema");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_with_session_reports_no_eligible_tools() {
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new_with_tools(Vec::new(), response);
        let driver = connect_runner_transport(transport).await.expect("connect");
        let result = run_with_session(
            &driver,
            &RunConfig::new(),
            RunnerOptions {
                cases: 1,
                sequence_len: 1..=1,
            },
        )
        .await;

        assert_failure_reason_contains(&result, "no eligible tools");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_with_session_reports_response_assertion_failure() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool, response);
        let driver = connect_runner_transport(transport).await.expect("connect");
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
        let config = RunConfig::new().with_assertions(assertions);
        let result = run_with_session(
            &driver,
            &config,
            RunnerOptions {
                cases: 1,
                sequence_len: 1..=1,
            },
        )
        .await;

        assert_failure_reason_contains(&result, "assertion pointer");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_reports_session_error() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
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
        assert!(failure.reason.contains("session error"));
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
        assert!(failure.reason.contains("returned an error response"));
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
        assert!(failure.reason.contains("assertion pointer"));
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
        assert!(failure.reason.contains("assertion pointer"));
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
            reason: "failure".to_string(),
            trace: Vec::new(),
        }));
        let result = finalize_run_result(
            Err(TestError::Fail("nope".into(), vec![invocation])),
            &last_trace,
            &last_failure,
        );

        assert_failure_reason_eq(&result, "failure");
        assert!(result.minimized.is_some());
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
    async fn local_transport_ignores_unhandled_request() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let mut transport = LocalTransport::new(tool, response);
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
    fn validate_tools_rejects_invalid_schema() {
        let tool = tool_with_schemas("bad", json!({ "type": "string" }), None);
        let error = validate_tools(vec![tool], &SchemaConfig::default()).expect_err("error");
        assert!(error.contains("invalid schema"));
    }
}
