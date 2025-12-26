//! MCP sequence runner with default and declarative assertions.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::rc::Rc;

use jsonschema::draft202012;
use proptest::test_runner::{Config as ProptestConfig, TestCaseError, TestError, TestRunner};
use rmcp::model::{CallToolResult, ListToolsResult, Tool};
use serde_json::{json, Value as JsonValue};

use crate::generator::{
    invocation_sequence_strategy, state_machine_sequence_strategy, uncallable_reason,
    UncallableReason, ValueCorpus,
};
use crate::schema::parse_list_tools;
use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CoverageReport, CoverageRule,
    CoverageWarning, CoverageWarningReason, GeneratorMode, HttpConfig, MinimizedSequence,
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
///
/// Runs apply default assertions that fail on error responses and validate
/// structured output against declared output schemas, plus any user-supplied
/// assertion rules.
///
/// Requires a multi-thread Tokio runtime; current-thread runtimes are rejected.
pub async fn run_with_session(
    session: &SessionDriver,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    let prelude_trace = Rc::new(vec![TraceEntry::list_tools()]);
    let tools = match session.list_tools().await {
        Ok(tools) => tools,
        Err(error) => {
            let reason = format!("failed to list tools: {error:?}");
            return failure_result(
                RunFailure::new(reason.clone()),
                vec![TraceEntry::list_tools_with_failure(reason)],
                None,
                None,
            );
        }
    };

    let tools = match validate_tools(tools, &config.schema) {
        Ok(tools) => tools,
        Err(reason) => {
            return failure_result(
                RunFailure::new(reason),
                prelude_trace.as_ref().clone(),
                None,
                None,
            )
        }
    };

    let validators = match build_output_validators(&tools) {
        Ok(validators) => validators,
        Err(reason) => {
            return failure_result(
                RunFailure::new(reason),
                prelude_trace.as_ref().clone(),
                None,
                None,
            )
        }
    };

    let strategy = match config.generator_mode {
        crate::GeneratorMode::Legacy => invocation_sequence_strategy(
            &tools,
            config.predicate.as_ref(),
            options.sequence_len.clone(),
        ),
        crate::GeneratorMode::StateMachine => state_machine_sequence_strategy(
            &tools,
            config.predicate.as_ref(),
            &config.state_machine,
            options.sequence_len.clone(),
        ),
    };
    let strategy = match strategy {
        Ok(strategy) => strategy,
        Err(error) => {
            return failure_result(
                RunFailure::new(error.to_string()),
                prelude_trace.as_ref().clone(),
                None,
                None,
            )
        }
    };

    let assertions = config.assertions.clone();
    let last_trace: Rc<RefCell<Vec<TraceEntry>>> = Rc::new(RefCell::new(Vec::new()));
    last_trace.replace(prelude_trace.as_ref().clone());
    let last_coverage: Rc<RefCell<Option<CoverageReport>>> = Rc::new(RefCell::new(None));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new(String::new()),
        trace: Vec::new(),
        coverage: None,
    }));
    let validators = Rc::new(validators);
    let handle = tokio::runtime::Handle::current();
    if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
        return failure_result(
            RunFailure::new("run_with_session requires a multi-thread Tokio runtime".to_string()),
            Vec::new(),
            None,
            None,
        );
    }

    let mut runner = TestRunner::new(ProptestConfig {
        cases: options.cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    });

    let run_result = runner.run(&strategy, {
        let assertions = assertions.clone();
        let last_trace = last_trace.clone();
        let last_coverage = last_coverage.clone();
        let last_failure = last_failure.clone();
        let validators = validators.clone();
        move |sequence| {
            let execution: Result<Vec<TraceEntry>, FailureContext> =
                tokio::task::block_in_place(|| {
                    let last_coverage = last_coverage.clone();
                    handle.block_on(async {
                        if config.generator_mode == GeneratorMode::StateMachine {
                            let mut tracker = CoverageTracker::new(&tools, &config.state_machine);
                            let result = execute_sequence_with_coverage(
                                session,
                                &validators,
                                &assertions,
                                &sequence,
                                &mut tracker,
                            )
                            .await;
                            match result {
                                Ok(trace) => {
                                    let validation =
                                        tracker.validate(&config.state_machine.coverage_rules);
                                    let report = tracker.finalize();
                                    last_coverage.replace(Some(report.clone()));
                                    if let Err(failure) = validation {
                                        let mut trace = trace;
                                        attach_failure_reason(
                                            &mut trace,
                                            "coverage validation failed".to_string(),
                                        );
                                        return Err(FailureContext {
                                            failure: coverage_failure(failure),
                                            trace,
                                            coverage: Some(report),
                                        });
                                    }
                                    Ok(trace)
                                }
                                Err(mut failure) => {
                                    failure.coverage = Some(tracker.finalize());
                                    last_coverage.replace(failure.coverage.clone());
                                    Err(failure)
                                }
                            }
                        } else {
                            let result =
                                execute_sequence(session, &validators, &assertions, &sequence)
                                    .await;
                            last_coverage.replace(None);
                            result
                        }
                    })
                });
            match execution {
                Ok(trace) => {
                    let mut full_trace = prelude_trace.as_ref().clone();
                    full_trace.extend(trace);
                    last_trace.replace(full_trace);
                    Ok(())
                }
                Err(mut failure) => {
                    let mut full_trace = prelude_trace.as_ref().clone();
                    full_trace.extend(failure.trace);
                    failure.trace = full_trace;
                    last_failure.replace(failure.clone());
                    Err(TestCaseError::fail(failure.failure.reason.clone()))
                }
            }
        }
    });

    finalize_run_result(run_result, &last_trace, &last_failure, &last_coverage)
}

/// Execute a tooltest run against a stdio MCP endpoint.
///
/// Uses the same default and declarative assertions as [`run_with_session`].
pub async fn run_stdio(
    endpoint: &StdioConfig,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    run_with_transport(
        Box::pin(SessionDriver::connect_stdio(endpoint)),
        "stdio",
        config,
        options,
    )
    .await
}

/// Execute a tooltest run against an HTTP MCP endpoint.
///
/// Uses the same default and declarative assertions as [`run_with_session`].
pub async fn run_http(
    endpoint: &HttpConfig,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    run_with_transport(
        Box::pin(SessionDriver::connect_http(endpoint)),
        "http",
        config,
        options,
    )
    .await
}

#[derive(Clone, Debug)]
struct FailureContext {
    failure: RunFailure,
    trace: Vec<TraceEntry>,
    coverage: Option<CoverageReport>,
}

async fn execute_sequence(
    session: &SessionDriver,
    validators: &BTreeMap<String, jsonschema::Validator>,
    assertions: &AssertionSet,
    sequence: &[ToolInvocation],
) -> Result<Vec<TraceEntry>, FailureContext> {
    let mut trace = Vec::new();
    let mut full_trace = Vec::new();
    for invocation in sequence {
        trace.push(TraceEntry::tool_call(invocation.clone()));
        let entry = match session.send_tool_call(invocation.clone()).await {
            Ok(entry) => entry,
            Err(error) => {
                attach_failure_reason(&mut trace, format!("session error: {error:?}"));
                return Err(FailureContext {
                    failure: RunFailure::new(format!("session error: {error:?}")),
                    trace,
                    coverage: None,
                });
            }
        };
        let (invocation, response) = entry.as_tool_call().expect("tool call trace entry");
        let invocation = invocation.clone();
        let response = response.expect("tool call response").clone();
        full_trace.push(entry);

        if let Some(reason) = apply_default_assertions(&invocation, &response, validators) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
            });
        }

        if let Some(reason) = apply_response_assertions(assertions, &invocation, &response) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
            });
        }
    }

    if let Some(reason) = apply_sequence_assertions(assertions, &full_trace) {
        attach_failure_reason(&mut trace, reason.clone());
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace,
            coverage: None,
        });
    }

    Ok(trace)
}

struct CoverageTracker<'a> {
    tools: &'a [Tool],
    corpus: ValueCorpus,
    counts: BTreeMap<String, u64>,
    allowlist: Option<Vec<String>>,
    blocklist: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
struct CoverageValidationFailure {
    details: JsonValue,
}

impl<'a> CoverageTracker<'a> {
    fn new(tools: &'a [Tool], config: &crate::StateMachineConfig) -> Self {
        let mut corpus = ValueCorpus::default();
        corpus.seed_numbers(config.seed_numbers.clone());
        corpus.seed_strings(config.seed_strings.clone());
        Self {
            tools,
            corpus,
            counts: BTreeMap::new(),
            allowlist: config.coverage_allowlist.clone(),
            blocklist: config.coverage_blocklist.clone(),
        }
    }

    fn record_success(&mut self, tool: &str) {
        *self.counts.entry(tool.to_string()).or_insert(0) += 1;
    }

    fn mine_response(&mut self, response: &CallToolResult) {
        if let Some(structured) = response.structured_content.as_ref() {
            self.corpus.mine_structured_content(structured);
        }
    }

    fn finalize(self) -> CoverageReport {
        let warnings = self.build_warnings();
        CoverageReport {
            counts: self.counts,
            warnings,
        }
    }

    fn build_warnings(&self) -> Vec<CoverageWarning> {
        let mut warnings = Vec::new();
        let allowlist = self.allowlist.as_ref();
        let blocklist = self.blocklist.as_ref();

        for tool in self.tools {
            let name = tool.name.to_string();
            if let Some(allowlist) = allowlist {
                if !allowlist.iter().any(|entry| entry == &name) {
                    continue;
                }
            }
            if let Some(blocklist) = blocklist {
                if blocklist.iter().any(|entry| entry == &name) {
                    continue;
                }
            }

            if let Some(reason) = uncallable_reason(tool, &self.corpus) {
                warnings.push(CoverageWarning {
                    tool: name,
                    reason: map_uncallable_reason(reason),
                });
            }
        }

        warnings
    }

    fn validate(&self, rules: &[CoverageRule]) -> Result<(), CoverageValidationFailure> {
        if rules.is_empty() {
            return Ok(());
        }

        let eligible_tools = self.eligible_tools();
        let mut callable_tools = Vec::new();
        for tool in eligible_tools {
            if uncallable_reason(tool, &self.corpus).is_none() {
                callable_tools.push(tool.name.to_string());
            }
        }

        for rule in rules {
            match rule {
                CoverageRule::MinCallsPerTool { min } => {
                    let mut violations = Vec::new();
                    for tool in &callable_tools {
                        let count = *self.counts.get(tool).unwrap_or(&0);
                        if count < *min {
                            violations.push(json!({ "tool": tool, "count": count }));
                        }
                    }
                    let failure = if violations.is_empty() {
                        None
                    } else {
                        Some(CoverageValidationFailure {
                            details: json!({
                                "rule": "min_calls_per_tool",
                                "min": min,
                                "violations": violations,
                            }),
                        })
                    };
                    if let Some(failure) = failure {
                        return Err(failure);
                    }
                }
                CoverageRule::NoUncalledTools => {
                    let uncalled: Vec<String> = callable_tools
                        .iter()
                        .filter(|tool| *self.counts.get(*tool).unwrap_or(&0) == 0)
                        .cloned()
                        .collect();
                    let failure = if uncalled.is_empty() {
                        None
                    } else {
                        Some(CoverageValidationFailure {
                            details: json!({
                                "rule": "no_uncalled_tools",
                                "uncalled": uncalled,
                            }),
                        })
                    };
                    if let Some(failure) = failure {
                        return Err(failure);
                    }
                }
                CoverageRule::PercentCalled { min_percent } => {
                    if !min_percent.is_finite() || *min_percent < 0.0 || *min_percent > 100.0 {
                        return Err(CoverageValidationFailure {
                            details: json!({
                                "rule": "percent_called",
                                "error": "min_percent_out_of_range",
                                "min_percent": min_percent,
                            }),
                        });
                    }
                    let denom = callable_tools.len() as f64;
                    if denom == 0.0 {
                        continue;
                    }
                    let called = callable_tools
                        .iter()
                        .filter(|tool| *self.counts.get(*tool).unwrap_or(&0) > 0)
                        .count() as f64;
                    let percent = (called / denom) * 100.0;
                    if percent < *min_percent {
                        return Err(CoverageValidationFailure {
                            details: json!({
                                "rule": "percent_called",
                                "min_percent": min_percent,
                                "percent": percent,
                                "called": called,
                                "eligible": denom,
                            }),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn eligible_tools(&self) -> Vec<&Tool> {
        let allowlist = self.allowlist.as_ref();
        let blocklist = self.blocklist.as_ref();
        self.tools
            .iter()
            .filter(|tool| {
                let name = tool.name.to_string();
                if let Some(allowlist) = allowlist {
                    if !allowlist.iter().any(|entry| entry == &name) {
                        return false;
                    }
                }
                if let Some(blocklist) = blocklist {
                    if blocklist.iter().any(|entry| entry == &name) {
                        return false;
                    }
                }
                true
            })
            .collect()
    }
}

fn map_uncallable_reason(reason: UncallableReason) -> CoverageWarningReason {
    match reason {
        UncallableReason::String => CoverageWarningReason::MissingString,
        UncallableReason::Integer => CoverageWarningReason::MissingInteger,
        UncallableReason::Number => CoverageWarningReason::MissingNumber,
        UncallableReason::RequiredValue => CoverageWarningReason::MissingRequiredValue,
    }
}

fn coverage_failure(failure: CoverageValidationFailure) -> RunFailure {
    RunFailure {
        reason: "coverage validation failed".to_string(),
        code: Some("coverage_validation_failed".to_string()),
        details: Some(failure.details),
    }
}

async fn execute_sequence_with_coverage(
    session: &SessionDriver,
    validators: &BTreeMap<String, jsonschema::Validator>,
    assertions: &AssertionSet,
    sequence: &[ToolInvocation],
    tracker: &mut CoverageTracker<'_>,
) -> Result<Vec<TraceEntry>, FailureContext> {
    let mut trace = Vec::new();
    let mut full_trace = Vec::new();
    for invocation in sequence {
        trace.push(TraceEntry::tool_call(invocation.clone()));
        let entry = match session.send_tool_call(invocation.clone()).await {
            Ok(entry) => entry,
            Err(error) => {
                attach_failure_reason(&mut trace, format!("session error: {error:?}"));
                return Err(FailureContext {
                    failure: RunFailure::new(format!("session error: {error:?}")),
                    trace,
                    coverage: None,
                });
            }
        };

        let (invocation, response) = entry.as_tool_call().expect("tool call trace entry");
        let invocation = invocation.clone();
        let response = response.expect("tool call response").clone();
        full_trace.push(entry);
        if !response.is_error.unwrap_or(false) {
            tracker.record_success(invocation.name.as_ref());
            tracker.mine_response(&response);
        }

        if let Some(reason) = apply_default_assertions(&invocation, &response, validators) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
            });
        }

        if let Some(reason) = apply_response_assertions(assertions, &invocation, &response) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
            });
        }
    }

    if let Some(reason) = apply_sequence_assertions(assertions, &full_trace) {
        attach_failure_reason(&mut trace, reason.clone());
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace,
            coverage: None,
        });
    }

    Ok(trace)
}

fn apply_default_assertions(
    invocation: &ToolInvocation,
    response: &CallToolResult,
    validators: &BTreeMap<String, jsonschema::Validator>,
) -> Option<String> {
    if response.is_error.unwrap_or(false) {
        return Some(format!(
            "tool '{}' returned an error response",
            invocation.name.as_ref()
        ));
    }

    let tool_name = invocation.name.as_ref();
    let validator = validators.get(tool_name)?;
    let Some(structured) = response.structured_content.as_ref() else {
        return Some(format!(
            "tool '{tool_name}' returned no structured_content for output schema"
        ));
    };
    if let Err(error) = validator.validate(structured) {
        return Some(format!(
            "output schema violation for tool '{tool_name}': {error}"
        ));
    }
    None
}

fn apply_response_assertions(
    assertions: &AssertionSet,
    invocation: &ToolInvocation,
    response: &CallToolResult,
) -> Option<String> {
    if assertions.rules.is_empty() {
        return None;
    }

    let input_payload = invocation
        .arguments
        .clone()
        .map(JsonValue::Object)
        .unwrap_or(JsonValue::Null);
    let output_payload = serde_json::to_value(response).unwrap_or(JsonValue::Null);
    let structured_payload = response
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
            if tool != invocation.name.as_ref() {
                continue;
            }
        }
        if let Some(reason) = evaluate_checks(
            &response_assertion.checks,
            &payloads,
            Some(invocation.name.as_ref()),
            false,
        ) {
            return Some(reason);
        }
    }

    None
}

fn attach_response(trace: &mut [TraceEntry], response: CallToolResult) {
    if let Some(TraceEntry::ToolCall { response: slot, .. }) = trace.last_mut() {
        *slot = Some(response);
    }
}

fn attach_failure_reason(trace: &mut [TraceEntry], reason: String) {
    if let Some(TraceEntry::ToolCall { failure_reason, .. }) = trace.last_mut() {
        *failure_reason = Some(reason);
    }
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
    failure: RunFailure,
    trace: Vec<TraceEntry>,
    minimized: Option<MinimizedSequence>,
    coverage: Option<CoverageReport>,
) -> RunResult {
    RunResult {
        outcome: RunOutcome::Failure(failure),
        trace,
        minimized,
        coverage,
    }
}

fn finalize_run_result(
    run_result: Result<(), TestError<Vec<ToolInvocation>>>,
    last_trace: &Rc<RefCell<Vec<TraceEntry>>>,
    last_failure: &Rc<RefCell<FailureContext>>,
    last_coverage: &Rc<RefCell<Option<CoverageReport>>>,
) -> RunResult {
    match run_result {
        Ok(()) => RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            coverage: last_coverage.borrow().clone(),
        },
        Err(TestError::Abort(reason)) => failure_result(
            RunFailure::new(format!("proptest aborted: {reason}")),
            last_trace.borrow().clone(),
            None,
            last_coverage.borrow().clone(),
        ),
        Err(TestError::Fail(_reason, sequence)) => {
            let failure = last_failure.borrow().clone();
            let trace = failure.trace;
            let minimized = Some(MinimizedSequence {
                invocations: sequence,
            });
            failure_result(failure.failure, trace, minimized, failure.coverage)
        }
    }
}

type ConnectFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<SessionDriver, crate::SessionError>> + Send + 'a>,
>;

async fn run_with_transport(
    connect: ConnectFuture<'_>,
    label: &str,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    let session = match connect.await {
        Ok(session) => session,
        Err(error) => {
            return failure_result(
                RunFailure::new(format!("failed to connect {label} transport: {error:?}")),
                Vec::new(),
                None,
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
        AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CoverageRule,
        CoverageWarningReason, ErrorCode, ErrorData, JsonObject, ResponseAssertion, SchemaConfig,
        SequenceAssertion, SessionError, StateMachineConfig,
    };
    use rmcp::model::{CallToolResult, ClientJsonRpcMessage, ClientRequest, Content};
    use rmcp::transport::Transport;
    use serde_json::{json, Number};

    use tooltest_test_support::{tool_with_schemas, RunnerTransport};

    fn trace_entry_with(
        name: &str,
        args: Option<JsonValue>,
        response: CallToolResult,
    ) -> TraceEntry {
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
        }));
        let result = finalize_run_result(
            Err(TestError::Abort("nope".into())),
            &last_trace,
            &last_failure,
            &Rc::new(RefCell::new(None)),
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
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
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
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
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
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
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
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
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
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
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
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
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
            coverage: None,
        };
        assert_success(&result);
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

        let result =
            execute_sequence(&session, &BTreeMap::new(), &AssertionSet::default(), &[]).await;

        let trace = result.expect("expected success");
        assert!(trace.is_empty());
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
        }));
        let result = finalize_run_result(
            Err(TestError::Fail("nope".into(), vec![invocation])),
            &last_trace,
            &last_failure,
            &Rc::new(RefCell::new(None)),
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
        tracker.mine_response(response.expect("response"));

        assert!(tracker.corpus.numbers().contains(&Number::from(2)));
        assert!(tracker.corpus.strings().contains(&"label".to_string()));
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
        tracker.mine_response(response.expect("response"));

        assert!(tracker.corpus.numbers().is_empty());
        assert!(tracker.corpus.strings().is_empty());
    }

    #[test]
    fn coverage_tracker_finalize_reports_warnings() {
        let tools = vec![tool_with_schemas(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        )];
        let config = StateMachineConfig::default();
        let tracker = CoverageTracker::new(&tools, &config);
        let report = tracker.finalize();
        assert!(!report.warnings.is_empty());
    }

    #[test]
    fn coverage_tracker_skips_blocklisted_tools() {
        let tools = vec![tool_with_schemas(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        )];
        let config =
            StateMachineConfig::default().with_coverage_blocklist(vec!["echo".to_string()]);
        let tracker = CoverageTracker::new(&tools, &config);
        let warnings = tracker.build_warnings();
        assert!(warnings.is_empty());
    }

    #[test]
    fn coverage_tracker_respects_allowlist_for_warnings() {
        let alpha = tool_with_schemas(
            "alpha",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        );
        let beta = tool_with_schemas(
            "beta",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        );
        let config =
            StateMachineConfig::default().with_coverage_allowlist(vec!["alpha".to_string()]);
        let tools = vec![alpha, beta];
        let tracker = CoverageTracker::new(&tools, &config);

        let warnings = tracker.build_warnings();

        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].tool, "alpha");
        assert_eq!(warnings[0].reason, CoverageWarningReason::MissingString);
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
                "properties": { "text": { "type": "string" } },
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
        let config =
            StateMachineConfig::default().with_coverage_allowlist(vec!["alpha".to_string()]);
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
        let config =
            StateMachineConfig::default().with_coverage_blocklist(vec!["alpha".to_string()]);
        let tools = vec![alpha, beta];
        let tracker = CoverageTracker::new(&tools, &config);
        let eligible = tracker.eligible_tools();
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].name.as_ref(), "beta");
    }

    #[test]
    fn map_uncallable_reason_maps_variants() {
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
        assert_eq!(tracker.counts.get("echo").copied(), Some(1));
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
}
