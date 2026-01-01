use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::rc::Rc;

use proptest::test_runner::{Config as ProptestConfig, TestCaseError, TestError, TestRunner};
use rmcp::model::{ListToolsResult, Tool};

use crate::generator::{
    clear_reject_context, invocation_from_corpus_seeded, record_reject_context,
    state_machine_sequence_strategy, take_reject_context, StateMachineSequence,
};
use crate::output_schema::compile_output_schema;
use crate::schema::parse_list_tools;
use crate::{
    AssertionSet, CorpusReport, CoverageReport, MinimizedSequence, RunConfig, RunFailure,
    RunOutcome, RunResult, RunWarning, SessionDriver, ToolInvocation, TraceEntry,
};

use super::assertions::{
    apply_default_assertions, apply_response_assertions, apply_sequence_assertions,
    attach_failure_reason, attach_response,
};
use super::coverage::{coverage_failure, CoverageTracker};

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
            sequence_len: 1..=20,
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
                Vec::new(),
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
                Vec::new(),
                None,
                None,
            )
        }
    };
    let warnings = collect_schema_warnings(&tools);

    let validators = match build_output_validators(&tools) {
        Ok(validators) => validators,
        Err(reason) => {
            return failure_result(
                RunFailure::new(reason),
                prelude_trace.as_ref().clone(),
                None,
                warnings.clone(),
                None,
                None,
            )
        }
    };

    let assertions = config.assertions.clone();
    let warnings = Rc::new(warnings);
    let aggregate_tools = tools.clone();
    let aggregate_tracker: Rc<RefCell<CoverageTracker<'_>>> = Rc::new(RefCell::new(
        CoverageTracker::new(&aggregate_tools, &config.state_machine),
    ));
    let last_trace: Rc<RefCell<Vec<TraceEntry>>> = Rc::new(RefCell::new(Vec::new()));
    last_trace.replace(prelude_trace.as_ref().clone());
    let last_coverage: Rc<RefCell<Option<CoverageReport>>> = Rc::new(RefCell::new(None));
    let last_corpus: Rc<RefCell<Option<CorpusReport>>> = Rc::new(RefCell::new(None));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new(String::new()),
        trace: Vec::new(),
        coverage: None,
        corpus: None,
    }));
    let validators = Rc::new(validators);
    clear_reject_context();
    let handle = tokio::runtime::Handle::current();
    if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
        return failure_result(
            RunFailure::new("run_with_session requires a multi-thread Tokio runtime".to_string()),
            Vec::new(),
            None,
            warnings.as_ref().clone(),
            None,
            None,
        );
    }

    let mut runner = TestRunner::new(ProptestConfig {
        cases: options.cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    });

    let strategy = match state_machine_sequence_strategy(
        &tools,
        config.predicate.as_ref(),
        &config.state_machine,
        options.sequence_len.clone(),
    ) {
        Ok(strategy) => strategy,
        Err(error) => {
            return failure_result(
                RunFailure::new(error.to_string()),
                prelude_trace.as_ref().clone(),
                None,
                warnings.as_ref().clone(),
                None,
                None,
            )
        }
    };

    let run_result = runner.run(&strategy, {
        let assertions = assertions.clone();
        let last_trace = last_trace.clone();
        let last_coverage = last_coverage.clone();
        let last_corpus = last_corpus.clone();
        let last_failure = last_failure.clone();
        let validators = validators.clone();
        let aggregate_tracker = aggregate_tracker.clone();
        move |sequence| {
            let execution: Result<Vec<TraceEntry>, FailureContext> =
                tokio::task::block_in_place(|| {
                    let last_coverage = last_coverage.clone();
                    let last_corpus = last_corpus.clone();
                    handle.block_on(async {
                        let mut tracker = CoverageTracker::new(&tools, &config.state_machine);
                        let min_len = if config.state_machine.coverage_rules.is_empty() {
                            Some(*options.sequence_len.start())
                        } else {
                            None
                        };
                        let result = execute_state_machine_sequence(
                            session,
                            &tools,
                            &validators,
                            &assertions,
                            &sequence,
                            &mut tracker,
                            config.predicate.as_ref(),
                            min_len,
                        )
                        .await;
                        let (report, corpus_report) = {
                            let mut aggregate = aggregate_tracker.borrow_mut();
                            aggregate.merge_from(&tracker);
                            let report = aggregate.report();
                            let corpus_report = if config.state_machine.dump_corpus {
                                Some(aggregate.corpus_report())
                            } else {
                                None
                            };
                            (report, corpus_report)
                        };
                        last_coverage.replace(Some(report.clone()));
                        last_corpus.replace(corpus_report.clone());
                        match result {
                            Ok(trace) => Ok(trace),
                            Err(mut failure) => {
                                failure.coverage = Some(report);
                                failure.corpus = corpus_report;
                                Err(failure)
                            }
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
    let run_result = finalize_state_machine_result(
        run_result,
        &last_trace,
        &last_failure,
        &last_coverage,
        &last_corpus,
        warnings.as_ref(),
    );
    if matches!(run_result.outcome, RunOutcome::Success) {
        if let Err(failure) = aggregate_tracker
            .borrow()
            .validate(&config.state_machine.coverage_rules)
        {
            let mut trace = last_trace.borrow().clone();
            attach_failure_reason(&mut trace, "coverage validation failed".to_string());
            let report = aggregate_tracker.borrow().report();
            let corpus_report = if config.state_machine.dump_corpus {
                Some(aggregate_tracker.borrow().corpus_report())
            } else {
                None
            };
            return failure_result(
                coverage_failure(failure),
                trace,
                None,
                warnings.as_ref().clone(),
                Some(report),
                corpus_report,
            );
        }
    }
    run_result
}

#[derive(Clone, Debug)]
pub(super) struct FailureContext {
    pub(super) failure: RunFailure,
    pub(super) trace: Vec<TraceEntry>,
    pub(super) coverage: Option<CoverageReport>,
    pub(super) corpus: Option<CorpusReport>,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) async fn execute_sequence(
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
                    corpus: None,
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
                corpus: None,
            });
        }

        if let Some(reason) = apply_response_assertions(assertions, &invocation, &response) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
                corpus: None,
            });
        }
    }

    if let Some(reason) = apply_sequence_assertions(assertions, &full_trace) {
        attach_failure_reason(&mut trace, reason.clone());
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace,
            coverage: None,
            corpus: None,
        });
    }

    Ok(trace)
}

#[cfg(test)]
pub(super) async fn execute_sequence_with_coverage(
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
                    corpus: None,
                });
            }
        };

        let (invocation, response) = entry.as_tool_call().expect("tool call trace entry");
        let invocation = invocation.clone();
        let response = response.expect("tool call response").clone();
        attach_response(&mut trace, response.clone());
        full_trace.push(entry);
        if !response.is_error.unwrap_or(false) {
            tracker.record_success(invocation.name.as_ref());
            tracker.mine_response(invocation.name.as_ref(), &response);
        }

        if let Some(reason) = apply_default_assertions(&invocation, &response, validators) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
                corpus: None,
            });
        }

        if let Some(reason) = apply_response_assertions(assertions, &invocation, &response) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
                corpus: None,
            });
        }
    }

    if let Some(reason) = apply_sequence_assertions(assertions, &full_trace) {
        attach_failure_reason(&mut trace, reason.clone());
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace,
            coverage: None,
            corpus: None,
        });
    }

    Ok(trace)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_state_machine_sequence(
    session: &SessionDriver,
    tools: &[Tool],
    validators: &BTreeMap<String, jsonschema::Validator>,
    assertions: &AssertionSet,
    sequence: &StateMachineSequence,
    tracker: &mut CoverageTracker<'_>,
    predicate: Option<&crate::ToolPredicate>,
    min_len: Option<usize>,
) -> Result<Vec<TraceEntry>, FailureContext> {
    let mut trace = Vec::new();
    let mut full_trace = Vec::new();
    let mut invocation_count = 0usize;
    for seed in &sequence.seeds {
        let invocation = match invocation_from_corpus_seeded(
            tools,
            predicate,
            tracker.corpus(),
            tracker.lenient_sourcing(),
            *seed,
        ) {
            Ok(Some(invocation)) => invocation,
            Ok(None) | Err(crate::generator::InvocationError::NoEligibleTools) => {
                record_reject_context("no callable tools".to_string());
                break;
            }
            Err(error) => {
                return Err(FailureContext {
                    failure: RunFailure::new(error.to_string()),
                    trace,
                    coverage: None,
                    corpus: None,
                });
            }
        };

        invocation_count += 1;
        trace.push(TraceEntry::tool_call(invocation.clone()));
        let entry = match session.send_tool_call(invocation.clone()).await {
            Ok(entry) => entry,
            Err(error) => {
                attach_failure_reason(&mut trace, format!("session error: {error:?}"));
                return Err(FailureContext {
                    failure: RunFailure::new(format!("session error: {error:?}")),
                    trace,
                    coverage: None,
                    corpus: None,
                });
            }
        };

        let (invocation, response) = entry.as_tool_call().expect("tool call trace entry");
        let invocation = invocation.clone();
        let response = response.expect("tool call response").clone();
        full_trace.push(entry);
        if !response.is_error.unwrap_or(false) {
            tracker.record_success(invocation.name.as_ref());
            tracker.mine_response(invocation.name.as_ref(), &response);
        }

        if let Some(reason) = apply_default_assertions(&invocation, &response, validators) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
                corpus: None,
            });
        }

        if let Some(reason) = apply_response_assertions(assertions, &invocation, &response) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
                corpus: None,
            });
        }
    }

    if let Some(min_len) = min_len {
        if invocation_count < min_len {
            let reason = format!(
                "state-machine generator failed to reach minimum sequence length ({min_len})"
            );
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                coverage: None,
                corpus: None,
            });
        }
    }

    if let Some(reason) = apply_sequence_assertions(assertions, &full_trace) {
        attach_failure_reason(&mut trace, reason.clone());
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace,
            coverage: None,
            corpus: None,
        });
    }

    Ok(trace)
}

pub(super) fn failure_result(
    failure: RunFailure,
    trace: Vec<TraceEntry>,
    minimized: Option<MinimizedSequence>,
    warnings: Vec<RunWarning>,
    coverage: Option<CoverageReport>,
    corpus: Option<CorpusReport>,
) -> RunResult {
    RunResult {
        outcome: RunOutcome::Failure(failure),
        trace,
        minimized,
        warnings,
        coverage,
        corpus,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn finalize_run_result(
    run_result: Result<(), TestError<Vec<ToolInvocation>>>,
    last_trace: &Rc<RefCell<Vec<TraceEntry>>>,
    last_failure: &Rc<RefCell<FailureContext>>,
    last_coverage: &Rc<RefCell<Option<CoverageReport>>>,
    last_corpus: &Rc<RefCell<Option<CorpusReport>>>,
    warnings: &[RunWarning],
) -> RunResult {
    match run_result {
        Ok(()) => RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: warnings.to_vec(),
            coverage: last_coverage.borrow().clone(),
            corpus: last_corpus.borrow().clone(),
        },
        Err(TestError::Abort(reason)) => {
            let mut message = format!("proptest aborted: {reason}");
            let context = take_reject_context()
                .map(|context| format!("; last rejection: {context}"))
                .unwrap_or_default();
            message.push_str(&context);
            failure_result(
                RunFailure::new(message),
                last_trace.borrow().clone(),
                None,
                warnings.to_vec(),
                last_coverage.borrow().clone(),
                last_corpus.borrow().clone(),
            )
        }
        Err(TestError::Fail(_reason, sequence)) => {
            let failure = last_failure.borrow().clone();
            let trace = failure.trace;
            let minimized = Some(MinimizedSequence {
                invocations: sequence,
            });
            failure_result(
                failure.failure,
                trace,
                minimized,
                warnings.to_vec(),
                failure.coverage,
                failure.corpus,
            )
        }
    }
}

fn trace_invocations(trace: &[TraceEntry]) -> Vec<ToolInvocation> {
    trace
        .iter()
        .filter_map(|entry| {
            entry
                .as_tool_call()
                .map(|(invocation, _)| invocation.clone())
        })
        .collect()
}

pub(super) fn finalize_state_machine_result(
    run_result: Result<(), TestError<StateMachineSequence>>,
    last_trace: &Rc<RefCell<Vec<TraceEntry>>>,
    last_failure: &Rc<RefCell<FailureContext>>,
    last_coverage: &Rc<RefCell<Option<CoverageReport>>>,
    last_corpus: &Rc<RefCell<Option<CorpusReport>>>,
    warnings: &[RunWarning],
) -> RunResult {
    match run_result {
        Ok(()) => RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: warnings.to_vec(),
            coverage: last_coverage.borrow().clone(),
            corpus: last_corpus.borrow().clone(),
        },
        Err(TestError::Abort(reason)) => {
            let mut message = format!("proptest aborted: {reason}");
            let context = take_reject_context()
                .map(|context| format!("; last rejection: {context}"))
                .unwrap_or_default();
            message.push_str(&context);
            failure_result(
                RunFailure::new(message),
                last_trace.borrow().clone(),
                None,
                warnings.to_vec(),
                last_coverage.borrow().clone(),
                last_corpus.borrow().clone(),
            )
        }
        Err(TestError::Fail(_reason, _sequence)) => {
            let failure = last_failure.borrow().clone();
            let trace = failure.trace;
            let invocations = trace_invocations(&trace);
            let minimized = if invocations.is_empty() {
                None
            } else {
                Some(MinimizedSequence { invocations })
            };
            failure_result(
                failure.failure,
                trace,
                minimized,
                warnings.to_vec(),
                failure.coverage,
                failure.corpus,
            )
        }
    }
}

pub(super) fn collect_schema_warnings(tools: &[Tool]) -> Vec<RunWarning> {
    let mut warnings = Vec::new();
    for tool in tools {
        collect_schema_keyword_warnings(
            tool,
            "input schema",
            tool.input_schema.as_ref(),
            &mut warnings,
        );
        if let Some(schema) = tool.output_schema.as_ref() {
            collect_schema_keyword_warnings(tool, "output schema", schema.as_ref(), &mut warnings);
        }
    }
    warnings
}

pub(super) fn collect_schema_keyword_warnings(
    tool: &Tool,
    schema_label: &str,
    schema: &crate::JsonObject,
    warnings: &mut Vec<RunWarning>,
) {
    if !schema.contains_key("$defs") {
        return;
    }
    let schema_id = schema
        .get("$schema")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if schema_id.contains("draft-07")
        || schema_id.contains("draft-06")
        || schema_id.contains("draft-04")
    {
        warnings.push(RunWarning {
            code: crate::RunWarningCode::SchemaUnsupportedKeyword,
            message: format!(
                "tool '{}' {schema_label} declares {schema_id} but uses '$defs'; draft-07 and earlier use 'definitions'",
                tool.name
            ),
            tool: Some(tool.name.to_string()),
        });
    }
}

pub(super) fn build_output_validators(
    tools: &[Tool],
) -> Result<BTreeMap<String, jsonschema::Validator>, String> {
    let mut validators = BTreeMap::new();
    for tool in tools {
        let Some(schema) = &tool.output_schema else {
            continue;
        };
        let validator = compile_output_schema(schema.as_ref()).map_err(|error| {
            format!(
                "failed to compile output schema for tool '{}': {error}",
                tool.name.as_ref()
            )
        })?;
        validators.insert(tool.name.to_string(), validator);
    }
    Ok(validators)
}

pub(super) fn validate_tools(
    tools: Vec<Tool>,
    config: &crate::SchemaConfig,
) -> Result<Vec<Tool>, String> {
    let list_tools = ListToolsResult {
        tools,
        next_cursor: None,
        meta: None,
    };
    let payload = serde_json::to_value(&list_tools).expect("list tools serialize");
    let parsed = parse_list_tools(payload, config).map_err(|error| error.to_string())?;
    Ok(parsed.tools)
}
