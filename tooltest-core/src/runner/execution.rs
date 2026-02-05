use std::cell::RefCell;
use std::ops::RangeInclusive;
use std::rc::Rc;

use proptest::test_runner::{Config as ProptestConfig, TestCaseError, TestError, TestRunner};

use crate::generator::{
    clear_reject_context, state_machine_sequence_strategy, StateMachineSequence,
};
use crate::{
    CorpusReport, CoverageReport, RunConfig, RunFailure, RunOutcome, RunResult, RunWarning,
    SessionDriver, TraceEntry,
};

use super::coverage::CoverageTracker;
use super::linting::{evaluate_run_phase, lint_phases};
use super::pre_run::run_pre_run_hook;
use super::prepare::prepare_run;
use super::result::{failure_result, finalize_state_machine_result, FailureContext};
use super::state_machine::{execute_state_machine_sequence, StateMachineExecution};

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
/// Runs apply default assertions that fail on MCP protocol errors, schema-invalid
/// responses, and (when configured) tool result error responses, plus any
/// user-supplied assertion rules.
///
/// Requires a multi-thread Tokio runtime; current-thread runtimes are rejected.
pub async fn run_with_session(
    session: &SessionDriver,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    let lint_phases = lint_phases(&config.lints);
    let prepared = match prepare_run(session, config, &lint_phases.list).await {
        Ok(prepared) => prepared,
        Err(result) => return result,
    };
    let prelude_trace = Rc::new(prepared.prelude_trace);
    let tools = prepared.tools;
    let warnings = prepared.warnings;
    let validators = prepared.validators;

    let assertions = config.assertions.clone();
    let warnings = Rc::new(RefCell::new(warnings));
    let aggregate_tools = tools.clone();
    let aggregate_tracker: Rc<RefCell<CoverageTracker<'_>>> =
        Rc::new(RefCell::new(CoverageTracker::new(
            &aggregate_tools,
            &config.state_machine,
            config.uncallable_limit,
        )));
    let last_trace: Rc<RefCell<Vec<TraceEntry>>> = Rc::new(RefCell::new(Vec::new()));
    last_trace.replace(prelude_trace.as_ref().clone());
    let last_coverage: Rc<RefCell<Option<CoverageReport>>> = Rc::new(RefCell::new(None));
    let last_corpus: Rc<RefCell<Option<CorpusReport>>> = Rc::new(RefCell::new(None));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new(String::new()),
        trace: Vec::new(),
        coverage: None,
        corpus: None,
        positive_error: false,
    }));
    let validators = Rc::new(validators);
    clear_reject_context();
    let handle = tokio::runtime::Handle::current();
    if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
        return failure_result(
            RunFailure::new("run_with_session requires a multi-thread Tokio runtime".to_string()),
            Vec::new(),
            None,
            warnings.borrow().clone(),
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
                warnings.borrow().clone(),
                None,
                None,
            )
        }
    };

    if options.cases == 0 {
        if let Err(failure) = run_pre_run_hook(config).await {
            return failure_result(
                failure,
                prelude_trace.as_ref().clone(),
                None,
                warnings.borrow().clone(),
                None,
                None,
            );
        }
    }

    let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runner.run(&strategy, {
            let assertions = assertions.clone();
            let last_trace = last_trace.clone();
            let last_coverage = last_coverage.clone();
            let last_corpus = last_corpus.clone();
            let last_failure = last_failure.clone();
            let validators = validators.clone();
            let aggregate_tracker = aggregate_tracker.clone();
            let response_lints = lint_phases.response.clone();
            let warnings = warnings.clone();
            let trace_sink = config.trace_sink.clone();
            let case_counter = Rc::new(RefCell::new(0u64));
            move |sequence| {
                let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    tokio::task::block_in_place(|| {
                        let last_coverage = last_coverage.clone();
                        let last_corpus = last_corpus.clone();
                        let case_counter = case_counter.clone();
                        handle.block_on(async {
                            if let Err(failure) = run_pre_run_hook(config).await {
                                return Err(FailureContext {
                                    failure,
                                    trace: Vec::new(),
                                    coverage: None,
                                    corpus: None,
                                    positive_error: true,
                                });
                            }
                            let mut tracker = CoverageTracker::new(
                                &tools,
                                &config.state_machine,
                                config.uncallable_limit,
                            );
                            let min_len = if config.lints.has_enabled("coverage") {
                                None
                            } else {
                                Some(*options.sequence_len.start())
                            };
                            let case_index = {
                                let mut counter = case_counter.borrow_mut();
                                let index = *counter;
                                *counter += 1;
                                index
                            };
                            let execution = StateMachineExecution {
                                session,
                                tools: &tools,
                                validators: &validators,
                                assertions: &assertions,
                                predicate: config.predicate.as_ref(),
                                min_len,
                                in_band_error_forbidden: config.in_band_error_forbidden,
                                full_trace: config.full_trace,
                                warnings: warnings.clone(),
                                response_lints: response_lints.clone(),
                                case_index,
                                trace_sink: trace_sink.clone(),
                            };
                            let result =
                                execute_state_machine_sequence(&sequence, &execution, &mut tracker)
                                    .await;
                            let (report, corpus_report) = {
                                let mut aggregate = aggregate_tracker.borrow_mut();
                                aggregate.merge_from(&tracker);
                                let mut report = aggregate.report();
                                apply_uncallable_traces(&mut report, config.show_uncallable);
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
                                    if failure.positive_error {
                                        failure.coverage = None;
                                    } else {
                                        failure.coverage = Some(report);
                                    }
                                    failure.corpus = corpus_report;
                                    Err(failure)
                                }
                            }
                        })
                    })
                }));
                let execution: Result<Vec<TraceEntry>, FailureContext> = match execution {
                    Ok(execution) => execution,
                    Err(payload) => {
                        let reason = panic_message(payload);
                        let failure = FailureContext {
                            failure: RunFailure {
                                reason: format!("run panicked: {reason}"),
                                code: Some("run_panicked".to_string()),
                                details: None,
                            },
                            trace: prelude_trace.as_ref().clone(),
                            coverage: None,
                            corpus: None,
                            positive_error: true,
                        };
                        last_failure.replace(failure.clone());
                        last_trace.replace(failure.trace.clone());
                        return Err(TestCaseError::fail(failure.failure.reason.clone()));
                    }
                };
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
        })
    }));
    let run_result = finalize_run_result(
        run_result,
        &last_trace,
        &last_failure,
        &last_coverage,
        &last_corpus,
        warnings.borrow().clone(),
    );
    let mut run_result = run_result;
    let outcome = run_result.outcome.clone();
    let coverage = last_coverage.borrow();
    let corpus = last_corpus.borrow();
    let context = crate::RunLintContext {
        coverage: coverage.as_ref(),
        corpus: corpus.as_ref(),
        coverage_allowlist: config.state_machine.coverage_allowlist.as_deref(),
        coverage_blocklist: config.state_machine.coverage_blocklist.as_deref(),
        outcome: &outcome,
    };
    if let Some(failure) = evaluate_run_phase(&lint_phases.run, &context, &mut run_result.warnings)
    {
        if matches!(outcome, RunOutcome::Success) {
            return failure_result(
                failure,
                Vec::new(),
                None,
                run_result.warnings.clone(),
                run_result.coverage.clone(),
                run_result.corpus.clone(),
            );
        }
    }
    run_result
}

fn apply_uncallable_traces(report: &mut CoverageReport, show_uncallable: bool) {
    if !show_uncallable {
        report.uncallable_traces.clear();
    }
}

fn finalize_run_result(
    run_result: std::thread::Result<Result<(), TestError<StateMachineSequence>>>,
    last_trace: &Rc<RefCell<Vec<TraceEntry>>>,
    last_failure: &Rc<RefCell<FailureContext>>,
    last_coverage: &Rc<RefCell<Option<CoverageReport>>>,
    last_corpus: &Rc<RefCell<Option<CorpusReport>>>,
    warnings: Vec<RunWarning>,
) -> RunResult {
    match run_result {
        Ok(run_result) => finalize_state_machine_result(
            run_result,
            last_trace,
            last_failure,
            last_coverage,
            last_corpus,
            &warnings,
        ),
        Err(payload) => run_result_from_panic(
            payload,
            last_trace.borrow().clone(),
            warnings,
            last_coverage.borrow().clone(),
            last_corpus.borrow().clone(),
        ),
    }
}

fn run_result_from_panic(
    payload: Box<dyn std::any::Any + Send>,
    trace: Vec<TraceEntry>,
    warnings: Vec<RunWarning>,
    coverage: Option<CoverageReport>,
    corpus: Option<CorpusReport>,
) -> RunResult {
    let reason = panic_message(payload);
    failure_result(
        RunFailure {
            reason: format!("run panicked: {reason}"),
            code: Some("run_panicked".to_string()),
            details: None,
        },
        trace,
        None,
        warnings,
        coverage,
        corpus,
    )
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.as_ref().downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.as_ref().downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_uncallable_traces, finalize_run_result, panic_message, run_result_from_panic,
        FailureContext,
    };
    use crate::generator::StateMachineSequence;
    use crate::{
        CallToolResult, CoverageReport, RunOutcome, RunWarning, ToolInvocation, UncallableToolCall,
    };
    use proptest::test_runner::TestError;
    use std::collections::BTreeMap;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn outcome_is_failure(outcome: &RunOutcome) -> bool {
        matches!(outcome, RunOutcome::Failure(_))
    }

    #[test]
    fn panic_message_handles_str() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(panic_message(payload), "boom");
    }

    #[test]
    fn panic_message_handles_string() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("boom".to_string());
        assert_eq!(panic_message(payload), "boom");
    }

    #[test]
    fn panic_message_handles_unknown() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(42_u64);
        assert_eq!(panic_message(payload), "unknown panic");
    }

    #[test]
    fn run_result_from_panic_builds_failure() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("boom");
        let result =
            run_result_from_panic(payload, Vec::new(), Vec::<RunWarning>::new(), None, None);
        let is_expected = matches!(
            result.outcome,
            RunOutcome::Failure(ref failure)
                if failure.reason.contains("run panicked: boom")
                    && failure.code.as_deref() == Some("run_panicked")
        );
        assert!(is_expected);
    }

    #[test]
    fn finalize_run_result_handles_panic() {
        let run_result: std::thread::Result<Result<(), TestError<StateMachineSequence>>> =
            Err(Box::new("boom"));
        let trace = Rc::new(RefCell::new(Vec::new()));
        let failure = Rc::new(RefCell::new(FailureContext {
            failure: crate::RunFailure::new(String::new()),
            trace: Vec::new(),
            coverage: None,
            corpus: None,
            positive_error: false,
        }));
        let coverage = Rc::new(RefCell::new(None));
        let corpus = Rc::new(RefCell::new(None));
        let result =
            finalize_run_result(run_result, &trace, &failure, &coverage, &corpus, Vec::new());
        assert!(outcome_is_failure(&result.outcome));
    }

    #[test]
    fn finalize_run_result_handles_success() {
        let run_result: std::thread::Result<Result<(), TestError<StateMachineSequence>>> =
            Ok(Ok(()));
        let trace = Rc::new(RefCell::new(Vec::new()));
        let failure = Rc::new(RefCell::new(FailureContext {
            failure: crate::RunFailure::new(String::new()),
            trace: Vec::new(),
            coverage: None,
            corpus: None,
            positive_error: false,
        }));
        let coverage = Rc::new(RefCell::new(None));
        let corpus = Rc::new(RefCell::new(None));
        let result =
            finalize_run_result(run_result, &trace, &failure, &coverage, &corpus, Vec::new());
        assert!(!outcome_is_failure(&result.outcome));
    }

    fn sample_report() -> CoverageReport {
        let mut uncallable_traces = BTreeMap::new();
        uncallable_traces.insert(
            "echo".to_string(),
            vec![UncallableToolCall {
                input: ToolInvocation {
                    name: "echo".to_string().into(),
                    arguments: None,
                },
                output: Some(CallToolResult::success(vec![])),
                error: None,
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            }],
        );
        CoverageReport {
            counts: BTreeMap::new(),
            failures: BTreeMap::new(),
            warnings: Vec::new(),
            uncallable_traces,
        }
    }

    #[test]
    fn apply_uncallable_traces_clears_when_disabled() {
        let mut report = sample_report();
        apply_uncallable_traces(&mut report, false);
        assert!(report.uncallable_traces.is_empty());
    }

    #[test]
    fn apply_uncallable_traces_retains_when_enabled() {
        let mut report = sample_report();
        apply_uncallable_traces(&mut report, true);
        assert_eq!(report.uncallable_traces.len(), 1);
    }
}
