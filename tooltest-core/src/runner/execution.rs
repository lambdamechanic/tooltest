use std::cell::RefCell;
use std::ops::RangeInclusive;
use std::process::Command;
use std::rc::Rc;

use proptest::test_runner::{Config as ProptestConfig, TestCaseError, TestRunner};
use serde_json::json;

use crate::generator::{clear_reject_context, state_machine_sequence_strategy};
use crate::{
    CorpusReport, CoverageReport, PreRunCommand, RunConfig, RunFailure, RunOutcome, RunResult,
    SessionDriver, TraceEntry,
};

use super::assertions::attach_failure_reason;
use super::coverage::{coverage_failure, CoverageTracker};
use super::prepare::prepare_run;
use super::result::{failure_result, finalize_state_machine_result, FailureContext};
use super::state_machine::execute_state_machine_sequence;

const PRE_RUN_COMMAND_INVALID: &str = "pre_run_command_invalid";
const PRE_RUN_COMMAND_FAILED: &str = "pre_run_command_failed";
const PRE_RUN_OUTPUT_LIMIT: usize = 4 * 1024;

fn run_pre_run_command(command: &PreRunCommand) -> Result<(), RunFailure> {
    let (program, args) = command.argv.split_first().ok_or_else(|| RunFailure {
        reason: "pre-run command argv is empty".to_string(),
        code: Some(PRE_RUN_COMMAND_INVALID.to_string()),
        details: Some(json!({
            "exit_code": null,
            "stdout": "",
            "stderr": "pre-run command argv is empty",
        })),
    })?;

    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| RunFailure {
            reason: format!("pre-run command failed to start: {error}"),
            code: Some(PRE_RUN_COMMAND_FAILED.to_string()),
            details: Some(json!({
                "exit_code": null,
                "stdout": "",
                "stderr": error.to_string(),
            })),
        })?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = truncate_output(&output.stdout);
    let stderr = truncate_output(&output.stderr);

    let code = output
        .status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    Err(RunFailure {
        reason: format!("pre-run command exited with code {code}"),
        code: Some(PRE_RUN_COMMAND_FAILED.to_string()),
        details: Some(json!({
            "exit_code": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
        })),
    })
}

fn truncate_output(output: &[u8]) -> String {
    if output.len() <= PRE_RUN_OUTPUT_LIMIT {
        return String::from_utf8_lossy(output).to_string();
    }
    let truncated = output[..PRE_RUN_OUTPUT_LIMIT].to_vec();
    let mut text = String::from_utf8_lossy(&truncated).to_string();
    text.push_str("...[truncated]");
    text
}

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
    let prepared = match prepare_run(session, config).await {
        Ok(prepared) => prepared,
        Err(result) => return result,
    };
    let prelude_trace = Rc::new(prepared.prelude_trace);
    let tools = prepared.tools;
    let warnings = prepared.warnings;
    let validators = prepared.validators;

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

    if options.cases == 0 {
        if let Some(command) = &config.pre_run_command {
            if let Err(failure) = run_pre_run_command(command) {
                return failure_result(
                    failure,
                    prelude_trace.as_ref().clone(),
                    None,
                    warnings.as_ref().clone(),
                    None,
                    None,
                );
            }
        }
    }

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
                        if let Some(command) = &config.pre_run_command {
                            if let Err(failure) = run_pre_run_command(command) {
                                return Err(FailureContext {
                                    failure,
                                    trace: Vec::new(),
                                    coverage: None,
                                    corpus: None,
                                });
                            }
                        }
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
