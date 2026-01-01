use std::cell::RefCell;
use std::rc::Rc;

use proptest::test_runner::TestError;

use crate::generator::{take_reject_context, StateMachineSequence};
use crate::{
    CorpusReport, CoverageReport, MinimizedSequence, RunFailure, RunOutcome, RunResult, RunWarning,
    ToolInvocation, TraceEntry,
};

#[derive(Clone, Debug)]
pub(super) struct FailureContext {
    pub(super) failure: RunFailure,
    pub(super) trace: Vec<TraceEntry>,
    pub(super) coverage: Option<CoverageReport>,
    pub(super) corpus: Option<CorpusReport>,
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
