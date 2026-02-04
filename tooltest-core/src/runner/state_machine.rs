use std::collections::BTreeMap;
use std::collections::HashSet;

use crate::generator::{
    invocation_from_corpus_seeded, record_reject_context, PreparedTool, StateMachineSequence,
};
use crate::{AssertionSet, RunFailure, SessionDriver, ToolPredicate, TraceEntry};

use super::assertions::{
    apply_default_assertions, apply_response_assertions, apply_sequence_assertions,
    attach_failure_reason, attach_response,
};
use super::coverage::CoverageTracker;
use super::result::FailureContext;

pub(super) struct StateMachineExecution<'a> {
    pub(super) session: &'a SessionDriver,
    pub(super) tools: &'a [PreparedTool],
    pub(super) validators: &'a BTreeMap<String, jsonschema::Validator>,
    pub(super) assertions: &'a AssertionSet,
    pub(super) predicate: Option<&'a ToolPredicate>,
    pub(super) min_len: Option<usize>,
    pub(super) in_band_error_forbidden: bool,
    pub(super) full_trace: bool,
    pub(super) warnings: std::rc::Rc<std::cell::RefCell<Vec<crate::RunWarning>>>,
    pub(super) warned_missing_structured: std::rc::Rc<std::cell::RefCell<HashSet<String>>>,
    pub(super) case_index: u64,
    pub(super) trace_sink: Option<std::sync::Arc<dyn crate::TraceSink>>,
}

pub(super) async fn execute_state_machine_sequence(
    sequence: &StateMachineSequence,
    execution: &StateMachineExecution<'_>,
    tracker: &mut CoverageTracker<'_>,
) -> Result<Vec<TraceEntry>, FailureContext> {
    let mut trace = Vec::new();
    let mut full_trace = Vec::new();
    let mut invocation_count = 0usize;
    let record_trace = |trace: &[TraceEntry]| {
        if let Some(sink) = execution.trace_sink.as_ref() {
            sink.record(execution.case_index, trace);
        }
    };
    for seed in &sequence.seeds {
        let invocation = match invocation_from_corpus_seeded(
            execution.tools,
            execution.predicate,
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
                let failure_trace = if execution.full_trace {
                    full_trace.clone()
                } else {
                    trace.clone()
                };
                record_trace(&failure_trace);
                return Err(FailureContext {
                    failure: RunFailure::new(error.to_string()),
                    trace: failure_trace,
                    coverage: None,
                    corpus: None,
                    positive_error: true,
                });
            }
        };

        invocation_count += 1;
        trace.push(TraceEntry::tool_call(invocation.clone()));
        if execution.full_trace {
            full_trace.push(TraceEntry::tool_call(invocation.clone()));
        }
        let entry = match execution.session.send_tool_call(invocation.clone()).await {
            Ok(entry) => entry,
            Err(error) => {
                let reason = format!("session error: {error:?}");
                if execution.full_trace {
                    attach_failure_reason(&mut full_trace, reason.clone());
                    record_trace(&full_trace);
                    return Err(FailureContext {
                        failure: RunFailure::new(reason),
                        trace: full_trace.clone(),
                        coverage: None,
                        corpus: None,
                        positive_error: true,
                    });
                }
                attach_failure_reason(&mut trace, reason.clone());
                record_trace(&trace);
                return Err(FailureContext {
                    failure: RunFailure::new(reason),
                    trace: trace.clone(),
                    coverage: None,
                    corpus: None,
                    positive_error: true,
                });
            }
        };

        let (invocation, response) = entry.as_tool_call().expect("tool call trace entry");
        let invocation = invocation.clone();
        let response = response.expect("tool call response").clone();
        if execution.full_trace {
            let _ = full_trace.pop();
        }
        full_trace.push(entry);
        tracker.record_call(&invocation, &response);
        if response.is_error.unwrap_or(false) {
            tracker.record_failure(invocation.name.as_ref());
        } else {
            tracker.record_success(invocation.name.as_ref());
            tracker.mine_response(invocation.name.as_ref(), &response);
        }

        if let Some(reason) = apply_default_assertions(
            &invocation,
            &response,
            execution.validators,
            execution.in_band_error_forbidden,
            &mut execution.warnings.borrow_mut(),
            &mut execution.warned_missing_structured.borrow_mut(),
        ) {
            let positive_error = true;
            if execution.full_trace {
                attach_response(&mut full_trace, response.clone());
                attach_failure_reason(&mut full_trace, reason.clone());
                record_trace(&full_trace);
                return Err(FailureContext {
                    failure: RunFailure::new(reason),
                    trace: full_trace.clone(),
                    coverage: None,
                    corpus: None,
                    positive_error,
                });
            }
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            record_trace(&trace);
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace: trace.clone(),
                coverage: None,
                corpus: None,
                positive_error,
            });
        }

        if let Some(reason) =
            apply_response_assertions(execution.assertions, &invocation, &response)
        {
            if execution.full_trace {
                attach_response(&mut full_trace, response.clone());
                attach_failure_reason(&mut full_trace, reason.clone());
                record_trace(&full_trace);
                return Err(FailureContext {
                    failure: RunFailure::new(reason),
                    trace: full_trace.clone(),
                    coverage: None,
                    corpus: None,
                    positive_error: true,
                });
            }
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            record_trace(&trace);
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace: trace.clone(),
                coverage: None,
                corpus: None,
                positive_error: true,
            });
        }
    }

    if let Some(min_len) = execution.min_len {
        if invocation_count < min_len {
            let reason = format!(
                "state-machine generator failed to reach minimum sequence length ({min_len})"
            );
            if execution.full_trace {
                attach_failure_reason(&mut full_trace, reason.clone());
                record_trace(&full_trace);
                return Err(FailureContext {
                    failure: RunFailure::new(reason),
                    trace: full_trace.clone(),
                    coverage: None,
                    corpus: None,
                    positive_error: false,
                });
            }
            attach_failure_reason(&mut trace, reason.clone());
            record_trace(&trace);
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace: trace.clone(),
                coverage: None,
                corpus: None,
                positive_error: false,
            });
        }
    }

    if let Some(reason) = apply_sequence_assertions(execution.assertions, &full_trace) {
        if execution.full_trace {
            attach_failure_reason(&mut full_trace, reason.clone());
            record_trace(&full_trace);
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace: full_trace.clone(),
                coverage: None,
                corpus: None,
                positive_error: true,
            });
        }
        attach_failure_reason(&mut trace, reason.clone());
        record_trace(&trace);
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace: trace.clone(),
            coverage: None,
            corpus: None,
            positive_error: true,
        });
    }

    let selected = if execution.full_trace {
        full_trace
    } else {
        trace
    };
    if let Some(sink) = execution.trace_sink.as_ref() {
        sink.record(execution.case_index, &selected);
    }
    Ok(selected)
}
