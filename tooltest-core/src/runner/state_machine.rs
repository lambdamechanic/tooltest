use std::collections::BTreeMap;

use rmcp::model::Tool;

use crate::generator::{
    invocation_from_corpus_seeded, record_reject_context, StateMachineSequence,
};
use crate::{AssertionSet, RunFailure, SessionDriver, ToolPredicate, TraceEntry};

use super::assertions::{
    apply_default_assertions, apply_response_assertions, apply_sequence_assertions,
    attach_failure_reason, attach_response,
};
use super::coverage::CoverageTracker;
use super::result::FailureContext;

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_state_machine_sequence(
    session: &SessionDriver,
    tools: &[Tool],
    validators: &BTreeMap<String, jsonschema::Validator>,
    assertions: &AssertionSet,
    sequence: &StateMachineSequence,
    tracker: &mut CoverageTracker<'_>,
    predicate: Option<&ToolPredicate>,
    min_len: Option<usize>,
    in_band_error_forbidden: bool,
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

        if let Some(reason) =
            apply_default_assertions(&invocation, &response, validators, in_band_error_forbidden)
        {
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
