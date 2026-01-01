use std::collections::BTreeMap;

use crate::{AssertionSet, RunFailure, SessionDriver, ToolInvocation, TraceEntry};

use super::assertions::{
    apply_default_assertions, apply_response_assertions, apply_sequence_assertions,
    attach_failure_reason, attach_response,
};
#[cfg(test)]
use super::coverage::CoverageTracker;
use super::result::FailureContext;

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
