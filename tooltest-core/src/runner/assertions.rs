use std::collections::BTreeMap;

use rmcp::model::CallToolResult;
use serde_json::Value as JsonValue;

use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, ToolInvocation, TraceEntry,
};

fn evaluate_check(
    check: &AssertionCheck,
    payload: &JsonValue,
    tool_name: Option<&str>,
) -> Option<String> {
    let actual = match payload.pointer(&check.pointer) {
        Some(value) => value,
        None => return Some(format!("assertion pointer '{}' not found", check.pointer)),
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
    None
}

pub(super) fn apply_default_assertions(
    invocation: &ToolInvocation,
    response: &CallToolResult,
    validators: &BTreeMap<String, jsonschema::Validator>,
    in_band_error_forbidden: bool,
) -> Option<String> {
    if response.is_error.unwrap_or(false) && in_band_error_forbidden {
        return Some(format!(
            "tool '{}' returned an error response (isError=true), which is forbidden by configuration",
            invocation.name.as_ref()
        ));
    }

    let tool_name = invocation.name.as_ref();
    let validator = validators.get(tool_name)?;
    let structured = response.structured_content.as_ref()?;
    if let Err(error) = validator.validate(structured) {
        return Some(format!(
            "output schema violation for tool '{tool_name}': {error}"
        ));
    }
    None
}

pub(super) fn apply_response_assertions(
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
    let payloads = ResponseAssertionPayloads {
        input: input_payload,
        output: output_payload,
        structured: structured_payload,
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
        if let Some(reason) = evaluate_response_checks(
            &response_assertion.checks,
            &payloads,
            Some(invocation.name.as_ref()),
        ) {
            return Some(reason);
        }
    }

    None
}

pub(super) fn apply_sequence_assertions(
    assertions: &AssertionSet,
    trace: &[TraceEntry],
) -> Option<String> {
    if assertions.rules.is_empty() {
        return None;
    }

    let sequence_payload = serde_json::to_value(trace).unwrap_or(JsonValue::Null);

    for rule in &assertions.rules {
        let AssertionRule::Sequence(sequence_assertion) = rule else {
            continue;
        };
        if let Some(reason) = evaluate_sequence_checks(&sequence_assertion.checks, &sequence_payload)
        {
            return Some(reason);
        }
    }
    None
}

pub(super) fn attach_response(trace: &mut [TraceEntry], response: CallToolResult) {
    if let Some(TraceEntry::ToolCall { response: slot, .. }) = trace.last_mut() {
        *slot = Some(response);
    }
}

pub(super) fn attach_failure_reason(trace: &mut [TraceEntry], reason: String) {
    if let Some(TraceEntry::ToolCall { failure_reason, .. }) = trace.last_mut() {
        *failure_reason = Some(reason);
    }
}

pub(super) struct ResponseAssertionPayloads {
    pub(super) input: JsonValue,
    pub(super) output: JsonValue,
    pub(super) structured: JsonValue,
}

pub(super) fn evaluate_response_checks(
    checks: &[AssertionCheck],
    payloads: &ResponseAssertionPayloads,
    tool_name: Option<&str>,
) -> Option<String> {
    for check in checks {
        let payload = match &check.target {
            AssertionTarget::Input => &payloads.input,
            AssertionTarget::Output => &payloads.output,
            AssertionTarget::StructuredOutput => &payloads.structured,
            AssertionTarget::Sequence => {
                return Some("sequence target is only valid for sequence assertions".to_string());
            }
        };
        if let Some(reason) = evaluate_check(check, payload, tool_name) {
            return Some(reason);
        }
    }
    None
}

pub(super) fn evaluate_sequence_checks(
    checks: &[AssertionCheck],
    sequence_payload: &JsonValue,
) -> Option<String> {
    for check in checks {
        if !matches!(check.target, AssertionTarget::Sequence) {
            return Some("sequence assertions must target the sequence payload".to_string());
        }
        if let Some(reason) = evaluate_check(check, sequence_payload, None) {
            return Some(reason);
        }
    }
    None
}
