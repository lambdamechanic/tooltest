use std::collections::BTreeMap;

use rmcp::model::CallToolResult;
use serde_json::Value as JsonValue;

use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, ToolInvocation, TraceEntry,
};

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

pub(super) fn apply_sequence_assertions(
    assertions: &AssertionSet,
    trace: &[TraceEntry],
) -> Option<String> {
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

pub(super) struct AssertionPayloads {
    pub(super) input: JsonValue,
    pub(super) output: JsonValue,
    pub(super) structured: JsonValue,
    pub(super) sequence: Option<JsonValue>,
}

pub(super) fn evaluate_checks(
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
