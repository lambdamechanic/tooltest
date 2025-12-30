use std::sync::Arc;

use rmcp::model::Tool;

use crate::output_schema::compile_output_schema;
use crate::{RunFailure, TraceEntry};

use super::{ToolValidationConfig, ToolValidationDecision, ToolValidationFn};

pub(super) fn apply_validators(
    config: &ToolValidationConfig,
    tool: &Tool,
    trace: &TraceEntry,
) -> Result<(), RunFailure> {
    for validator in &config.validators {
        match validator(tool, trace) {
            ToolValidationDecision::Accept => return Ok(()),
            ToolValidationDecision::Reject(failure) => return Err(failure),
            ToolValidationDecision::Defer => continue,
        }
    }
    Ok(())
}

pub(super) fn default_validators() -> Vec<ToolValidationFn> {
    vec![
        Arc::new(output_schema_validator),
        Arc::new(default_validator),
    ]
}

pub(super) fn output_schema_validator(tool: &Tool, trace: &TraceEntry) -> ToolValidationDecision {
    let Some(schema) = &tool.output_schema else {
        return ToolValidationDecision::Defer;
    };
    let Some((_invocation, response)) = trace.as_tool_call() else {
        return ToolValidationDecision::Defer;
    };
    let Some(response) = response else {
        return ToolValidationDecision::Defer;
    };
    if response.is_error == Some(true) {
        return ToolValidationDecision::Defer;
    }
    let Some(structured) = &response.structured_content else {
        return ToolValidationDecision::Reject(RunFailure::new(format!(
            "tool '{}' returned no structured_content for output schema",
            tool.name
        )));
    };
    let validator = match compile_output_schema(schema.as_ref()) {
        Ok(validator) => validator,
        Err(error) => {
            return ToolValidationDecision::Reject(RunFailure::new(format!(
                "failed to compile output schema for tool '{}': {error}",
                tool.name
            )));
        }
    };
    if let Err(error) = validator.validate(structured) {
        return ToolValidationDecision::Reject(RunFailure::new(format!(
            "tool '{}' output schema violations: {error}",
            tool.name
        )));
    }
    ToolValidationDecision::Defer
}

pub(super) fn default_validator(_tool: &Tool, trace: &TraceEntry) -> ToolValidationDecision {
    let Some((_invocation, response)) = trace.as_tool_call() else {
        return ToolValidationDecision::Defer;
    };
    let Some(response) = response else {
        return ToolValidationDecision::Defer;
    };
    if response.is_error == Some(true) {
        return ToolValidationDecision::Reject(RunFailure::new("tool returned error".to_string()));
    }
    ToolValidationDecision::Defer
}
