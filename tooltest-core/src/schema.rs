use std::borrow::Cow;
use std::fmt;

use rmcp::model::{CallToolRequestParam, CallToolResult, JsonObject, ListToolsResult, Tool};
use serde_json::Value as JsonValue;

use crate::{SchemaConfig, SchemaVersion};

const SUPPORTED_SCHEMA_VERSION: &str = "2025-11-25";
/// Supported JSON Schema draft URL (2020-12) without a hash fragment.
const SUPPORTED_JSON_SCHEMA: &str = "https://json-schema.org/draft/2020-12/schema";
/// Supported JSON Schema draft URL (2020-12) with a hash fragment.
const SUPPORTED_JSON_SCHEMA_WITH_HASH: &str = "https://json-schema.org/draft/2020-12/schema#";

/// Errors produced while parsing MCP schema data.
#[derive(Debug)]
pub enum SchemaError {
    /// The requested schema version is unsupported.
    UnsupportedSchemaVersion(String),
    /// Failed to parse a tools/list response.
    InvalidListTools(String),
    /// Failed to parse a tools/call request payload.
    InvalidCallToolRequest(String),
    /// Failed to parse a tools/call response payload.
    InvalidCallToolResult(String),
    /// The tool schema payload is invalid.
    InvalidToolSchema {
        tool: String,
        field: String,
        reason: String,
    },
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported MCP schema version: {version}")
            }
            SchemaError::InvalidListTools(message) => write!(f, "invalid tools/list: {message}"),
            SchemaError::InvalidCallToolRequest(message) => {
                write!(f, "invalid tools/call request: {message}")
            }
            SchemaError::InvalidCallToolResult(message) => {
                write!(f, "invalid tools/call result: {message}")
            }
            SchemaError::InvalidToolSchema {
                tool,
                field,
                reason,
            } => {
                write!(
                    f,
                    "invalid schema for tool '{tool}' field '{field}': {reason}"
                )
            }
        }
    }
}

impl std::error::Error for SchemaError {}

/// Validate and parse a tools/list response payload.
pub fn parse_list_tools(
    payload: JsonValue,
    config: &SchemaConfig,
) -> Result<ListToolsResult, SchemaError> {
    ensure_supported_schema_version(config)?;
    let result: ListToolsResult = serde_json::from_value(payload)
        .map_err(|err| SchemaError::InvalidListTools(err.to_string()))?;
    for tool in &result.tools {
        validate_tool_schema(tool)?;
    }
    Ok(result)
}

/// Validate and parse a tools/call request payload.
pub fn parse_call_tool_request(
    payload: JsonValue,
    config: &SchemaConfig,
) -> Result<CallToolRequestParam, SchemaError> {
    ensure_supported_schema_version(config)?;
    serde_json::from_value(payload)
        .map_err(|err| SchemaError::InvalidCallToolRequest(err.to_string()))
}

/// Validate and parse a tools/call response payload.
pub fn parse_call_tool_result(
    payload: JsonValue,
    config: &SchemaConfig,
) -> Result<CallToolResult, SchemaError> {
    ensure_supported_schema_version(config)?;
    serde_json::from_value(payload)
        .map_err(|err| SchemaError::InvalidCallToolResult(err.to_string()))
}

fn ensure_supported_schema_version(config: &SchemaConfig) -> Result<(), SchemaError> {
    match &config.version {
        SchemaVersion::V2025_11_25 => Ok(()),
        SchemaVersion::Other(version) => {
            if version == SUPPORTED_SCHEMA_VERSION {
                Ok(())
            } else {
                Err(SchemaError::UnsupportedSchemaVersion(version.clone()))
            }
        }
    }
}

fn validate_tool_schema(tool: &Tool) -> Result<(), SchemaError> {
    validate_schema_object(
        tool.input_schema.as_ref(),
        tool.name.as_ref(),
        "inputSchema",
    )?;
    if let Some(output) = &tool.output_schema {
        validate_schema_object(output.as_ref(), tool.name.as_ref(), "outputSchema")?;
    }
    Ok(())
}

fn validate_schema_object(
    schema: &JsonObject,
    tool_name: &str,
    field: &str,
) -> Result<(), SchemaError> {
    let type_value = schema
        .get("type")
        .ok_or_else(|| invalid_tool_schema(tool_name, field, "missing type"))?;
    match type_value {
        JsonValue::String(value) if value == "object" => {}
        JsonValue::String(value) => {
            return Err(invalid_tool_schema(
                tool_name,
                field,
                &format!("type must be object, got {value}"),
            ))
        }
        _ => {
            return Err(invalid_tool_schema(
                tool_name,
                field,
                "type must be a string",
            ))
        }
    }

    if let Some(schema_value) = schema.get("$schema") {
        let schema_value = schema_value
            .as_str()
            .ok_or_else(|| invalid_tool_schema(tool_name, field, "$schema must be a string"))?;
        if schema_value != SUPPORTED_JSON_SCHEMA && schema_value != SUPPORTED_JSON_SCHEMA_WITH_HASH
        {
            return Err(invalid_tool_schema(
                tool_name,
                field,
                &format!(
                    "expected $schema to be one of [{SUPPORTED_JSON_SCHEMA}, {SUPPORTED_JSON_SCHEMA_WITH_HASH}], got: {schema_value}"
                ),
            ));
        }
    }

    if let Some(properties) = schema.get("properties") {
        if !properties.is_object() {
            return Err(invalid_tool_schema(
                tool_name,
                field,
                "properties must be an object",
            ));
        }
    }

    if let Some(required) = schema.get("required") {
        if let JsonValue::Array(values) = required {
            if values.iter().any(|value| !value.is_string()) {
                return Err(invalid_tool_schema(
                    tool_name,
                    field,
                    "required values must be strings",
                ));
            }
        } else {
            return Err(invalid_tool_schema(
                tool_name,
                field,
                "required must be an array",
            ));
        }
    }

    Ok(())
}

fn invalid_tool_schema(tool_name: &str, field: &str, reason: &str) -> SchemaError {
    SchemaError::InvalidToolSchema {
        tool: tool_name.to_string(),
        field: field.to_string(),
        reason: reason.to_string(),
    }
}

pub fn schema_version_label(version: &SchemaVersion) -> Cow<'_, str> {
    match version {
        SchemaVersion::V2025_11_25 => Cow::Borrowed(SUPPORTED_SCHEMA_VERSION),
        SchemaVersion::Other(value) => Cow::Borrowed(value),
    }
}
