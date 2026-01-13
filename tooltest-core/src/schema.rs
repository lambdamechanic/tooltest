use std::borrow::Cow;
use std::fmt;
use std::sync::OnceLock;

use jsonschema::{draft202012, Validator};
use rmcp::model::{CallToolRequestParam, CallToolResult, ListToolsResult};
use serde_json::Value as JsonValue;

use crate::{SchemaConfig, SchemaVersion};

const SUPPORTED_SCHEMA_VERSION: &str = "2025-11-25";
const DEFAULT_SCHEMA_ID: &str = "https://json-schema.org/draft/2020-12/schema";
// Source: https://github.com/modelcontextprotocol/specification/tree/main/schema/2025-11-25
// Update: run `scripts/update-mcp-schema.sh 2025-11-25`.
const MCP_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/mcp-schema-2025-11-25.json"
));
static LIST_TOOLS_VALIDATOR: OnceLock<Validator> = OnceLock::new();
static CALL_TOOL_REQUEST_VALIDATOR: OnceLock<Validator> = OnceLock::new();
/// Errors produced while parsing MCP schema data.
#[derive(Debug)]
pub enum SchemaError {
    /// Failed to parse a tools/list response.
    InvalidListTools(String),
    /// Failed to parse a tools/call request payload.
    InvalidCallToolRequest(String),
    /// Failed to parse a tools/call response payload.
    InvalidCallToolResult(String),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::InvalidListTools(message) => write!(f, "invalid tools/list: {message}"),
            SchemaError::InvalidCallToolRequest(message) => {
                write!(f, "invalid tools/call request: {message}")
            }
            SchemaError::InvalidCallToolResult(message) => {
                write!(f, "invalid tools/call result: {message}")
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
    let _ = config;
    validate_list_tools(&payload)?;
    parse_list_tools_payload(payload)
}

/// Validate and parse a tools/call request payload.
pub fn parse_call_tool_request(
    payload: JsonValue,
    config: &SchemaConfig,
) -> Result<CallToolRequestParam, SchemaError> {
    let _ = config;
    validate_call_tool_request(&payload)?;
    parse_call_tool_request_payload(payload)
}

/// Validate and parse a tools/call response payload.
pub fn parse_call_tool_result(
    payload: JsonValue,
    config: &SchemaConfig,
) -> Result<CallToolResult, SchemaError> {
    let _ = config;
    serde_json::from_value(payload)
        .map_err(|err| SchemaError::InvalidCallToolResult(err.to_string()))
}

#[inline(never)]
fn validate_list_tools(payload: &JsonValue) -> Result<(), SchemaError> {
    let validator = list_tools_validator();
    if let Err(error) = validator.validate(payload) {
        return Err(SchemaError::InvalidListTools(error.to_string()));
    }
    Ok(())
}

#[inline(never)]
fn validate_call_tool_request(payload: &JsonValue) -> Result<(), SchemaError> {
    let validator = call_tool_request_validator();
    if let Err(error) = validator.validate(payload) {
        return Err(SchemaError::InvalidCallToolRequest(error.to_string()));
    }
    Ok(())
}

fn parse_list_tools_payload(payload: JsonValue) -> Result<ListToolsResult, SchemaError> {
    match serde_json::from_value(payload) {
        Ok(result) => Ok(result),
        Err(err) => Err(SchemaError::InvalidListTools(err.to_string())),
    }
}

fn parse_call_tool_request_payload(
    payload: JsonValue,
) -> Result<CallToolRequestParam, SchemaError> {
    match serde_json::from_value(payload) {
        Ok(result) => Ok(result),
        Err(err) => Err(SchemaError::InvalidCallToolRequest(err.to_string())),
    }
}

#[inline(never)]
fn list_tools_validator() -> &'static Validator {
    if let Some(validator) = LIST_TOOLS_VALIDATOR.get() {
        return validator;
    }
    let validator =
        build_validator_for_def("ListToolsResult").expect("list tools validator compiles");
    let _ = LIST_TOOLS_VALIDATOR.set(validator);
    LIST_TOOLS_VALIDATOR
        .get()
        .expect("list tools validator initialized")
}

#[inline(never)]
fn call_tool_request_validator() -> &'static Validator {
    if let Some(validator) = CALL_TOOL_REQUEST_VALIDATOR.get() {
        return validator;
    }
    let validator = build_validator_for_def("CallToolRequestParams")
        .expect("call tool request validator compiles");
    let _ = CALL_TOOL_REQUEST_VALIDATOR.set(validator);
    CALL_TOOL_REQUEST_VALIDATOR
        .get()
        .expect("call tool request validator initialized")
}

#[inline(never)]
fn build_validator_for_def(def_name: &str) -> Result<Validator, String> {
    let schema: JsonValue = serde_json::from_str(MCP_SCHEMA).expect("MCP schema JSON parses");
    let defs = schema
        .get("$defs")
        .cloned()
        .expect("MCP schema defines $defs");
    let schema_id = schema_id_for(&schema);
    let list_tools_schema = serde_json::json!({
        "$schema": schema_id,
        "$defs": defs,
        "$ref": format!("#/$defs/{def_name}")
    });
    draft202012::new(&list_tools_schema)
        .map_err(|err| format!("failed to compile MCP schema: {err}"))
}

fn schema_id_for(schema: &JsonValue) -> JsonValue {
    schema
        .get("$schema")
        .cloned()
        .unwrap_or_else(|| JsonValue::String(DEFAULT_SCHEMA_ID.to_string()))
}

pub fn schema_version_label(version: &SchemaVersion) -> Cow<'_, str> {
    match version {
        SchemaVersion::V2025_11_25 => Cow::Borrowed(SUPPORTED_SCHEMA_VERSION),
        SchemaVersion::Other(value) => Cow::Borrowed(value),
    }
}

#[cfg(test)]
#[path = "../tests/internal/schema_unit_tests.rs"]
mod tests;
