use std::collections::BTreeMap;

use crate::output_schema::compile_output_schema;
use crate::schema::parse_list_tools;
use crate::{JsonObject, RunWarning, RunWarningCode, SchemaConfig};
use rmcp::model::{ListToolsResult, Tool};

pub(super) fn collect_schema_warnings(tools: &[Tool]) -> Vec<RunWarning> {
    let mut warnings = Vec::new();
    for tool in tools {
        collect_schema_keyword_warnings(
            tool,
            "input schema",
            tool.input_schema.as_ref(),
            &mut warnings,
        );
        if let Some(schema) = tool.output_schema.as_ref() {
            collect_schema_keyword_warnings(tool, "output schema", schema.as_ref(), &mut warnings);
        }
    }
    warnings
}

pub(super) fn collect_schema_keyword_warnings(
    tool: &Tool,
    schema_label: &str,
    schema: &JsonObject,
    warnings: &mut Vec<RunWarning>,
) {
    if !schema.contains_key("$defs") {
        return;
    }
    let schema_id = schema
        .get("$schema")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if schema_id.contains("draft-07")
        || schema_id.contains("draft-06")
        || schema_id.contains("draft-04")
    {
        warnings.push(RunWarning {
            code: RunWarningCode::SchemaUnsupportedKeyword,
            message: format!(
                "tool '{}' {schema_label} declares {schema_id} but uses '$defs'; draft-07 and earlier use 'definitions'",
                tool.name
            ),
            tool: Some(tool.name.to_string()),
        });
    }
}

pub(super) fn build_output_validators(
    tools: &[Tool],
) -> Result<BTreeMap<String, jsonschema::Validator>, String> {
    let mut validators = BTreeMap::new();
    for tool in tools {
        let Some(schema) = &tool.output_schema else {
            continue;
        };
        let validator = compile_output_schema(schema.as_ref()).map_err(|error| {
            format!(
                "failed to compile output schema for tool '{}': {error}",
                tool.name.as_ref()
            )
        })?;
        validators.insert(tool.name.to_string(), validator);
    }
    Ok(validators)
}

pub(super) fn validate_tools(tools: Vec<Tool>, config: &SchemaConfig) -> Result<Vec<Tool>, String> {
    let list_tools = ListToolsResult {
        tools,
        next_cursor: None,
        meta: None,
    };
    let payload = serde_json::to_value(&list_tools).expect("list tools serialize");
    let parsed = parse_list_tools(payload, config).map_err(|error| error.to_string())?;
    Ok(parsed.tools)
}
