use std::collections::BTreeMap;

use rmcp::model::{ListToolsResult, Tool};

use crate::output_schema::compile_output_schema;
use crate::schema::parse_list_tools;
use crate::SchemaConfig;

pub(super) fn build_output_validators(tools: &[Tool]) -> BTreeMap<String, jsonschema::Validator> {
    let mut validators = BTreeMap::new();
    for tool in tools {
        let Some(schema) = &tool.output_schema else {
            continue;
        };
        if let Ok(validator) = compile_output_schema(schema.as_ref()) {
            validators.insert(tool.name.to_string(), validator);
        }
    }
    validators
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
