use std::collections::BTreeMap;

use crate::{
    RunConfig, RunFailure, RunResult, RunWarning, RunWarningCode, SessionDriver, Tool, TraceEntry,
};

use super::pre_run::run_pre_run_hook;
use super::result::failure_result;
use super::schema::{build_output_validators, collect_schema_warnings, validate_tools};

pub(super) struct PreparedRun {
    pub(super) tools: Vec<Tool>,
    pub(super) warnings: Vec<RunWarning>,
    pub(super) validators: BTreeMap<String, jsonschema::Validator>,
    pub(super) prelude_trace: Vec<TraceEntry>,
}

pub(super) async fn prepare_run(
    session: &SessionDriver,
    config: &RunConfig,
) -> Result<PreparedRun, RunResult> {
    let prelude_trace = vec![TraceEntry::list_tools()];
    let tools = match session.list_tools().await {
        Ok(tools) => tools,
        Err(error) => {
            let reason = format!("failed to list tools: {error:?}");
            return Err(failure_result(
                RunFailure::new(reason.clone()),
                vec![TraceEntry::list_tools_with_failure(reason)],
                None,
                Vec::new(),
                None,
                None,
            ));
        }
    };
    if let Err(failure) = run_pre_run_hook(config).await {
        return Err(failure_result(
            failure,
            prelude_trace.clone(),
            None,
            Vec::new(),
            None,
            None,
        ));
    }

    let tools = match validate_tools(tools, &config.schema) {
        Ok(tools) => tools,
        Err(reason) => {
            return Err(failure_result(
                RunFailure::new(reason),
                prelude_trace.clone(),
                None,
                Vec::new(),
                None,
                None,
            ))
        }
    };
    let mut warnings = collect_schema_warnings(&tools);

    // Check max tool count limit
    if let Some(max_count) = config.max_tool_count {
        if tools.len() > max_count {
            let message = format!(
                "server registered {} tools, which exceeds the limit of {}",
                tools.len(),
                max_count
            );
            if config.max_tool_count_fail {
                return Err(failure_result(
                    RunFailure::new(message),
                    prelude_trace.clone(),
                    None,
                    warnings.clone(),
                    None,
                    None,
                ));
            }
            warnings.push(RunWarning {
                code: RunWarningCode::TooManyTools,
                message,
                tool: None,
            });
        }
    }

    let validators = match build_output_validators(&tools) {
        Ok(validators) => validators,
        Err(reason) => {
            return Err(failure_result(
                RunFailure::new(reason),
                prelude_trace.clone(),
                None,
                warnings.clone(),
                None,
                None,
            ))
        }
    };

    let original_count = tools.len();
    let tools = filter_tools(tools, config.tool_filter.as_ref());
    if tools.is_empty() {
        let reason = if original_count == 0 {
            "server returned no tools".to_string()
        } else {
            format!("all {original_count} tools were filtered out by the tool filter")
        };
        return Err(failure_result(
            RunFailure::new(format!("no eligible tools to generate ({reason})")),
            prelude_trace.clone(),
            None,
            warnings.clone(),
            None,
            None,
        ));
    }

    Ok(PreparedRun {
        tools,
        warnings,
        validators,
        prelude_trace,
    })
}

fn filter_tools(tools: Vec<Tool>, predicate: Option<&crate::ToolNamePredicate>) -> Vec<Tool> {
    let Some(predicate) = predicate else {
        return tools;
    };
    tools
        .into_iter()
        .filter(|tool| predicate(tool.name.as_ref()))
        .collect()
}
