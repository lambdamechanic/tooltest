use std::collections::BTreeMap;

use crate::generator::{prepare_tools, PreparedTool};
use crate::{
    lint::ListLintContext, RunConfig, RunFailure, RunResult, RunWarning, SessionDriver, Tool,
    TraceEntry,
};

use super::linting::evaluate_list_phase;
use super::pre_run::run_pre_run_hook;
use super::result::failure_result;
use super::schema::{build_output_validators, collect_schema_warnings, validate_tools};

pub(super) struct PreparedRun {
    pub(super) tools: Vec<PreparedTool>,
    pub(super) warnings: Vec<RunWarning>,
    pub(super) validators: BTreeMap<String, jsonschema::Validator>,
    pub(super) prelude_trace: Vec<TraceEntry>,
}

pub(super) async fn prepare_run(
    session: &SessionDriver,
    config: &RunConfig,
    list_lints: &[std::sync::Arc<dyn crate::LintRule>],
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
    if let Some(failure) = evaluate_list_phase(
        list_lints,
        &ListLintContext { tools: &tools },
        &mut warnings,
    ) {
        return Err(failure_result(
            failure,
            prelude_trace.clone(),
            None,
            warnings,
            None,
            None,
        ));
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

    let tools = prepare_tools(tools);

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
