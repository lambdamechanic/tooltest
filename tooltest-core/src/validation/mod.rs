//! Helpers for enumerating tools and validating tool behavior.

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::sync::Arc;

use crate::generator::invocation_strategy;
use crate::{RunConfig, RunFailure, SessionDriver, SessionError, TraceEntry};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use rmcp::model::Tool;

mod listing;
mod validators;

pub use listing::{list_tools_http, list_tools_stdio, list_tools_with_session, ListToolsError};

#[cfg(test)]
#[path = "../../tests/internal/validation_unit_tests.rs"]
mod tests;

#[cfg(test)]
use crate::SchemaError;
#[cfg(test)]
use crate::{HttpConfig, SchemaConfig, StdioConfig};
#[cfg(test)]
use listing::list_tools_with_connector;
#[cfg(test)]
use validators::{apply_validators, default_validator, output_schema_validator};

const DEFAULT_CASES_PER_TOOL: usize = 50;
const CASES_PER_TOOL_ENV: &str = "TOOLTEST_CASES_PER_TOOL";

/// Middleware decision returned by a tool validator.
#[derive(Clone, Debug)]
pub enum ToolValidationDecision {
    /// Accept the tool response and stop the validation chain.
    Accept,
    /// Reject the tool response with a failure.
    Reject(RunFailure),
    /// Defer to the next validator in the chain.
    Defer,
}

/// Callable used to validate a tool response.
pub type ToolValidationFn = Arc<dyn Fn(&Tool, &TraceEntry) -> ToolValidationDecision + Send + Sync>;

/// Configuration for bulk tool validation.
///
/// Defaults `cases_per_tool` from the `TOOLTEST_CASES_PER_TOOL` env var (minimum 1),
/// unless overridden with `with_cases_per_tool`.
///
/// ```no_run
/// use tooltest_core::{SessionDriver, StdioConfig, ToolValidationConfig, validate_tools};
///
/// # async fn run() {
/// let session = SessionDriver::connect_stdio(&StdioConfig::new("./my-mcp-server"))
///     .await
///     .expect("connect");
/// let config = ToolValidationConfig::new().with_cases_per_tool(5);
/// let summary = validate_tools(&session, &config, None)
///     .await
///     .expect("validate tools");
/// println!("validated {} tools", summary.tools.len());
/// # }
/// # tokio::runtime::Runtime::new().unwrap().block_on(run());
/// ```
#[derive(Clone)]
pub struct ToolValidationConfig {
    /// Run-level configuration and predicates.
    pub run: RunConfig,
    /// Number of cases to exercise per tool.
    pub cases_per_tool: usize,
    /// Validators invoked after each tool call.
    pub validators: Vec<ToolValidationFn>,
}

impl ToolValidationConfig {
    /// Creates a validation configuration with defaults.
    pub fn new() -> Self {
        Self {
            run: RunConfig::new(),
            cases_per_tool: default_cases_per_tool(),
            validators: validators::default_validators(),
        }
    }

    /// Sets the per-tool case count.
    pub fn with_cases_per_tool(mut self, cases_per_tool: usize) -> Self {
        self.cases_per_tool = cases_per_tool.max(1);
        self
    }

    /// Sets the run configuration used for validation.
    pub fn with_run_config(mut self, run: RunConfig) -> Self {
        self.run = run;
        self
    }

    /// Adds a response validator ahead of the defaults.
    pub fn with_validator(mut self, validator: ToolValidationFn) -> Self {
        self.validators.insert(0, validator);
        self
    }
}

impl Default for ToolValidationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of a bulk validation run.
#[derive(Clone, Debug)]
pub struct BulkToolValidationSummary {
    /// Tool names that were validated.
    pub tools: Vec<String>,
    /// Number of cases exercised per tool.
    pub cases_per_tool: usize,
}

/// Failure details for a tool validation run.
#[derive(Clone, Debug)]
pub struct ToolValidationFailure {
    /// The tool that failed validation.
    pub tool: String,
    /// Failure reason.
    pub failure: RunFailure,
    /// Trace entries for the minimized failing case.
    pub trace: Vec<TraceEntry>,
}

/// Errors emitted while validating tools.
#[derive(Debug)]
pub enum ToolValidationError {
    /// Failed to communicate with the MCP endpoint.
    Session(SessionError),
    /// No tools are available for validation.
    NoToolsAvailable,
    /// Requested tool names were not found.
    MissingTools { tools: Vec<String> },
    /// Tool invocation generation failed.
    Generation { tool: String, reason: String },
    /// A tool validation failed.
    ValidationFailed(ToolValidationFailure),
}

impl fmt::Display for ToolValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToolValidationError::Session(error) => write!(f, "session error: {error:?}"),
            ToolValidationError::NoToolsAvailable => write!(f, "no tools available for validation"),
            ToolValidationError::MissingTools { tools } => {
                write!(f, "missing tools: {}", tools.join(", "))
            }
            ToolValidationError::Generation { tool, reason } => {
                write!(f, "failed to generate invocation for '{tool}': {reason}")
            }
            ToolValidationError::ValidationFailed(failure) => write!(
                f,
                "tool '{}' failed validation: {}",
                failure.tool, failure.failure.reason
            ),
        }
    }
}

impl std::error::Error for ToolValidationError {}

impl From<SessionError> for ToolValidationError {
    fn from(error: SessionError) -> Self {
        ToolValidationError::Session(error)
    }
}

/// Validates tools by name, or all tools when no name list is provided.
///
/// ```no_run
/// use tooltest_core::{validate_tools, SessionDriver, ToolValidationConfig};
///
/// # async fn run() {
/// let config = ToolValidationConfig::new();
/// let session = SessionDriver::connect_http(&tooltest_core::HttpConfig {
///     url: "http://localhost:3000/mcp".into(),
///     auth_token: None,
/// })
/// .await
/// .expect("connect");
/// let summary = validate_tools(&session, &config, Some(&vec!["echo".into()]))
///     .await
///     .expect("validate tools");
/// println!("cases per tool: {}", summary.cases_per_tool);
/// # }
/// # tokio::runtime::Runtime::new().unwrap().block_on(run());
/// ```
pub async fn validate_tools(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool_names: Option<&[String]>,
) -> Result<BulkToolValidationSummary, ToolValidationError> {
    let tools = session.list_tools().await?;
    if tools.is_empty() {
        return Err(ToolValidationError::NoToolsAvailable);
    }

    let tools = select_tools(tools, tool_names)?;
    for tool in &tools {
        run_tool_cases(session, config, tool).await?;
    }

    Ok(BulkToolValidationSummary {
        tools: tools.iter().map(|tool| tool.name.to_string()).collect(),
        cases_per_tool: config.cases_per_tool.max(1),
    })
}

/// Validates a single tool definition.
pub async fn validate_tool(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool: &Tool,
) -> Result<(), ToolValidationError> {
    run_tool_cases(session, config, tool).await
}

#[allow(clippy::result_large_err)]
fn select_tools(
    tools: Vec<Tool>,
    tool_names: Option<&[String]>,
) -> Result<Vec<Tool>, ToolValidationError> {
    let Some(tool_names) = tool_names else {
        return Ok(tools);
    };

    let tool_map: HashMap<String, Tool> = tools
        .into_iter()
        .map(|tool| (tool.name.to_string(), tool))
        .collect();

    let mut missing = Vec::new();
    let mut selected = Vec::new();
    for name in tool_names {
        if let Some(tool) = tool_map.get(name) {
            selected.push(tool.clone());
        } else {
            missing.push(name.clone());
        }
    }

    if !missing.is_empty() {
        return Err(ToolValidationError::MissingTools { tools: missing });
    }

    Ok(selected)
}

async fn run_tool_cases(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool: &Tool,
) -> Result<(), ToolValidationError> {
    let strategy = invocation_strategy(std::slice::from_ref(tool), config.run.predicate.as_ref())
        .map_err(|error| ToolValidationError::Generation {
        tool: tool.name.to_string(),
        reason: error.to_string(),
    })?;

    let cases = config.cases_per_tool.max(1);
    let mut runner = TestRunner::default();

    for _ in 0..cases {
        let tree =
            strategy
                .new_tree(&mut runner)
                .map_err(|reason| ToolValidationError::Generation {
                    tool: tool.name.to_string(),
                    reason: reason.to_string(),
                })?;

        if run_invocation(session, config, tool, tree.current())
            .await?
            .is_some()
        {
            let minimized = shrink_failure(session, config, tool, tree).await?;
            return Err(ToolValidationError::ValidationFailed(minimized));
        }
    }

    Ok(())
}

async fn run_invocation(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool: &Tool,
    invocation: crate::ToolInvocation,
) -> Result<Option<ToolValidationFailure>, ToolValidationError> {
    let trace = session.send_tool_call(invocation).await?;
    if let Err(failure) = validators::apply_validators(config, tool, &trace) {
        return Ok(Some(ToolValidationFailure {
            tool: tool.name.to_string(),
            failure,
            trace: vec![trace],
        }));
    }
    Ok(None)
}

async fn shrink_failure<T>(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool: &Tool,
    mut tree: T,
) -> Result<ToolValidationFailure, ToolValidationError>
where
    T: ValueTree<Value = crate::ToolInvocation>,
{
    let Some(mut best) = run_invocation(session, config, tool, tree.current()).await? else {
        return Err(ToolValidationError::Generation {
            tool: tool.name.to_string(),
            reason: "expected failing case to shrink".to_string(),
        });
    };

    loop {
        if !tree.simplify() {
            break;
        }

        match run_invocation(session, config, tool, tree.current()).await? {
            Some(failure) => {
                best = failure;
                continue;
            }
            None => {
                let mut restored = false;
                while tree.complicate() {
                    if let Some(failure) =
                        run_invocation(session, config, tool, tree.current()).await?
                    {
                        best = failure;
                        restored = true;
                        break;
                    }
                }
                if !restored {
                    break;
                }
            }
        }
    }

    Ok(best)
}

fn default_cases_per_tool() -> usize {
    match env::var(CASES_PER_TOOL_ENV) {
        Ok(value) => value
            .parse::<usize>()
            .ok()
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_CASES_PER_TOOL),
        Err(_) => DEFAULT_CASES_PER_TOOL,
    }
}
