use std::collections::{BTreeMap, HashSet};
use std::ops::RangeInclusive;
use std::sync::Arc;

use reqwest::Url;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    HttpConfig, PreRunHook, RunConfig, RunnerOptions, StateMachineConfig, StdioConfig,
    ToolNamePredicate, ToolPredicate,
};

fn default_cases() -> u32 {
    32
}

fn default_min_sequence_len() -> usize {
    1
}

fn default_max_sequence_len() -> usize {
    3
}

fn default_uncallable_limit() -> usize {
    1
}

/// Shared tooltest input type for CLI and MCP modes.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TooltestInput {
    /// Target MCP transport configuration.
    pub target: TooltestTarget,
    /// Number of proptest cases to execute.
    #[serde(default = "default_cases")]
    pub cases: u32,
    /// Minimum sequence length per generated run.
    #[serde(default = "default_min_sequence_len")]
    pub min_sequence_len: usize,
    /// Maximum sequence length per generated run.
    #[serde(default = "default_max_sequence_len")]
    pub max_sequence_len: usize,
    /// Allow schema-based generation when corpus lacks required values.
    #[serde(default)]
    pub lenient_sourcing: bool,
    /// Mine whitespace-delimited text tokens into the state corpus.
    #[serde(default)]
    pub mine_text: bool,
    /// Dump the final state-machine corpus after the run completes.
    #[serde(default)]
    pub dump_corpus: bool,
    /// Log newly mined corpus values after each tool response.
    #[serde(default)]
    pub log_corpus_deltas: bool,
    /// Disable schema-based generation when corpus lacks required values.
    #[serde(default)]
    pub no_lenient_sourcing: bool,
    /// State-machine config overrides.
    #[serde(default)]
    pub state_machine_config: Option<StateMachineConfig>,
    /// Allowlist tool names eligible for invocation generation.
    #[serde(default)]
    pub tool_allowlist: Vec<String>,
    /// Blocklist tool names excluded from invocation generation.
    #[serde(default)]
    pub tool_blocklist: Vec<String>,
    /// Fail the run when a tool result reports `isError = true`.
    #[serde(default)]
    pub in_band_error_forbidden: bool,
    /// Pre-run hook configuration.
    #[serde(default)]
    pub pre_run_hook: Option<TooltestPreRunHook>,
    /// Include tool responses in the trace output.
    #[serde(default)]
    pub full_trace: bool,
    /// Include uncallable tool traces when coverage validation fails.
    #[serde(default)]
    pub show_uncallable: bool,
    /// Number of calls per tool to include in uncallable traces.
    #[serde(default = "default_uncallable_limit")]
    pub uncallable_limit: usize,
}

impl TooltestInput {
    /// Validates the input to match CLI semantics.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_run_config()?;
        build_sequence_len(self.min_sequence_len, self.max_sequence_len)?;
        Ok(())
    }

    /// Builds the target configuration for the run.
    pub fn to_target_config(&self) -> Result<TooltestTargetConfig, String> {
        self.target.validate()?;
        self.target.to_config()
    }

    /// Builds the run configuration for the run.
    pub fn to_run_config(&self) -> Result<RunConfig, String> {
        self.validate_run_config()?;
        let mut state_machine = self.state_machine_config.clone().unwrap_or_default();
        if self.lenient_sourcing {
            state_machine.lenient_sourcing = true;
        } else if self.no_lenient_sourcing {
            state_machine.lenient_sourcing = false;
        }
        if self.mine_text {
            state_machine.mine_text = true;
        }
        if self.dump_corpus {
            state_machine.dump_corpus = true;
        }
        if self.log_corpus_deltas {
            state_machine.log_corpus_deltas = true;
        }

        let mut run_config = RunConfig::new()
            .with_state_machine(state_machine)
            .with_full_trace(self.full_trace)
            .with_show_uncallable(self.show_uncallable)
            .with_uncallable_limit(self.uncallable_limit);

        if let Some(hook) = self.pre_run_hook.as_ref() {
            run_config = run_config.with_pre_run_hook(hook.to_pre_run_hook());
        }
        if self.in_band_error_forbidden {
            run_config = run_config.with_in_band_error_forbidden(true);
        }
        if let Some(filters) = build_tool_filters(&self.tool_allowlist, &self.tool_blocklist) {
            run_config = run_config
                .with_predicate(filters.predicate)
                .with_tool_filter(filters.name_predicate);
        }

        Ok(run_config)
    }

    /// Builds the runner options for the run.
    pub fn to_runner_options(&self) -> Result<RunnerOptions, String> {
        let sequence_len = build_sequence_len(self.min_sequence_len, self.max_sequence_len)?;
        Ok(RunnerOptions {
            cases: self.cases,
            sequence_len,
        })
    }

    /// Builds the target configuration, run configuration, and runner options together.
    pub fn to_configs(&self) -> Result<TooltestRunConfig, String> {
        let target = self.to_target_config()?;
        let run_config = self.to_run_config();
        let runner_options = self.to_runner_options();
        match (run_config, runner_options) {
            (Ok(run_config), Ok(runner_options)) => Ok(TooltestRunConfig {
                target,
                run_config,
                runner_options,
            }),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }

    fn validate_run_config(&self) -> Result<(), String> {
        if self.uncallable_limit < 1 {
            return Err("uncallable-limit must be at least 1".to_string());
        }
        if self.lenient_sourcing && self.no_lenient_sourcing {
            return Err("lenient-sourcing conflicts with no-lenient-sourcing".to_string());
        }
        self.target.validate()?;
        Ok(())
    }
}

/// Target configuration input wrapper.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", untagged)]
pub enum TooltestTarget {
    /// Stdio transport configuration.
    Stdio(TooltestTargetStdio),
    /// HTTP transport configuration.
    Http(TooltestTargetHttp),
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TooltestTargetStdio {
    /// Stdio transport configuration.
    pub stdio: TooltestStdioTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TooltestTargetHttp {
    /// HTTP transport configuration.
    pub http: TooltestHttpTarget,
}

impl TooltestTarget {
    fn validate(&self) -> Result<(), String> {
        match self {
            TooltestTarget::Stdio(wrapper) => {
                if wrapper.stdio.command.trim().is_empty() {
                    return Err("stdio command must not be empty".to_string());
                }
                Ok(())
            }
            TooltestTarget::Http(wrapper) => validate_http_url(&wrapper.http.url),
        }
    }

    fn to_config(&self) -> Result<TooltestTargetConfig, String> {
        match self {
            TooltestTarget::Stdio(wrapper) => {
                Ok(TooltestTargetConfig::Stdio(wrapper.stdio.to_config()))
            }
            TooltestTarget::Http(wrapper) => {
                validate_http_url(&wrapper.http.url)?;
                Ok(TooltestTargetConfig::Http(wrapper.http.to_config()))
            }
        }
    }
}

/// Stdio transport input configuration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TooltestStdioTarget {
    /// Command to execute for the MCP server.
    #[schemars(length(min = 1))]
    pub command: String,
    /// Command-line arguments passed to the MCP server.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables to add or override for the MCP process.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Optional working directory for the MCP process.
    #[serde(default)]
    pub cwd: Option<String>,
}

impl TooltestStdioTarget {
    fn to_config(&self) -> StdioConfig {
        StdioConfig {
            command: self.command.clone(),
            args: self.args.clone(),
            env: self.env.clone(),
            cwd: self.cwd.clone(),
        }
    }
}

/// HTTP transport input configuration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TooltestHttpTarget {
    /// MCP endpoint URL.
    #[schemars(regex(
        pattern = r"^https?://[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*(?::[0-9]{1,5})?(?:/[^\s]*)?$"
    ))]
    pub url: String,
    /// Authorization bearer token.
    #[serde(default)]
    pub auth_token: Option<String>,
}

impl TooltestHttpTarget {
    fn to_config(&self) -> HttpConfig {
        HttpConfig {
            url: self.url.clone(),
            auth_token: self.auth_token.clone(),
        }
    }
}

/// Pre-run hook input configuration.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TooltestPreRunHook {
    /// Shell command string to execute before each run and validation.
    pub command: String,
    /// Environment variables to add or override for the hook process.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Optional working directory for the hook process.
    #[serde(default)]
    pub cwd: Option<String>,
}

impl TooltestPreRunHook {
    fn to_pre_run_hook(&self) -> PreRunHook {
        PreRunHook {
            command: self.command.clone(),
            env: self.env.clone(),
            cwd: self.cwd.clone(),
        }
    }
}

/// Target configuration for a tooltest run.
#[derive(Debug)]
pub enum TooltestTargetConfig {
    /// Stdio transport configuration.
    Stdio(StdioConfig),
    /// HTTP transport configuration.
    Http(HttpConfig),
}

/// Combined configuration output from shared tooltest input.
#[derive(Debug)]
pub struct TooltestRunConfig {
    /// Target transport configuration.
    pub target: TooltestTargetConfig,
    /// Run configuration.
    pub run_config: RunConfig,
    /// Runner options.
    pub runner_options: RunnerOptions,
}

struct ToolFilters {
    predicate: ToolPredicate,
    name_predicate: ToolNamePredicate,
}

fn build_tool_filters(allowlist: &[String], blocklist: &[String]) -> Option<ToolFilters> {
    if allowlist.is_empty() && blocklist.is_empty() {
        return None;
    }
    let allowlist =
        (!allowlist.is_empty()).then(|| allowlist.iter().cloned().collect::<HashSet<_>>());
    let blocklist =
        (!blocklist.is_empty()).then(|| blocklist.iter().cloned().collect::<HashSet<_>>());
    let name_predicate: ToolNamePredicate = Arc::new(move |tool_name| {
        if let Some(allowlist) = allowlist.as_ref() {
            if !allowlist.contains(tool_name) {
                return false;
            }
        }
        if let Some(blocklist) = blocklist.as_ref() {
            if blocklist.contains(tool_name) {
                return false;
            }
        }
        true
    });
    let predicate_name = Arc::clone(&name_predicate);
    let predicate: ToolPredicate = Arc::new(move |tool_name, _input| predicate_name(tool_name));
    Some(ToolFilters {
        predicate,
        name_predicate,
    })
}

fn build_sequence_len(min_len: usize, max_len: usize) -> Result<RangeInclusive<usize>, String> {
    if min_len == 0 {
        return Err("min-sequence-len must be at least 1".to_string());
    }
    if min_len > max_len {
        return Err("min-sequence-len must be <= max-sequence-len".to_string());
    }
    Ok(min_len..=max_len)
}

fn validate_http_url(url: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|error| format!("invalid http url '{url}': {error}"))?;
    if !parsed.has_host() {
        return Err(format!("invalid http url '{url}': missing host"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_validate_rejects_empty_command() {
        let target = TooltestTarget::Stdio(TooltestTargetStdio {
            stdio: TooltestStdioTarget {
                command: "  ".to_string(),
                args: Vec::new(),
                env: BTreeMap::new(),
                cwd: None,
            },
        });
        let error = target.validate().unwrap_err();
        assert!(error.contains("stdio command"));
    }

    #[test]
    fn target_to_config_rejects_invalid_http_url() {
        let target = TooltestTarget::Http(TooltestTargetHttp {
            http: TooltestHttpTarget {
                url: "localhost:8080/mcp".to_string(),
                auth_token: None,
            },
        });
        let error = target.to_config().unwrap_err();
        assert!(error.contains("invalid http url"));
    }
}
