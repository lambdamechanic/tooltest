use std::collections::BTreeMap;
use std::fs;
use std::ops::RangeInclusive;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tooltest_core::{
    CoverageWarningReason, GeneratorMode, HttpConfig, RunConfig, RunOutcome, RunResult, RunWarning,
    RunWarningCode, RunnerOptions, StateMachineConfig, StdioConfig,
};

#[derive(Parser)]
#[command(name = "tooltest", version, about = "CLI wrapper for tooltest-core")]
pub struct Cli {
    /// Number of proptest cases to execute.
    #[arg(long, default_value_t = 32)]
    pub cases: u32,
    /// Minimum sequence length per generated run.
    #[arg(long, default_value_t = 1)]
    pub min_sequence_len: usize,
    /// Maximum sequence length per generated run.
    #[arg(long, default_value_t = 3)]
    pub max_sequence_len: usize,
    /// Generator mode for sequence synthesis.
    #[arg(long, value_enum, default_value_t = GeneratorModeArg::Legacy)]
    pub generator_mode: GeneratorModeArg,
    /// Allow schema-based generation when corpus lacks required values.
    #[arg(long)]
    pub lenient_sourcing: bool,
    /// Disable schema-based generation when corpus lacks required values.
    #[arg(long, conflicts_with = "lenient_sourcing")]
    pub no_lenient_sourcing: bool,
    /// State-machine config as inline JSON or @path to a JSON file.
    #[arg(long, value_name = "JSON|@PATH")]
    pub state_machine_config: Option<String>,
    /// Emit JSON output instead of human-readable output.
    #[arg(long)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum GeneratorModeArg {
    Legacy,
    StateMachine,
}

impl From<GeneratorModeArg> for GeneratorMode {
    fn from(mode: GeneratorModeArg) -> Self {
        match mode {
            GeneratorModeArg::Legacy => GeneratorMode::Legacy,
            GeneratorModeArg::StateMachine => GeneratorMode::StateMachine,
        }
    }
}

#[derive(Deserialize)]
struct StateMachineConfigInput {
    #[serde(default)]
    seed_numbers: Vec<serde_json::Number>,
    #[serde(default)]
    seed_strings: Vec<String>,
    #[serde(default)]
    lenient_sourcing: bool,
    #[serde(default)]
    coverage_allowlist: Option<Vec<String>>,
    #[serde(default)]
    coverage_blocklist: Option<Vec<String>>,
    #[serde(default)]
    coverage_rules: Vec<tooltest_core::CoverageRule>,
}

impl From<StateMachineConfigInput> for StateMachineConfig {
    fn from(input: StateMachineConfigInput) -> Self {
        StateMachineConfig {
            seed_numbers: input.seed_numbers,
            seed_strings: input.seed_strings,
            lenient_sourcing: input.lenient_sourcing,
            coverage_allowlist: input.coverage_allowlist,
            coverage_blocklist: input.coverage_blocklist,
            coverage_rules: input.coverage_rules,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Subcommand)]
pub enum Command {
    /// Run against a stdio MCP endpoint.
    Stdio {
        /// Command to execute.
        #[arg(long)]
        command: String,
        /// Command arguments (repeatable).
        #[arg(long = "arg")]
        args: Vec<String>,
        /// Environment variables (KEY=VALUE).
        #[arg(long = "env")]
        env: Vec<String>,
        /// Working directory.
        #[arg(long)]
        cwd: Option<String>,
    },
    /// Run against an HTTP MCP endpoint.
    Http {
        /// MCP endpoint URL.
        #[arg(long)]
        url: String,
        /// Authorization bearer token.
        #[arg(long)]
        auth_token: Option<String>,
    },
}

pub async fn run(cli: Cli) -> ExitCode {
    let sequence_len = match build_sequence_len(cli.min_sequence_len, cli.max_sequence_len) {
        Ok(range) => range,
        Err(message) => return error_exit(&message, cli.json),
    };

    let options = RunnerOptions {
        cases: cli.cases,
        sequence_len,
    };
    let mut state_machine = match cli.state_machine_config.as_deref() {
        Some(raw) => match parse_state_machine_config(raw) {
            Ok(config) => config,
            Err(message) => return error_exit(&message, cli.json),
        },
        None => StateMachineConfig::default(),
    };
    if cli.lenient_sourcing {
        state_machine.lenient_sourcing = true;
    } else if cli.no_lenient_sourcing {
        state_machine.lenient_sourcing = false;
    }
    let run_config = RunConfig::new()
        .with_generator_mode(cli.generator_mode.into())
        .with_state_machine(state_machine);

    let result = match cli.command {
        Command::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
            let env = match parse_env_vars(env) {
                Ok(env) => env,
                Err(message) => return error_exit(&message, cli.json),
            };
            let config = StdioConfig {
                command,
                args,
                env,
                cwd,
            };
            tooltest_core::run_stdio(&config, &run_config, options).await
        }
        Command::Http { url, auth_token } => {
            let config = HttpConfig { url, auth_token };
            tooltest_core::run_http(&config, &run_config, options).await
        }
    };

    let output = if cli.json {
        serde_json::to_string_pretty(&result).expect("serialize run result")
    } else {
        format_run_result_human(&result)
    };
    print!("{output}");

    exit_code_for_result(&result)
}

pub fn build_sequence_len(min_len: usize, max_len: usize) -> Result<RangeInclusive<usize>, String> {
    if min_len == 0 {
        return Err("min-sequence-len must be at least 1".to_string());
    }
    if min_len > max_len {
        return Err("min-sequence-len must be <= max-sequence-len".to_string());
    }
    Ok(min_len..=max_len)
}

pub fn parse_env_vars(entries: Vec<String>) -> Result<BTreeMap<String, String>, String> {
    let mut env = BTreeMap::new();
    for entry in entries {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| format!("invalid env entry: '{entry}'"))?;
        if key.is_empty() {
            return Err(format!("invalid env entry: '{entry}'"));
        }
        env.insert(key.to_string(), value.to_string());
    }
    Ok(env)
}

pub fn parse_state_machine_config(raw: &str) -> Result<StateMachineConfig, String> {
    let payload = if let Some(path) = raw.strip_prefix('@') {
        fs::read_to_string(path)
            .map_err(|error| format!("failed to read state-machine-config: {error}"))?
    } else {
        raw.to_string()
    };
    let input: StateMachineConfigInput = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid state-machine-config: {error}"))?;
    Ok(input.into())
}

#[derive(Serialize)]
struct CliError<'a> {
    status: &'static str,
    message: &'a str,
}

fn error_exit(message: &str, json: bool) -> ExitCode {
    if json {
        let payload = CliError {
            status: "error",
            message,
        };
        let output = serde_json::to_string_pretty(&payload).expect("serialize cli error");
        eprintln!("{output}");
    } else {
        eprintln!("{message}");
    }
    ExitCode::from(2)
}

fn exit_code_for_result(result: &RunResult) -> ExitCode {
    match &result.outcome {
        RunOutcome::Success => ExitCode::SUCCESS,
        RunOutcome::Failure(_) => ExitCode::from(1),
    }
}

fn format_run_result_human(result: &RunResult) -> String {
    let mut output = String::new();
    match &result.outcome {
        RunOutcome::Success => {
            output.push_str("Outcome: success\n");
        }
        RunOutcome::Failure(failure) => {
            output.push_str("Outcome: failure\n");
            output.push_str(&format!("Reason: {}\n", failure.reason));
            if let Some(code) = &failure.code {
                output.push_str(&format!("Code: {code}\n"));
            }
            if let Some(details) = &failure.details {
                let details =
                    serde_json::to_string_pretty(details).expect("serialize failure details");
                output.push_str("Details:\n");
                output.push_str(&details);
                output.push('\n');
            }
        }
    }

    if let Some(coverage) = &result.coverage {
        if !coverage.warnings.is_empty() {
            output.push_str("Coverage warnings:\n");
            for warning in &coverage.warnings {
                output.push_str(&format!(
                    "- {}: {}\n",
                    warning.tool,
                    format_coverage_warning_reason(&warning.reason)
                ));
            }
        }
    }

    if !result.warnings.is_empty() {
        output.push_str("Warnings:\n");
        for warning in &result.warnings {
            output.push_str(&format!(
                "- {}: {}\n",
                format_run_warning_code(&warning.code),
                format_run_warning_message(warning)
            ));
        }
    }

    if !result.trace.is_empty() {
        let trace = serde_json::to_string_pretty(&result.trace).expect("serialize trace");
        output.push_str("Trace:\n");
        output.push_str(&trace);
        output.push('\n');
    }

    output
}

fn format_coverage_warning_reason(reason: &CoverageWarningReason) -> &'static str {
    match reason {
        CoverageWarningReason::MissingString => "missing_string",
        CoverageWarningReason::MissingInteger => "missing_integer",
        CoverageWarningReason::MissingNumber => "missing_number",
        CoverageWarningReason::MissingRequiredValue => "missing_required_value",
    }
}

fn format_run_warning_code(code: &RunWarningCode) -> &'static str {
    match code {
        RunWarningCode::SchemaUnsupportedKeyword => "schema_unsupported_keyword",
    }
}

fn format_run_warning_message(warning: &RunWarning) -> String {
    if let Some(tool) = &warning.tool {
        format!("{} ({tool})", warning.message)
    } else {
        warning.message.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use clap::CommandFactory;
    use rmcp::model::{CallToolResult, Content};
    use tooltest_core::{
        CoverageReport, CoverageWarning, RunFailure, RunWarning, RunWarningCode, ToolInvocation,
        TraceEntry,
    };

    #[test]
    fn build_sequence_len_rejects_zero_min() {
        let error = build_sequence_len(0, 1).expect_err("error");
        assert!(error.contains("min-sequence-len must be at least 1"));
    }

    #[test]
    fn build_sequence_len_rejects_inverted_range() {
        let error = build_sequence_len(3, 2).expect_err("error");
        assert!(error.contains("min-sequence-len must be <= max-sequence-len"));
    }

    #[test]
    fn build_sequence_len_accepts_valid_range() {
        let range = build_sequence_len(1, 3).expect("range");
        assert_eq!(range, 1..=3);
    }

    #[test]
    fn parse_env_vars_rejects_missing_equals() {
        let error = parse_env_vars(vec!["NOPE".to_string()]).expect_err("error");
        assert!(error.contains("invalid env entry"));
    }

    #[test]
    fn parse_env_vars_rejects_empty_key() {
        let error = parse_env_vars(vec!["=value".to_string()]).expect_err("error");
        assert!(error.contains("invalid env entry"));
    }

    #[test]
    fn parse_env_vars_accepts_values() {
        let env = parse_env_vars(vec!["FOO=bar".to_string(), "BAZ=qux".to_string()]).expect("env");
        assert_eq!(env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(env.get("BAZ"), Some(&"qux".to_string()));
    }

    #[test]
    fn parse_state_machine_config_reads_inline_json() {
        let config = parse_state_machine_config(
            r#"{"seed_numbers":[1],"seed_strings":["alpha"],"lenient_sourcing":true}"#,
        )
        .expect("config");
        assert_eq!(config.seed_numbers.len(), 1);
        assert_eq!(config.seed_strings.len(), 1);
        assert!(config.lenient_sourcing);
    }

    #[test]
    fn parse_state_machine_config_reads_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("tooltest-cli-state-machine.json");
        fs::write(&path, r#"{"seed_numbers":[2],"seed_strings":["beta"]}"#).expect("write config");
        let config = parse_state_machine_config(&format!("@{}", path.display())).expect("config");
        assert_eq!(config.seed_numbers.len(), 1);
        assert_eq!(config.seed_strings.len(), 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn parse_state_machine_config_rejects_invalid_json() {
        let error = parse_state_machine_config("{bad json}").expect_err("error");
        assert!(error.contains("invalid state-machine-config"));
    }

    #[test]
    fn parse_state_machine_config_rejects_missing_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("tooltest-cli-missing.json");
        let error = parse_state_machine_config(&format!("@{}", path.display())).expect_err("error");
        assert!(error.contains("failed to read state-machine-config"));
    }

    #[test]
    fn error_exit_formats_json_payload() {
        let exit = error_exit("bad", true);
        assert_eq!(exit, ExitCode::from(2));
    }

    #[test]
    fn exit_code_for_result_handles_success_and_failure() {
        let success = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            coverage: None,
        };
        assert_eq!(exit_code_for_result(&success), ExitCode::SUCCESS);

        let failure = RunResult {
            outcome: RunOutcome::Failure(RunFailure::new("nope")),
            trace: Vec::new(),
            minimized: None,
            coverage: None,
        };
        assert_eq!(exit_code_for_result(&failure), ExitCode::from(1));
    }

    #[test]
    fn cli_parses_generator_mode_and_stdio() {
        let cli = Cli::parse_from([
            "tooltest",
            "--generator-mode",
            "state-machine",
            "stdio",
            "--command",
            "server",
        ]);
        assert_eq!(cli.generator_mode, GeneratorModeArg::StateMachine);
        assert!(!cli.lenient_sourcing);
        assert!(!cli.no_lenient_sourcing);
        assert_eq!(
            cli.command,
            Command::Stdio {
                command: "server".to_string(),
                args: Vec::new(),
                env: Vec::new(),
                cwd: None,
            }
        );
    }

    #[test]
    fn cli_parses_lenient_sourcing_flag() {
        let cli = Cli::parse_from([
            "tooltest",
            "--lenient-sourcing",
            "http",
            "--url",
            "http://example.test/mcp",
        ]);
        assert!(cli.lenient_sourcing);
        assert!(!cli.no_lenient_sourcing);
    }

    #[test]
    fn cli_parses_no_lenient_sourcing_flag() {
        let cli = Cli::parse_from([
            "tooltest",
            "--no-lenient-sourcing",
            "http",
            "--url",
            "http://example.test/mcp",
        ]);
        assert!(!cli.lenient_sourcing);
        assert!(cli.no_lenient_sourcing);
    }

    #[test]
    fn generator_mode_arg_equality_covers_variants() {
        assert_eq!(GeneratorModeArg::Legacy, GeneratorModeArg::Legacy);
        assert_ne!(GeneratorModeArg::Legacy, GeneratorModeArg::StateMachine);
    }

    #[test]
    fn generator_mode_arg_value_enum_variants() {
        let variants = GeneratorModeArg::value_variants();
        assert!(variants.contains(&GeneratorModeArg::Legacy));
        assert!(variants.contains(&GeneratorModeArg::StateMachine));
        assert!(GeneratorModeArg::Legacy.to_possible_value().is_some());
        assert!(GeneratorModeArg::StateMachine.to_possible_value().is_some());
    }

    #[test]
    fn command_equality_covers_http_variant() {
        let left = Command::Http {
            url: "http://example.test/mcp".to_string(),
            auth_token: None,
        };
        let right = Command::Http {
            url: "http://example.test/mcp".to_string(),
            auth_token: None,
        };
        let other = Command::Http {
            url: "http://other.test/mcp".to_string(),
            auth_token: None,
        };

        assert_eq!(left, right);
        assert_ne!(left, other);
    }

    #[test]
    fn cli_parses_http_command() {
        let cli = Cli::parse_from(["tooltest", "http", "--url", "http://example.test/mcp"]);

        assert_eq!(
            cli.command,
            Command::Http {
                url: "http://example.test/mcp".to_string(),
                auth_token: None,
            }
        );
    }

    #[test]
    fn cli_command_factory_includes_subcommands() {
        let command = Cli::command();
        let names: Vec<_> = command
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .collect();

        assert!(names.contains(&"stdio".to_string()));
        assert!(names.contains(&"http".to_string()));
    }

    #[test]
    fn format_run_result_human_reports_success() {
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
        };

        let output = format_run_result_human(&result);
        assert_eq!(output, "Outcome: success\n");
    }

    #[test]
    fn format_run_result_human_reports_failure_details() {
        let failure = RunFailure {
            reason: "oops".to_string(),
            code: Some("failure_code".to_string()),
            details: Some(serde_json::json!({ "extra": 1 })),
        };
        let result = RunResult {
            outcome: RunOutcome::Failure(failure),
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("Outcome: failure"));
        assert!(output.contains("Reason: oops"));
        assert!(output.contains("Code: failure_code"));
        assert!(output.contains("Details:"));
        assert!(output.contains("\"extra\": 1"));
    }

    #[test]
    fn format_run_result_human_reports_coverage_warnings() {
        let coverage = CoverageReport {
            counts: BTreeMap::new(),
            warnings: vec![
                CoverageWarning {
                    tool: "alpha".to_string(),
                    reason: CoverageWarningReason::MissingString,
                },
                CoverageWarning {
                    tool: "beta".to_string(),
                    reason: CoverageWarningReason::MissingInteger,
                },
                CoverageWarning {
                    tool: "gamma".to_string(),
                    reason: CoverageWarningReason::MissingNumber,
                },
                CoverageWarning {
                    tool: "delta".to_string(),
                    reason: CoverageWarningReason::MissingRequiredValue,
                },
            ],
        };
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: Some(coverage),
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("Coverage warnings:"));
        assert!(output.contains("- alpha: missing_string"));
        assert!(output.contains("- beta: missing_integer"));
        assert!(output.contains("- gamma: missing_number"));
        assert!(output.contains("- delta: missing_required_value"));
    }

    #[test]
    fn format_run_result_human_reports_warnings() {
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: vec![RunWarning {
                code: RunWarningCode::SchemaUnsupportedKeyword,
                message: "schema warning".to_string(),
                tool: Some("echo".to_string()),
            }],
            coverage: None,
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("Warnings:"));
        assert!(output.contains("schema_unsupported_keyword"));
        assert!(output.contains("schema warning"));
        assert!(output.contains("echo"));
    }

    #[test]
    fn format_run_result_human_reports_warning_without_tool() {
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: vec![RunWarning {
                code: RunWarningCode::SchemaUnsupportedKeyword,
                message: "standalone warning".to_string(),
                tool: None,
            }],
            coverage: None,
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("standalone warning"));
        assert!(!output.contains("standalone warning ("));
    }

    #[test]
    fn format_run_result_human_includes_trace() {
        let invocation = ToolInvocation {
            name: "demo".into(),
            arguments: Some(
                serde_json::json!({ "value": 1 })
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        };
        let trace = vec![TraceEntry::tool_call_with_response(
            invocation,
            CallToolResult::error(vec![Content::text("boom")]),
        )];
        let result = RunResult {
            outcome: RunOutcome::Failure(RunFailure::new("failed")),
            trace,
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("Trace:"));
        assert!(output.contains("\"kind\": \"tool_call\""));
        assert!(output.contains("\"boom\""));
    }

    #[test]
    fn format_run_result_human_skips_empty_coverage_warnings() {
        let coverage = CoverageReport {
            counts: BTreeMap::new(),
            warnings: Vec::new(),
        };
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: Some(coverage),
        };

        let output = format_run_result_human(&result);
        assert!(!output.contains("Coverage warnings:"));
    }

    #[tokio::test]
    async fn run_exits_on_invalid_state_machine_config() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            generator_mode: GeneratorModeArg::Legacy,
            lenient_sourcing: false,
            no_lenient_sourcing: false,
            state_machine_config: Some("{bad json}".to_string()),
            json: false,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(2));
    }

    #[tokio::test]
    async fn run_allows_lenient_sourcing_flag() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            generator_mode: GeneratorModeArg::StateMachine,
            lenient_sourcing: true,
            no_lenient_sourcing: false,
            state_machine_config: None,
            json: false,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_state_machine_mode_returns_failure_for_unreachable_http() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            generator_mode: GeneratorModeArg::StateMachine,
            lenient_sourcing: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            json: false,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_stdio_returns_failure_when_command_missing() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            generator_mode: GeneratorModeArg::Legacy,
            lenient_sourcing: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            json: false,
            command: Command::Stdio {
                command: "tooltest-missing-command".to_string(),
                args: Vec::new(),
                env: vec!["FOO=bar".to_string()],
                cwd: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_stdio_exits_on_invalid_env_entry() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            generator_mode: GeneratorModeArg::Legacy,
            lenient_sourcing: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            json: false,
            command: Command::Stdio {
                command: "tooltest-missing-command".to_string(),
                args: Vec::new(),
                env: vec!["NOPE".to_string()],
                cwd: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(2));
    }
}
