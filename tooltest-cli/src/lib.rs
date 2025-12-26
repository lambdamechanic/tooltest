use std::collections::BTreeMap;
use std::fs;
use std::ops::RangeInclusive;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use tooltest_core::{
    GeneratorMode, HttpConfig, RunConfig, RunOutcome, RunnerOptions, StateMachineConfig,
    StdioConfig,
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
    /// State-machine config as inline JSON or @path to a JSON file.
    #[arg(long, value_name = "JSON|@PATH")]
    pub state_machine_config: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
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
            coverage_allowlist: input.coverage_allowlist,
            coverage_blocklist: input.coverage_blocklist,
            coverage_rules: input.coverage_rules,
        }
    }
}

#[derive(Subcommand)]
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
        Err(message) => return error_exit(&message),
    };

    let options = RunnerOptions {
        cases: cli.cases,
        sequence_len,
    };
    let state_machine = match cli.state_machine_config.as_deref() {
        Some(raw) => match parse_state_machine_config(raw) {
            Ok(config) => config,
            Err(message) => return error_exit(&message),
        },
        None => StateMachineConfig::default(),
    };
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
                Err(message) => return error_exit(&message),
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

    let payload = serde_json::to_string_pretty(&result).expect("serialize run result");
    println!("{payload}");

    match result.outcome {
        RunOutcome::Success => ExitCode::SUCCESS,
        RunOutcome::Failure(_) => ExitCode::from(1),
    }
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

fn error_exit(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let config = parse_state_machine_config(r#"{"seed_numbers":[1],"seed_strings":["alpha"]}"#)
            .expect("config");
        assert_eq!(config.seed_numbers.len(), 1);
        assert_eq!(config.seed_strings.len(), 1);
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
    fn cli_parses_generator_mode_and_stdio() {
        let cli = Cli::parse_from([
            "tooltest",
            "--generator-mode",
            "state-machine",
            "stdio",
            "--command",
            "server",
        ]);
        assert!(matches!(cli.generator_mode, GeneratorModeArg::StateMachine));
        assert!(matches!(cli.command, Command::Stdio { .. }));
    }
}
