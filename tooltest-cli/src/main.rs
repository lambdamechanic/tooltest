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
struct Cli {
    /// Number of proptest cases to execute.
    #[arg(long, default_value_t = 32)]
    cases: u32,
    /// Minimum sequence length per generated run.
    #[arg(long, default_value_t = 1)]
    min_sequence_len: usize,
    /// Maximum sequence length per generated run.
    #[arg(long, default_value_t = 3)]
    max_sequence_len: usize,
    /// Generator mode for sequence synthesis.
    #[arg(long, value_enum, default_value_t = GeneratorModeArg::Legacy)]
    generator_mode: GeneratorModeArg,
    /// State-machine config as inline JSON or @path to a JSON file.
    #[arg(long, value_name = "JSON|@PATH")]
    state_machine_config: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum GeneratorModeArg {
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
enum Command {
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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();

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

fn build_sequence_len(min_len: usize, max_len: usize) -> Result<RangeInclusive<usize>, String> {
    if min_len == 0 {
        return Err("min-sequence-len must be at least 1".to_string());
    }
    if min_len > max_len {
        return Err("min-sequence-len must be <= max-sequence-len".to_string());
    }
    Ok(min_len..=max_len)
}

fn parse_env_vars(entries: Vec<String>) -> Result<BTreeMap<String, String>, String> {
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

fn parse_state_machine_config(raw: &str) -> Result<StateMachineConfig, String> {
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
