use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tooltest_core::{HttpConfig, RunConfig, RunOutcome, RunnerOptions, StdioConfig};

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
    #[command(subcommand)]
    command: Command,
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
    let run_config = RunConfig::new();

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

fn error_exit(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(2)
}
