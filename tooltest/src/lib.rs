#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::process::ExitCode;

use tooltest_core::{default_tooltest_toml, TooltestRunConfig, TooltestTargetConfig};

mod cli;
mod config;
mod mcp;
mod output;
mod trace;

#[cfg(test)]
use tooltest_test_support as _;

pub use cli::{Cli, Command, ConfigCommand};
pub use config::{parse_env_vars, parse_state_machine_config};

use config::build_tooltest_input;
use output::{error_exit, exit_code_for_result, format_run_result_human, maybe_dump_corpus};
use trace::TraceFileSink;

#[cfg(test)]
mod tests;

pub async fn run(cli: Cli) -> ExitCode {
    run_with_json_serializer(cli, serde_json::to_string_pretty).await
}

async fn run_with_json_serializer(
    cli: Cli,
    serialize_run_result: fn(&tooltest_core::RunResult) -> Result<String, serde_json::Error>,
) -> ExitCode {
    match &cli.command {
        Command::Mcp { .. } => {
            let result = mcp::run_stdio().await;
            if let Err(message) = result {
                return error_exit(&message, cli.json);
            }
            return ExitCode::SUCCESS;
        }
        Command::Config {
            command: ConfigCommand::Default,
        } => {
            print!("{}", default_tooltest_toml());
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let json = cli.json;
    let trace_all = cli.trace_all.clone();
    let input = match build_tooltest_input(&cli) {
        Ok(input) => input,
        Err(message) => return error_exit(&message, json),
    };
    let TooltestRunConfig {
        target,
        mut run_config,
        runner_options,
    } = match input.to_configs() {
        Ok(configs) => configs,
        Err(message) => return error_exit(&message, json),
    };
    if let Some(path) = trace_all.as_ref() {
        match TraceFileSink::new(path) {
            Ok(sink) => {
                run_config = run_config.with_trace_sink(std::sync::Arc::new(sink));
            }
            Err(message) => return error_exit(&message, json),
        }
    }

    let dump_corpus = run_config.state_machine.dump_corpus;
    let result = match target {
        TooltestTargetConfig::Stdio(config) => {
            tooltest_core::run_stdio(&config, &run_config, runner_options).await
        }
        TooltestTargetConfig::Http(config) => {
            tooltest_core::run_http(&config, &run_config, runner_options).await
        }
    };

    let output = if json {
        match serialize_run_result(&result) {
            Ok(output) => output,
            Err(error) => {
                return error_exit(&format!("failed to serialize run result: {error}"), json);
            }
        }
    } else {
        format_run_result_human(&result)
    };
    print!("{output}");
    maybe_dump_corpus(dump_corpus, json, &result);

    exit_code_for_result(&result)
}
