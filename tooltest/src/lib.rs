use std::collections::BTreeMap;
use std::fs;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;
use tooltest_core::{
    CoverageWarningReason, RunOutcome, RunResult, RunWarning, RunWarningCode, StateMachineConfig,
    TooltestHttpTarget, TooltestInput, TooltestPreRunHook, TooltestRunConfig, TooltestStdioTarget,
    TooltestTarget, TooltestTargetConfig, TraceEntry, TraceSink,
};

mod mcp;

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
    /// Allow schema-based generation when corpus lacks required values.
    #[arg(long)]
    pub lenient_sourcing: bool,
    /// Mine whitespace-delimited text tokens into the state corpus.
    #[arg(long)]
    pub mine_text: bool,
    /// Dump the final state-machine corpus after the run completes.
    #[arg(long)]
    pub dump_corpus: bool,
    /// Log newly mined corpus values after each tool response.
    #[arg(long)]
    pub log_corpus_deltas: bool,
    /// Disable schema-based generation when corpus lacks required values.
    #[arg(long, conflicts_with = "lenient_sourcing")]
    pub no_lenient_sourcing: bool,
    /// State-machine config as inline JSON or @path to a JSON file.
    #[arg(long, value_name = "JSON|@PATH")]
    pub state_machine_config: Option<String>,
    /// Allowlist tool names eligible for invocation generation (repeatable).
    #[arg(long = "tool-allowlist")]
    pub tool_allowlist: Vec<String>,
    /// Blocklist tool names excluded from invocation generation (repeatable).
    #[arg(long = "tool-blocklist")]
    pub tool_blocklist: Vec<String>,
    /// Fail the run when a tool result reports `isError = true`.
    /// By default, tool error responses are allowed and do not fail the run.
    #[arg(long)]
    pub in_band_error_forbidden: bool,

    /// Shell command to execute before validation and each run.
    #[arg(long)]
    pub pre_run_hook: Option<String>,
    /// Emit JSON output instead of human-readable output.
    #[arg(long)]
    pub json: bool,
    /// Include tool responses in the trace output.
    #[arg(long)]
    pub full_trace: bool,
    /// Include uncallable tool traces when coverage validation fails.
    #[arg(long)]
    pub show_uncallable: bool,
    /// Number of calls per tool to include in uncallable traces.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(usize))]
    pub uncallable_limit: usize,
    /// Emit all per-case traces to a file (JSON lines).
    #[arg(long, value_name = "PATH")]
    pub trace_all: Option<String>,
    #[command(subcommand)]
    pub command: Command,
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
    /// Run the tooltest MCP server.
    Mcp {
        /// Use stdio transport for the MCP server (default).
        #[arg(long)]
        stdio: bool,
        /// Use HTTP transport for the MCP server.
        #[arg(long)]
        http: bool,
        /// Bind address for the HTTP server (required with --http).
        #[arg(long, value_name = "ADDR")]
        bind: Option<String>,
    },
}

pub async fn run(cli: Cli) -> ExitCode {
    if let Command::Mcp { stdio, http, bind } = &cli.command {
        let transport = match resolve_mcp_transport(*stdio, *http, bind.as_deref()) {
            Ok(transport) => transport,
            Err(message) => return error_exit(&message, cli.json),
        };
        let result = match transport {
            McpTransport::Stdio => mcp::run_stdio().await,
            McpTransport::Http { bind } => mcp::run_http(&bind).await,
        };
        if let Err(message) = result {
            return error_exit(&message, cli.json);
        }
        return ExitCode::SUCCESS;
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
        serde_json::to_string_pretty(&result).expect("serialize run result")
    } else {
        format_run_result_human(&result)
    };
    print!("{output}");
    maybe_dump_corpus(dump_corpus, json, &result);

    exit_code_for_result(&result)
}

fn build_tooltest_input(cli: &Cli) -> Result<TooltestInput, String> {
    let state_machine_config = match cli.state_machine_config.as_deref() {
        Some(raw) => Some(parse_state_machine_config(raw)?),
        None => None,
    };
    let pre_run_hook = cli.pre_run_hook.as_ref().map(|command| TooltestPreRunHook {
        command: command.clone(),
        env: BTreeMap::new(),
        cwd: None,
    });
    let target = match &cli.command {
        Command::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
            let env = parse_env_vars(env.clone())?;
            TooltestTarget {
                stdio: Some(TooltestStdioTarget {
                    command: command.clone(),
                    args: args.clone(),
                    env,
                    cwd: cwd.clone(),
                }),
                http: None,
            }
        }
        Command::Http { url, auth_token } => TooltestTarget {
            stdio: None,
            http: Some(TooltestHttpTarget {
                url: url.clone(),
                auth_token: auth_token.clone(),
            }),
        },
        Command::Mcp { .. } => return Err("mcp command does not accept tooltest input".to_string()),
    };
    Ok(TooltestInput {
        target,
        cases: cli.cases,
        min_sequence_len: cli.min_sequence_len,
        max_sequence_len: cli.max_sequence_len,
        lenient_sourcing: cli.lenient_sourcing,
        mine_text: cli.mine_text,
        dump_corpus: cli.dump_corpus,
        log_corpus_deltas: cli.log_corpus_deltas,
        no_lenient_sourcing: cli.no_lenient_sourcing,
        state_machine_config,
        tool_allowlist: cli.tool_allowlist.clone(),
        tool_blocklist: cli.tool_blocklist.clone(),
        in_band_error_forbidden: cli.in_band_error_forbidden,
        pre_run_hook,
        full_trace: cli.full_trace,
        show_uncallable: cli.show_uncallable,
        uncallable_limit: cli.uncallable_limit,
    })
}

#[derive(Debug, Eq, PartialEq)]
enum McpTransport {
    Stdio,
    Http { bind: String },
}

fn resolve_mcp_transport(
    stdio: bool,
    http: bool,
    bind: Option<&str>,
) -> Result<McpTransport, String> {
    if stdio && http {
        return Err("mcp transport flags are mutually exclusive".to_string());
    }
    if stdio && bind.is_some() {
        return Err("mcp stdio transport does not accept --bind".to_string());
    }
    if http {
        let bind = bind.ok_or_else(|| "mcp http transport requires --bind".to_string())?;
        return Ok(McpTransport::Http {
            bind: bind.to_string(),
        });
    }
    if bind.is_some() {
        return Err("mcp --bind requires --http".to_string());
    }
    Ok(McpTransport::Stdio)
}

fn maybe_dump_corpus(dump_corpus: bool, json: bool, result: &RunResult) {
    if dump_corpus && !json {
        if let Some(corpus) = &result.corpus {
            let payload = serde_json::to_string_pretty(corpus).expect("serialize corpus");
            eprintln!("corpus:\n{payload}");
        }
    }
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
    let input: StateMachineConfig = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid state-machine-config: {error}"))?;
    Ok(input)
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
        if coverage.failures.values().any(|count| *count > 0) {
            output.push_str("Coverage failures:\n");
            for (tool, count) in &coverage.failures {
                if *count > 0 {
                    output.push_str(&format!("- {tool}: {count}\n"));
                }
            }
        }
        if !coverage.uncallable_traces.is_empty() {
            output.push_str("Uncallable traces:\n");
            for (tool, calls) in &coverage.uncallable_traces {
                output.push_str(&format!("- {tool}:\n"));
                if calls.is_empty() {
                    output.push_str("  (no calls)\n");
                    continue;
                }
                for call in calls {
                    output.push_str("  - timestamp: ");
                    output.push_str(&call.timestamp);
                    output.push('\n');
                    let arguments = call
                        .input
                        .arguments
                        .clone()
                        .map(serde_json::Value::Object)
                        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
                    let args_payload = serde_json::to_string_pretty(&arguments)
                        .expect("serialize uncallable arguments");
                    output.push_str("    arguments:\n");
                    for line in args_payload.lines() {
                        output.push_str("      ");
                        output.push_str(line);
                        output.push('\n');
                    }
                    if let Some(result) = call.output.as_ref() {
                        let output_payload = serde_json::to_string_pretty(result)
                            .expect("serialize uncallable output");
                        output.push_str("    output:\n");
                        for line in output_payload.lines() {
                            output.push_str("      ");
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                    if let Some(result) = call.error.as_ref() {
                        let error_payload = serde_json::to_string_pretty(result)
                            .expect("serialize uncallable error");
                        output.push_str("    error:\n");
                        for line in error_payload.lines() {
                            output.push_str("      ");
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                }
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
        RunWarningCode::MissingStructuredContent => "missing_structured_content",
    }
}

fn format_run_warning_message(warning: &RunWarning) -> String {
    if let Some(tool) = &warning.tool {
        format!("{} ({tool})", warning.message)
    } else {
        warning.message.clone()
    }
}

#[derive(Clone)]
struct TraceFileSink {
    path: String,
    file: std::sync::Arc<std::sync::Mutex<fs::File>>,
    write_failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl TraceFileSink {
    fn new(path: &str) -> Result<Self, String> {
        let path = path.to_string();
        let header = serde_json::to_string(&serde_json::json!({ "format": "trace_all_v1" }))
            .expect("serialize trace header");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .map_err(|error| format!("failed to write trace file '{path}': {error}"))?;
        use std::io::Write;
        file.write_all(header.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|error| format!("failed to write trace file '{path}': {error}"))?;
        Ok(Self {
            path,
            file: std::sync::Arc::new(std::sync::Mutex::new(file)),
            write_failed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
}

impl TraceSink for TraceFileSink {
    fn record(&self, case_index: u64, trace: &[TraceEntry]) {
        let payload = serde_json::json!({
            "case": case_index,
            "trace": trace,
        });
        let line = serde_json::to_string(&payload).expect("serialize trace payload");
        let mut file = match self.file.lock() {
            Ok(file) => file,
            Err(_) => return,
        };
        let result = {
            use std::io::Write;
            file.write_all(line.as_bytes())
                .and_then(|()| file.write_all(b"\n"))
        };
        if result.is_err()
            && !self
                .write_failed
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            eprintln!("failed to append trace output to '{}'", self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::env;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use clap::{CommandFactory, Parser};
    use rmcp::model::{
        CallToolResult, ClientJsonRpcMessage, ClientRequest, Content, ListPromptsRequest,
        NumberOrString, PaginatedRequestParam, Tool,
    };
    use rmcp::transport::Transport;
    use serde_json::json;
    use std::sync::Arc;
    use tooltest_core::{
        list_tools_http, list_tools_stdio, list_tools_with_session, CorpusReport, CoverageReport,
        CoverageWarning, HttpConfig, ListToolsError, RunFailure, RunWarning, RunWarningCode,
        SchemaConfig, SessionDriver, StdioConfig, ToolInvocation, TraceEntry, UncallableToolCall,
    };
    use tooltest_test_support::{
        stub_tool, FaultyListToolsTransport, ListToolsTransport, TransportError,
    };

    fn temp_path(name: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("tooltest-{name}-{pid}-{nanos}-{counter}"))
    }

    fn unpack_mcp(command: Command) -> (bool, bool, Option<String>) {
        match command {
            Command::Mcp { stdio, http, bind } => (stdio, http, bind),
            other => panic!("expected mcp command, got {other:?}"),
        }
    }

    static MCP_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: String,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &str, value: &str) -> Self {
            let previous = env::var(key).ok();
            env::set_var(key, value);
            Self {
                key: key.to_string(),
                previous,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                env::set_var(&self.key, previous);
            } else {
                env::remove_var(&self.key);
            }
        }
    }

    #[test]
    fn tooltest_input_rejects_zero_min_sequence_len() {
        let cli = Cli::parse_from([
            "tooltest",
            "--min-sequence-len",
            "0",
            "http",
            "--url",
            "http://127.0.0.1:0/mcp",
        ]);
        let input = build_tooltest_input(&cli).expect("input");
        let error = input.to_runner_options().expect_err("error");
        assert!(error.contains("min-sequence-len must be at least 1"));
    }

    #[test]
    fn tooltest_input_rejects_inverted_sequence_len() {
        let cli = Cli::parse_from([
            "tooltest",
            "--min-sequence-len",
            "3",
            "--max-sequence-len",
            "2",
            "http",
            "--url",
            "http://127.0.0.1:0/mcp",
        ]);
        let input = build_tooltest_input(&cli).expect("input");
        let error = input.to_runner_options().expect_err("error");
        assert!(error.contains("min-sequence-len must be <= max-sequence-len"));
    }

    #[test]
    fn tooltest_input_accepts_valid_sequence_len() {
        let cli = Cli::parse_from([
            "tooltest",
            "--min-sequence-len",
            "1",
            "--max-sequence-len",
            "3",
            "http",
            "--url",
            "http://127.0.0.1:0/mcp",
        ]);
        let input = build_tooltest_input(&cli).expect("input");
        let options = input.to_runner_options().expect("options");
        assert_eq!(options.sequence_len, 1..=3);
    }

    #[test]
    fn cli_defaults_uncallable_flags() {
        let cli = Cli::parse_from(["tooltest", "http", "--url", "http://127.0.0.1:0/mcp"]);
        assert!(!cli.show_uncallable);
        assert_eq!(cli.uncallable_limit, 1);
    }

    #[test]
    fn cli_parses_uncallable_flags() {
        let cli = Cli::parse_from([
            "tooltest",
            "--show-uncallable",
            "--uncallable-limit",
            "3",
            "http",
            "--url",
            "http://127.0.0.1:0/mcp",
        ]);
        assert!(cli.show_uncallable);
        assert_eq!(cli.uncallable_limit, 3);
    }

    #[test]
    fn tooltest_input_builds_tool_filters_from_blocklist() {
        let cli = Cli::parse_from([
            "tooltest",
            "--tool-blocklist",
            "echo",
            "http",
            "--url",
            "http://127.0.0.1:0/mcp",
        ]);
        let input = build_tooltest_input(&cli).expect("input");
        let run_config = input.to_run_config().expect("run config");
        let predicate = run_config.predicate.expect("predicate");
        let name_predicate = run_config.tool_filter.expect("tool filter");

        assert!(!(predicate)("echo", &json!({})));
        assert!(!(name_predicate)("echo"));
        assert!((predicate)("other", &json!({})));
        assert!((name_predicate)("other"));
    }

    #[test]
    fn tooltest_input_omits_tool_filters_when_empty() {
        let cli = Cli::parse_from(["tooltest", "http", "--url", "http://127.0.0.1:0/mcp"]);
        let input = build_tooltest_input(&cli).expect("input");
        let run_config = input.to_run_config().expect("run config");
        assert!(run_config.predicate.is_none());
        assert!(run_config.tool_filter.is_none());
    }

    #[test]
    fn tooltest_input_builds_tool_filters_from_allowlist() {
        let cli = Cli::parse_from([
            "tooltest",
            "--tool-allowlist",
            "echo",
            "http",
            "--url",
            "http://127.0.0.1:0/mcp",
        ]);
        let input = build_tooltest_input(&cli).expect("input");
        let run_config = input.to_run_config().expect("run config");
        let predicate = run_config.predicate.expect("predicate");
        let name_predicate = run_config.tool_filter.expect("tool filter");

        assert!(!(predicate)("other", &json!({})));
        assert!(!(name_predicate)("other"));
        assert!((predicate)("echo", &json!({})));
        assert!((name_predicate)("echo"));
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
        let path = dir.join("tooltest-state-machine.json");
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
        let path = dir.join("tooltest-missing.json");
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
            warnings: Vec::new(),
            coverage: None,
            corpus: None,
        };
        assert_eq!(exit_code_for_result(&success), ExitCode::SUCCESS);

        let failure = RunResult {
            outcome: RunOutcome::Failure(RunFailure::new("nope")),
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
            corpus: None,
        };
        assert_eq!(exit_code_for_result(&failure), ExitCode::from(1));
    }

    #[tokio::test]
    async fn list_tools_helpers_report_errors_in_cli_tests() {
        let http = HttpConfig {
            url: "http://127.0.0.1:0/mcp".to_string(),
            auth_token: None,
        };
        assert!(list_tools_http(&http, &SchemaConfig::default())
            .await
            .is_err());

        let missing = std::env::temp_dir().join("tooltest-missing-stdio");
        let stdio = StdioConfig::new(missing.display().to_string());
        assert!(list_tools_stdio(&stdio, &SchemaConfig::default())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn list_tools_with_session_reports_tools_in_cli_tests() {
        let tool = stub_tool("echo");
        let transport = ListToolsTransport::new(vec![tool]);
        let driver = SessionDriver::connect_with_transport::<
            ListToolsTransport,
            std::convert::Infallible,
            rmcp::transport::TransportAdapterIdentity,
        >(transport)
        .await
        .expect("connect");

        let tools = list_tools_with_session(&driver, &SchemaConfig::default())
            .await
            .expect("tools");
        assert_eq!(tools.len(), 1);
    }

    #[tokio::test]
    async fn list_tools_with_session_reports_errors_in_cli_tests() {
        let transport = FaultyListToolsTransport::default();
        let driver = SessionDriver::connect_with_transport::<
            FaultyListToolsTransport,
            TransportError,
            rmcp::transport::TransportAdapterIdentity,
        >(transport)
        .await
        .expect("connect");

        let session_error = list_tools_with_session(&driver, &SchemaConfig::default())
            .await
            .expect_err("list tools error");

        let mut input_schema = serde_json::Map::new();
        input_schema.insert("type".to_string(), serde_json::Value::Bool(false));
        let tool = Tool {
            name: "bad".to_string().into(),
            title: None,
            description: None,
            input_schema: Arc::new(input_schema),
            output_schema: None,
            annotations: None,
            icons: None,
            meta: None,
        };
        let transport = ListToolsTransport::new(vec![tool]);
        let driver = SessionDriver::connect_with_transport::<
            ListToolsTransport,
            std::convert::Infallible,
            rmcp::transport::TransportAdapterIdentity,
        >(transport)
        .await
        .expect("connect");

        let schema_error = list_tools_with_session(&driver, &SchemaConfig::default())
            .await
            .expect_err("schema error");
        let mut saw_session = false;
        let mut saw_schema = false;

        for error in [session_error, schema_error] {
            match error {
                ListToolsError::Session(_) => saw_session = true,
                ListToolsError::Schema(_) => saw_schema = true,
            }
        }

        assert!(saw_session && saw_schema);
    }

    #[tokio::test]
    async fn faulty_list_tools_transport_handles_unhandled_request_and_close_in_cli_tests() {
        let mut transport = FaultyListToolsTransport::default();
        let request = ClientJsonRpcMessage::request(
            ClientRequest::ListPromptsRequest(ListPromptsRequest {
                method: Default::default(),
                params: Some(PaginatedRequestParam { cursor: None }),
                extensions: Default::default(),
            }),
            NumberOrString::Number(1),
        );

        transport.send(request).await.expect("send");
        transport.close().await.expect("close");
        assert_eq!(TransportError("boom").to_string(), "boom");
    }

    #[test]
    fn cli_parses_stdio_command() {
        let cli = Cli::parse_from(["tooltest", "stdio", "--command", "server"]);
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
    fn tooltest_input_builds_stdio_target_from_cli() {
        let cli = Cli::parse_from([
            "tooltest",
            "stdio",
            "--command",
            "server",
            "--arg",
            "flag",
            "--env",
            "FOO=bar",
            "--cwd",
            "/tmp",
        ]);
        let input = build_tooltest_input(&cli).expect("input");
        let stdio = input.target.stdio.expect("stdio target");
        assert_eq!(stdio.command, "server");
        assert_eq!(stdio.args, vec!["flag".to_string()]);
        assert_eq!(stdio.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(stdio.cwd.as_deref(), Some("/tmp"));
        assert!(input.target.http.is_none());
    }

    #[test]
    fn tooltest_input_builds_http_target_from_cli() {
        let cli = Cli::parse_from([
            "tooltest",
            "http",
            "--url",
            "http://127.0.0.1:0/mcp",
            "--auth-token",
            "secret",
        ]);
        let input = build_tooltest_input(&cli).expect("input");
        let http = input.target.http.expect("http target");
        assert_eq!(http.url, "http://127.0.0.1:0/mcp");
        assert_eq!(http.auth_token.as_deref(), Some("secret"));
        assert!(input.target.stdio.is_none());
    }

    #[test]
    fn tooltest_input_rejects_mcp_command() {
        let cli = Cli::parse_from(["tooltest", "mcp"]);
        let error = build_tooltest_input(&cli).expect_err("error");
        assert!(error.contains("mcp command"));
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
    fn mcp_command_defaults_to_stdio_transport() {
        let cli = Cli::parse_from(["tooltest", "mcp"]);
        let (stdio, http, bind) = unpack_mcp(cli.command);
        let transport = resolve_mcp_transport(stdio, http, bind.as_deref()).expect("transport");
        assert_eq!(transport, McpTransport::Stdio);
    }

    #[test]
    fn mcp_command_accepts_explicit_stdio_transport() {
        let cli = Cli::parse_from(["tooltest", "mcp", "--stdio"]);
        let (stdio, http, bind) = unpack_mcp(cli.command);
        let transport = resolve_mcp_transport(stdio, http, bind.as_deref()).expect("transport");
        assert_eq!(transport, McpTransport::Stdio);
    }

    #[test]
    fn mcp_command_requires_bind_for_http() {
        let cli = Cli::parse_from(["tooltest", "mcp", "--http"]);
        let (stdio, http, bind) = unpack_mcp(cli.command);
        let error = resolve_mcp_transport(stdio, http, bind.as_deref()).expect_err("error");
        assert!(error.contains("bind"));
    }

    #[test]
    fn mcp_command_accepts_http_bind() {
        let cli = Cli::parse_from(["tooltest", "mcp", "--http", "--bind", "127.0.0.1:9000"]);
        let (stdio, http, bind) = unpack_mcp(cli.command);
        let transport = resolve_mcp_transport(stdio, http, bind.as_deref()).expect("transport");
        assert_eq!(
            transport,
            McpTransport::Http {
                bind: "127.0.0.1:9000".to_string()
            }
        );
    }

    #[test]
    fn mcp_command_rejects_stdio_and_http_together() {
        let cli = Cli::parse_from(["tooltest", "mcp", "--stdio", "--http"]);
        let (stdio, http, bind) = unpack_mcp(cli.command);
        let error = resolve_mcp_transport(stdio, http, bind.as_deref()).expect_err("error");
        assert!(error.contains("mutually"));
    }

    #[test]
    fn mcp_command_rejects_stdio_with_bind() {
        let cli = Cli::parse_from(["tooltest", "mcp", "--stdio", "--bind", "127.0.0.1:9000"]);
        let (stdio, http, bind) = unpack_mcp(cli.command);
        let error = resolve_mcp_transport(stdio, http, bind.as_deref()).expect_err("error");
        assert!(error.contains("bind"));
    }

    #[test]
    fn mcp_command_rejects_bind_without_http() {
        let cli = Cli::parse_from(["tooltest", "mcp", "--bind", "127.0.0.1:9000"]);
        let (stdio, http, bind) = unpack_mcp(cli.command);
        let error = resolve_mcp_transport(stdio, http, bind.as_deref()).expect_err("error");
        assert!(error.contains("--http"));
    }

    #[test]
    #[should_panic(expected = "expected mcp command")]
    fn unpack_mcp_panics_on_non_mcp_command() {
        unpack_mcp(Command::Http {
            url: "http://example.test/mcp".to_string(),
            auth_token: None,
        });
    }

    #[tokio::test]
    async fn run_mcp_stdio_exits_successfully() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
        let _guard = EnvVarGuard::set("TOOLTEST_MCP_EXIT_IMMEDIATELY", "1");
        let cli = Cli::parse_from(["tooltest", "mcp", "--stdio"]);
        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn run_mcp_stdio_waits_for_transport_shutdown() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
        let cli = Cli::parse_from(["tooltest", "mcp", "--stdio"]);
        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn run_mcp_stdio_without_test_transport_reports_error() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        env::remove_var("TOOLTEST_MCP_TEST_TRANSPORT");
        env::remove_var("TOOLTEST_MCP_EXIT_IMMEDIATELY");
        let result = mcp::run_stdio().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_mcp_stdio_bad_transport_reports_error() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
        let _bad_guard = EnvVarGuard::set("TOOLTEST_MCP_BAD_TRANSPORT", "1");
        let result = mcp::run_stdio().await;
        assert!(result
            .expect_err("expected error")
            .contains("failed to start MCP stdio server"));
    }

    #[tokio::test]
    async fn run_mcp_stdio_panic_transport_reports_error() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
        let _panic_guard = EnvVarGuard::set("TOOLTEST_MCP_PANIC_TRANSPORT", "1");
        let result = mcp::run_stdio().await;
        assert!(result
            .expect_err("expected error")
            .contains("MCP stdio server failed"));
    }

    #[tokio::test]
    async fn run_mcp_stdio_exit_immediately_reports_error_on_panic() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
        let _panic_guard = EnvVarGuard::set("TOOLTEST_MCP_PANIC_TRANSPORT", "1");
        let _exit_guard = EnvVarGuard::set("TOOLTEST_MCP_EXIT_IMMEDIATELY", "1");
        let result = mcp::run_stdio().await;
        assert!(result
            .expect_err("expected error")
            .contains("MCP stdio server failed"));
    }

    #[tokio::test]
    async fn run_mcp_http_exits_successfully() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        let _guard = EnvVarGuard::set("TOOLTEST_MCP_EXIT_IMMEDIATELY", "1");
        let cli = Cli::parse_from(["tooltest", "mcp", "--http", "--bind", "127.0.0.1:0"]);
        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn run_mcp_http_pending_shutdown_times_out() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        env::remove_var("TOOLTEST_MCP_EXIT_IMMEDIATELY");
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            mcp::run_http("127.0.0.1:0"),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_mcp_http_forced_error_reports_error() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        let _guard = EnvVarGuard::set("TOOLTEST_MCP_FORCE_HTTP_ERROR", "1");
        let result = mcp::run_http("127.0.0.1:0").await;
        assert!(result
            .expect_err("expected error")
            .contains("failed to serve MCP HTTP server"));
    }

    #[tokio::test]
    async fn run_mcp_missing_bind_returns_exit_code_2() {
        let cli = Cli::parse_from(["tooltest", "mcp", "--http"]);
        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(2));
    }

    #[tokio::test]
    async fn run_mcp_http_invalid_bind_returns_exit_code_2() {
        let cli = Cli::parse_from(["tooltest", "mcp", "--http", "--bind", "invalid:bind"]);
        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(2));
    }

    #[test]
    fn env_var_guard_restores_previous_value() {
        let _lock = MCP_ENV_LOCK.lock().expect("lock");
        env::set_var("TOOLTEST_MCP_EXIT_IMMEDIATELY", "original");
        {
            let _guard = EnvVarGuard::set("TOOLTEST_MCP_EXIT_IMMEDIATELY", "temporary");
            assert_eq!(
                env::var("TOOLTEST_MCP_EXIT_IMMEDIATELY").as_deref(),
                Ok("temporary")
            );
        }
        assert_eq!(
            env::var("TOOLTEST_MCP_EXIT_IMMEDIATELY").as_deref(),
            Ok("original")
        );
        env::remove_var("TOOLTEST_MCP_EXIT_IMMEDIATELY");
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
        assert!(names.contains(&"mcp".to_string()));
    }

    #[test]
    fn format_run_result_human_reports_success() {
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
            corpus: None,
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
            corpus: None,
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
            failures: BTreeMap::new(),
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
            uncallable_traces: BTreeMap::new(),
        };
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: Some(coverage),
            corpus: None,
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("Coverage warnings:"));
        assert!(output.contains("- alpha: missing_string"));
        assert!(output.contains("- beta: missing_integer"));
        assert!(output.contains("- gamma: missing_number"));
        assert!(output.contains("- delta: missing_required_value"));
    }

    #[test]
    fn format_run_result_human_reports_coverage_failures() {
        let mut failures = BTreeMap::new();
        failures.insert("alpha".to_string(), 2);
        failures.insert("beta".to_string(), 0);
        let coverage = CoverageReport {
            counts: BTreeMap::new(),
            failures,
            warnings: Vec::new(),
            uncallable_traces: BTreeMap::new(),
        };
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: Some(coverage),
            corpus: None,
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("Coverage failures:"));
        assert!(output.contains("- alpha: 2"));
        assert!(!output.contains("- beta: 0"));
    }

    #[test]
    fn format_run_result_human_reports_uncallable_traces() {
        let invocation = ToolInvocation {
            name: "alpha".into(),
            arguments: Some(
                serde_json::json!({ "value": 1 })
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        };
        let call = UncallableToolCall {
            input: invocation,
            output: Some(CallToolResult::success(vec![Content::text("ok")])),
            error: None,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };
        let error_invocation = ToolInvocation {
            name: "gamma".into(),
            arguments: None,
        };
        let error_call = UncallableToolCall {
            input: error_invocation,
            output: None,
            error: Some(CallToolResult::error(vec![Content::text("boom")])),
            timestamp: "2024-01-02T00:00:00Z".to_string(),
        };
        let mut uncallable_traces = BTreeMap::new();
        uncallable_traces.insert("beta".to_string(), Vec::new());
        uncallable_traces.insert("alpha".to_string(), vec![call]);
        uncallable_traces.insert("gamma".to_string(), vec![error_call]);
        let coverage = CoverageReport {
            counts: BTreeMap::new(),
            failures: BTreeMap::new(),
            warnings: Vec::new(),
            uncallable_traces,
        };
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: Some(coverage),
            corpus: None,
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("Uncallable traces:"));
        let alpha_idx = output.find("- alpha:").expect("alpha");
        let beta_idx = output.find("- beta:").expect("beta");
        let gamma_idx = output.find("- gamma:").expect("gamma");
        assert!(alpha_idx < beta_idx);
        assert!(beta_idx < gamma_idx);
        assert!(output.contains("timestamp: 2024-01-01T00:00:00Z"));
        assert!(output.contains("arguments:"));
        assert!(output.contains("output:"));
        assert!(output.contains("- beta:\n  (no calls)"));
        assert!(output.contains("error:"));
        assert!(output.contains("boom"));
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
            corpus: None,
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("Warnings:"));
        assert!(output.contains("schema_unsupported_keyword"));
        assert!(output.contains("schema warning"));
        assert!(output.contains("echo"));
    }

    #[test]
    fn format_run_result_human_reports_missing_structured_warning_code() {
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: vec![RunWarning {
                code: RunWarningCode::MissingStructuredContent,
                message: "missing".to_string(),
                tool: Some("echo".to_string()),
            }],
            coverage: None,
            corpus: None,
        };

        let output = format_run_result_human(&result);
        assert!(output.contains("missing_structured_content"));
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
            corpus: None,
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
            corpus: None,
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
            failures: BTreeMap::new(),
            warnings: Vec::new(),
            uncallable_traces: BTreeMap::new(),
        };
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: Some(coverage),
            corpus: None,
        };

        let output = format_run_result_human(&result);
        assert!(!output.contains("Coverage warnings:"));
        assert!(!output.contains("Coverage failures:"));
    }

    #[test]
    fn trace_file_sink_writes_header_and_records_trace() {
        let path = temp_path("trace-all.jsonl");
        let sink = TraceFileSink::new(path.to_str().expect("path")).expect("trace sink");
        let invocation = ToolInvocation {
            name: "demo".into(),
            arguments: None,
        };
        let trace = vec![TraceEntry::tool_call(invocation)];
        sink.record(3, &trace);

        let contents = fs::read_to_string(&path).expect("read trace file");
        let mut lines = contents.lines();
        let header = lines.next().expect("header");
        let record = lines.next().expect("record");
        assert!(header.contains("trace_all_v1"));
        assert!(record.contains("\"case\":3"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn trace_file_sink_new_fails_for_directory() {
        let path = temp_path("trace-all-dir");
        fs::create_dir_all(&path).expect("create dir");

        assert!(TraceFileSink::new(path.to_str().expect("path")).is_err());
        fs::remove_dir_all(path).expect("cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trace_file_sink_record_ignores_write_error() {
        let path = std::path::Path::new("/dev/full");
        assert!(path.exists());
        let sink = TraceFileSink {
            path: path.to_string_lossy().to_string(),
            file: std::sync::Arc::new(std::sync::Mutex::new(
                fs::OpenOptions::new().write(true).open(path).expect("open"),
            )),
            write_failed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let invocation = ToolInvocation {
            name: "demo".into(),
            arguments: None,
        };
        let trace = vec![TraceEntry::tool_call(invocation)];
        sink.record(1, &trace);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trace_file_sink_new_reports_header_write_error() {
        let path = std::path::Path::new("/dev/full");
        assert!(path.exists());

        assert!(TraceFileSink::new(path.to_str().expect("path")).is_err());
    }

    #[test]
    fn trace_file_sink_record_ignores_poisoned_lock() {
        let path = temp_path("trace-all-poison");
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open");
        let file = std::sync::Arc::new(std::sync::Mutex::new(file));
        let poisoned = file.clone();
        let _ = std::panic::catch_unwind(move || {
            let _guard = poisoned.lock().expect("lock");
            panic!("poison lock");
        });

        let sink = TraceFileSink {
            path: path.to_string_lossy().to_string(),
            file,
            write_failed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let invocation = ToolInvocation {
            name: "demo".into(),
            arguments: None,
        };
        let trace = vec![TraceEntry::tool_call(invocation)];
        sink.record(1, &trace);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn maybe_dump_corpus_emits_when_requested() {
        let corpus = CorpusReport {
            numbers: vec![serde_json::Number::from(1)],
            integers: vec![2],
            strings: vec!["status".to_string()],
        };
        let result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
            corpus: Some(corpus),
        };

        maybe_dump_corpus(true, false, &result);
    }

    #[test]
    fn exit_code_for_result_reports_success_and_failure() {
        let success = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
            corpus: None,
        };
        let failure = RunResult {
            outcome: RunOutcome::Failure(RunFailure::new("nope")),
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
            corpus: None,
        };
        assert_eq!(exit_code_for_result(&success), ExitCode::SUCCESS);
        assert_eq!(exit_code_for_result(&failure), ExitCode::from(1));
    }

    #[test]
    fn error_exit_emits_json_payload() {
        let code = error_exit("oops", true);
        assert_eq!(code, ExitCode::from(2));
    }

    #[tokio::test]
    async fn run_stdio_missing_command_returns_exit_code_1() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
            command: Command::Stdio {
                command: "tooltest-missing-binary".to_string(),
                args: Vec::new(),
                env: Vec::new(),
                cwd: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_accepts_trace_all_output() {
        let trace_path = temp_path("trace-all-ok");
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: Some(trace_path.display().to_string()),
            command: Command::Stdio {
                command: "tooltest-missing-binary".to_string(),
                args: Vec::new(),
                env: Vec::new(),
                cwd: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
        assert!(trace_path.exists());
        let _ = fs::remove_file(trace_path);
    }

    #[tokio::test]
    async fn run_exits_on_trace_all_error() {
        let trace_dir = temp_path("trace-all-run");
        fs::create_dir_all(&trace_dir).expect("create dir");
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: Some(trace_dir.display().to_string()),
            command: Command::Stdio {
                command: "tooltest-missing-binary".to_string(),
                args: Vec::new(),
                env: Vec::new(),
                cwd: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(2));
        let _ = fs::remove_dir_all(trace_dir);
    }

    #[tokio::test]
    async fn run_stdio_invalid_env_returns_exit_code_2() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
            command: Command::Stdio {
                command: "tooltest-missing-binary".to_string(),
                args: Vec::new(),
                env: vec!["NOPE".to_string()],
                cwd: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(2));
    }
    #[tokio::test]
    async fn run_exits_on_invalid_state_machine_config() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: Some("{bad json}".to_string()),
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
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
            lenient_sourcing: true,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_applies_pre_run_hook_and_tool_filter() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: vec!["echo".to_string()],
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,
            pre_run_hook: Some("true".to_string()),
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_applies_state_machine_overrides() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: true,
            dump_corpus: false,
            log_corpus_deltas: true,
            no_lenient_sourcing: true,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_accepts_state_machine_config_with_json_output() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: Some(r#"{"seed_numbers":[1]}"#.to_string()),
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: true,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_applies_dump_corpus_flag() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: true,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: true,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_invalid_sequence_len_returns_exit_code_2() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 0,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(2));
    }

    #[tokio::test]
    async fn run_invalid_uncallable_limit_returns_exit_code_2() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 0,
            trace_all: None,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(2));
    }

    #[tokio::test]
    async fn run_state_machine_mode_returns_failure_for_unreachable_http() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
            command: Command::Http {
                url: "http://127.0.0.1:0/mcp".to_string(),
                auth_token: None,
            },
        };

        let exit = run(cli).await;
        assert_eq!(exit, ExitCode::from(1));
    }

    #[tokio::test]
    async fn run_applies_in_band_error_forbidden_flag() {
        let cli = Cli {
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: true,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
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
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
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
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,

            pre_run_hook: None,
            json: false,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
            trace_all: None,
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
