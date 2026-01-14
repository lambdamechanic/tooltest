use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::ops::RangeInclusive;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tooltest_core::{
    CoverageWarningReason, HttpConfig, PreRunHook, RunConfig, RunOutcome, RunResult, RunWarning,
    RunWarningCode, RunnerOptions, StateMachineConfig, StdioConfig, ToolNamePredicate,
    ToolPredicate,
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

    /// Shell command to execute before validation and each run.
    #[arg(long)]
    pub pre_run_hook: Option<String>,
    /// Emit JSON output instead of human-readable output.
    #[arg(long)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Deserialize)]
struct StateMachineConfigInput {
    #[serde(default)]
    seed_numbers: Vec<serde_json::Number>,
    #[serde(default)]
    seed_strings: Vec<String>,
    #[serde(default)]
    mine_text: bool,
    #[serde(default)]
    dump_corpus: bool,
    #[serde(default)]
    log_corpus_deltas: bool,
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
            mine_text: input.mine_text,
            dump_corpus: input.dump_corpus,
            log_corpus_deltas: input.log_corpus_deltas,
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
    if cli.mine_text {
        state_machine.mine_text = true;
    }
    if cli.dump_corpus {
        state_machine.dump_corpus = true;
    }
    if cli.log_corpus_deltas {
        state_machine.log_corpus_deltas = true;
    }
    let dump_corpus = state_machine.dump_corpus;
    let mut run_config = RunConfig::new().with_state_machine(state_machine);
    if let Some(hook) = cli.pre_run_hook.as_ref() {
        run_config = run_config.with_pre_run_hook(PreRunHook::new(hook));
    }
    if let Some(filters) = build_tool_filters(&cli.tool_allowlist, &cli.tool_blocklist) {
        run_config = run_config
            .with_predicate(filters.predicate)
            .with_tool_filter(filters.name_predicate);
    }

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
    maybe_dump_corpus(dump_corpus, cli.json, &result);

    exit_code_for_result(&result)
}

fn maybe_dump_corpus(dump_corpus: bool, json: bool, result: &RunResult) {
    if dump_corpus && !json {
        if let Some(corpus) = &result.corpus {
            let payload = serde_json::to_string_pretty(corpus).expect("serialize corpus");
            eprintln!("corpus:\n{payload}");
        }
    }
}

struct ToolFilterSets {
    allowlist: Option<HashSet<String>>,
    blocklist: Option<HashSet<String>>,
}

struct ToolFilters {
    predicate: ToolPredicate,
    name_predicate: ToolNamePredicate,
}

fn build_tool_filter_sets(allowlist: &[String], blocklist: &[String]) -> Option<ToolFilterSets> {
    if allowlist.is_empty() && blocklist.is_empty() {
        return None;
    }
    let allowlist =
        (!allowlist.is_empty()).then(|| allowlist.iter().cloned().collect::<HashSet<_>>());
    let blocklist =
        (!blocklist.is_empty()).then(|| blocklist.iter().cloned().collect::<HashSet<_>>());
    Some(ToolFilterSets {
        allowlist,
        blocklist,
    })
}

fn build_tool_filters(allowlist: &[String], blocklist: &[String]) -> Option<ToolFilters> {
    let sets = build_tool_filter_sets(allowlist, blocklist)?;
    let allowlist = sets.allowlist;
    let blocklist = sets.blocklist;
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
        SchemaConfig, SessionDriver, StdioConfig, ToolInvocation, TraceEntry,
    };
    use tooltest_test_support::{
        stub_tool, FaultyListToolsTransport, ListToolsTransport, TransportError,
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
    fn build_tool_filters_block_blocklisted_tool() {
        let filters = build_tool_filters(&[], &[String::from("echo")]).expect("filters");

        assert!(!(filters.predicate)("echo", &json!({})));
        assert!(!(filters.name_predicate)("echo"));
        assert!((filters.predicate)("other", &json!({})));
        assert!((filters.name_predicate)("other"));
    }

    #[test]
    fn build_tool_filters_reject_non_allowlisted_tool() {
        let filters = build_tool_filters(&[String::from("echo")], &[]).expect("filters");

        assert!(!(filters.predicate)("other", &json!({})));
        assert!(!(filters.name_predicate)("other"));
        assert!((filters.predicate)("echo", &json!({})));
        assert!((filters.name_predicate)("echo"));
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
            warnings: Vec::new(),
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

            pre_run_hook: None,
            json: false,
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

            pre_run_hook: None,
            json: false,
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

            pre_run_hook: None,
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
            lenient_sourcing: true,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),

            pre_run_hook: None,
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
            pre_run_hook: Some("true".to_string()),
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

            pre_run_hook: None,
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

            pre_run_hook: None,
            json: true,
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

            pre_run_hook: None,
            json: true,
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

            pre_run_hook: None,
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

            pre_run_hook: None,
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
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),

            pre_run_hook: None,
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
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),

            pre_run_hook: None,
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
