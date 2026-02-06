use super::*;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::OnceLock;

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
    CoverageWarning, CoverageWarningReason, HttpConfig, ListToolsError, RunFailure, RunOutcome,
    RunResult, RunWarning, RunWarningCode, SchemaConfig, SessionDriver, StdioConfig,
    ToolInvocation, TooltestHttpTarget, TooltestStdioTarget, TooltestTarget, TraceEntry, TraceSink,
    UncallableToolCall,
};
use tooltest_test_support::{
    stub_tool, temp_path, EnvVarGuard, FaultyListToolsTransport, ListToolsTransport, TransportError,
};

fn expect_stdio_target(target: TooltestTarget) -> TooltestStdioTarget {
    match target {
        TooltestTarget::Stdio(wrapper) => wrapper.stdio,
        TooltestTarget::Http(_) => panic!("expected stdio target"),
    }
}

fn expect_http_target(target: TooltestTarget) -> TooltestHttpTarget {
    match target {
        TooltestTarget::Http(wrapper) => wrapper.http,
        TooltestTarget::Stdio(_) => panic!("expected http target"),
    }
}

static MCP_ENV_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn mcp_env_lock() -> &'static tokio::sync::Mutex<()> {
    MCP_ENV_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
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
    let path = temp_path("state-machine.json");
    fs::write(&path, r#"{"seed_numbers":[2],"seed_strings":["beta"]}"#).expect("write config");
    let config = parse_state_machine_config(&format!("@{}", path.display())).expect("config");
    assert_eq!(config.seed_numbers.len(), 1);
    assert_eq!(config.seed_strings.len(), 1);
    let _ = fs::remove_file(&path);
}

#[test]
fn parse_state_machine_config_rejects_invalid_json() {
    let error = parse_state_machine_config("{bad json}").expect_err("error");
    assert!(error.contains("invalid state-machine-config"));
}

#[test]
fn parse_state_machine_config_rejects_missing_file() {
    let path = temp_path("missing.json");
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

    let missing = temp_path("missing-stdio");
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
    let stdio = expect_stdio_target(input.target);
    assert_eq!(stdio.command, "server");
    assert_eq!(stdio.args, vec!["flag".to_string()]);
    assert_eq!(stdio.env.get("FOO"), Some(&"bar".to_string()));
    assert_eq!(stdio.cwd.as_deref(), Some("/tmp"));
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
    let http = expect_http_target(input.target);
    assert_eq!(http.url, "http://127.0.0.1:0/mcp");
    assert_eq!(http.auth_token.as_deref(), Some("secret"));
}

#[test]
fn tooltest_input_rejects_config_command() {
    let cli = Cli::parse_from(["tooltest", "config", "default"]);
    let error = build_tooltest_input(&cli).expect_err("error");
    assert!(error.contains("config command does not accept tooltest input"));
}

#[test]
#[should_panic(expected = "expected stdio target")]
fn expect_stdio_target_panics_on_http() {
    let cli = Cli::parse_from(["tooltest", "http", "--url", "http://127.0.0.1:0/mcp"]);
    let input = build_tooltest_input(&cli).expect("input");
    let _ = expect_stdio_target(input.target);
}

#[test]
#[should_panic(expected = "expected http target")]
fn expect_http_target_panics_on_stdio() {
    let cli = Cli::parse_from(["tooltest", "stdio", "--command", "server"]);
    let input = build_tooltest_input(&cli).expect("input");
    let _ = expect_http_target(input.target);
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
fn cli_parses_config_default_command() {
    let cli = Cli::parse_from(["tooltest", "config", "default"]);
    assert_eq!(
        cli.command,
        Command::Config {
            command: ConfigCommand::Default
        }
    );
}

#[tokio::test]
async fn run_config_default_exits_successfully() {
    let cli = Cli::parse_from(["tooltest", "config", "default"]);
    let exit = run(cli).await;
    assert_eq!(exit, ExitCode::SUCCESS);
}

#[test]
fn format_run_warning_code_supports_lint_codes() {
    assert_eq!(
        crate::output::format_run_warning_code(
            &RunWarningCode::lint("missing_structured_content",)
        ),
        "lint.missing_structured_content"
    );
}

#[test]
fn mcp_command_accepts_explicit_stdio_transport() {
    let cli = Cli::parse_from(["tooltest", "mcp", "--stdio"]);
    assert!(cli.command == Command::Mcp { stdio: true });
}

#[tokio::test]
async fn run_mcp_stdio_exits_successfully() {
    let _lock = mcp_env_lock().lock().await;
    let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
    let _guard = EnvVarGuard::set("TOOLTEST_MCP_EXIT_IMMEDIATELY", "1");
    let cli = Cli::parse_from(["tooltest", "mcp", "--stdio"]);
    let exit = run(cli).await;
    assert_eq!(exit, ExitCode::SUCCESS);
}

#[tokio::test]
async fn run_mcp_stdio_waits_for_transport_shutdown() {
    let _lock = mcp_env_lock().lock().await;
    let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
    let cli = Cli::parse_from(["tooltest", "mcp", "--stdio"]);
    let exit = run(cli).await;
    assert_eq!(exit, ExitCode::SUCCESS);
}

#[test]
fn run_mcp_stdio_without_test_transport_reports_error() {
    // Run the real-stdio path in a subprocess so it can't block on the interactive terminal.
    // This test binary is already built, so spawning it is cheap and stable.
    let _lock = futures::executor::block_on(mcp_env_lock().lock());
    let exe = std::env::current_exe().expect("current test binary");
    let output = ProcessCommand::new(exe)
        .arg("--ignored")
        .arg("--exact")
        .arg("--nocapture")
        .arg("tests::run_mcp_stdio_without_test_transport_reports_error_child")
        .stdin(Stdio::null())
        .env_remove("TOOLTEST_MCP_TEST_TRANSPORT")
        .env_remove("TOOLTEST_MCP_EXIT_IMMEDIATELY")
        .env_remove("TOOLTEST_MCP_BAD_TRANSPORT")
        .env_remove("TOOLTEST_MCP_PANIC_TRANSPORT")
        .output()
        .expect("run child stdio test");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1 passed"));
}

#[ignore]
#[tokio::test]
async fn run_mcp_stdio_without_test_transport_reports_error_child() {
    let _lock = mcp_env_lock().lock().await;
    env::remove_var("TOOLTEST_MCP_TEST_TRANSPORT");
    env::remove_var("TOOLTEST_MCP_EXIT_IMMEDIATELY");
    env::remove_var("TOOLTEST_MCP_BAD_TRANSPORT");
    env::remove_var("TOOLTEST_MCP_PANIC_TRANSPORT");
    let error = mcp::run_stdio().await.expect_err("expected error");
    assert!(error.contains("failed to start MCP stdio server"));
}

#[tokio::test]
async fn run_mcp_stdio_bad_transport_reports_error() {
    let _lock = mcp_env_lock().lock().await;
    let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
    let _bad_guard = EnvVarGuard::set("TOOLTEST_MCP_BAD_TRANSPORT", "1");
    let result = mcp::run_stdio().await;
    assert!(result
        .expect_err("expected error")
        .contains("failed to start MCP stdio server"));
}

#[tokio::test]
async fn run_mcp_stdio_bad_transport_returns_exit_code_2() {
    let _lock = mcp_env_lock().lock().await;
    let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
    let _bad_guard = EnvVarGuard::set("TOOLTEST_MCP_BAD_TRANSPORT", "1");
    let cli = Cli::parse_from(["tooltest", "mcp", "--stdio"]);
    let exit = run(cli).await;
    assert_eq!(exit, ExitCode::from(2));
}

#[tokio::test]
async fn run_mcp_stdio_panic_transport_reports_error() {
    let _lock = mcp_env_lock().lock().await;
    let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
    let _panic_guard = EnvVarGuard::set("TOOLTEST_MCP_PANIC_TRANSPORT", "1");
    let result = mcp::run_stdio().await;
    assert!(result
        .expect_err("expected error")
        .contains("MCP stdio server failed"));
}

#[tokio::test]
async fn run_mcp_stdio_exit_immediately_reports_error_on_panic() {
    let _lock = mcp_env_lock().lock().await;
    let _transport_guard = EnvVarGuard::set("TOOLTEST_MCP_TEST_TRANSPORT", "1");
    let _panic_guard = EnvVarGuard::set("TOOLTEST_MCP_PANIC_TRANSPORT", "1");
    let _exit_guard = EnvVarGuard::set("TOOLTEST_MCP_EXIT_IMMEDIATELY", "1");
    let result = mcp::run_stdio().await;
    assert!(result
        .expect_err("expected error")
        .contains("MCP stdio server failed"));
}

#[test]
fn env_var_guard_restores_previous_value() {
    let _lock = futures::executor::block_on(mcp_env_lock().lock());
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
fn format_run_result_human_reports_failure_without_details() {
    let failure = RunFailure {
        reason: "nope".to_string(),
        code: None,
        details: None,
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
    assert!(output.contains("Reason: nope"));
    assert!(!output.contains("Code:"));
    assert!(!output.contains("Details:"));
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
fn format_run_result_human_skips_empty_coverage_failures() {
    let mut failures = BTreeMap::new();
    failures.insert("alpha".to_string(), 0);
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
    assert!(!output.contains("Coverage failures:"));
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
fn format_run_result_human_reports_empty_uncallable_arguments() {
    let invocation = ToolInvocation {
        name: "alpha".into(),
        arguments: None,
    };
    let call = UncallableToolCall {
        input: invocation,
        output: None,
        error: None,
        timestamp: "2024-01-03T00:00:00Z".to_string(),
    };
    let mut uncallable_traces = BTreeMap::new();
    uncallable_traces.insert("alpha".to_string(), vec![call]);
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
    assert!(output.contains("arguments:"));
    assert!(output.contains("{}"));
}

#[test]
fn format_run_result_human_reports_warnings() {
    let result = RunResult {
        outcome: RunOutcome::Success,
        trace: Vec::new(),
        minimized: None,
        warnings: vec![RunWarning {
            code: RunWarningCode("custom_warning".to_string()),
            message: "schema warning".to_string(),
            tool: Some("echo".to_string()),
            details: None,
        }],
        coverage: None,
        corpus: None,
    };

    let output = format_run_result_human(&result);
    assert!(output.contains("Warnings:"));
    assert!(output.contains("custom_warning"));
    assert!(output.contains("schema warning"));
    assert!(output.contains("echo"));
}

#[test]
fn format_run_result_human_reports_lint_warning_code() {
    let result = RunResult {
        outcome: RunOutcome::Success,
        trace: Vec::new(),
        minimized: None,
        warnings: vec![RunWarning {
            code: RunWarningCode::lint("missing_structured_content"),
            message: "lint missing_structured_content: lint warning".to_string(),
            tool: None,
            details: Some(serde_json::json!({ "lint_id": "missing_structured_content" })),
        }],
        coverage: None,
        corpus: None,
    };

    let output = format_run_result_human(&result);
    assert!(output.contains("lint.missing_structured_content"));
    assert!(output.contains("lint warning"));
    assert!(output.contains("missing_structured_content"));
}

#[test]
fn format_run_result_human_reports_warning_without_tool() {
    let result = RunResult {
        outcome: RunOutcome::Success,
        trace: Vec::new(),
        minimized: None,
        warnings: vec![RunWarning {
            code: RunWarningCode("custom_warning".to_string()),
            message: "standalone warning".to_string(),
            tool: None,
            details: None,
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

    let _ = fs::OpenOptions::new().write(true).open(path).expect("open");
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

#[cfg(target_os = "linux")]
#[tokio::test]
async fn run_exits_on_trace_all_write_error() {
    let trace_path = std::path::Path::new("/dev/full");
    assert!(trace_path.exists());
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
        trace_all: Some(trace_path.to_string_lossy().to_string()),
        command: Command::Stdio {
            command: "tooltest-missing-binary".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
        },
    };

    let exit = run(cli).await;
    assert_eq!(exit, ExitCode::from(2));
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
