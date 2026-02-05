use chrono::DateTime;
use std::env;
use std::fs;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tooltest_core::{RunOutcome, RunResult, TraceEntry};
use tooltest_test_support as _;

fn tooltest_command(args: &[&str]) -> Command {
    let tooltest = env!("CARGO_BIN_EXE_tooltest");
    let mut full_args: Vec<&str> = args.to_vec();
    if args.contains(&"stdio") {
        full_args.push("--env");
        full_args.push("LLVM_PROFILE_FILE=/dev/null");
        full_args.push("--env");
        full_args.push("TOOLTEST_TEST_SERVER_ALLOW_STDIN=1");
    }
    let mut command = Command::new(tooltest);
    command.args(full_args);
    command
}

fn run_tooltest(args: &[&str]) -> Output {
    tooltest_command(args).output().expect("run tooltest")
}

fn run_tooltest_json(args: &[&str]) -> serde_json::Value {
    let output = run_tooltest(args);
    let outer_json = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "stderr: {}\nouter json:\n{}",
        String::from_utf8_lossy(&output.stderr),
        outer_json
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).expect("json output")
}

fn run_tooltest_json_allow_failure(args: &[&str]) -> (Output, serde_json::Value) {
    let output = run_tooltest(args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload = serde_json::from_str(stdout.trim()).expect("json output");
    (output, payload)
}

fn run_tooltest_run_result_allow_failure(args: &[&str]) -> (Output, RunResult) {
    let output = run_tooltest(args);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload = serde_json::from_str(stdout.trim()).expect("run result");
    (output, payload)
}

fn test_server() -> Option<&'static str> {
    let server = option_env!("CARGO_BIN_EXE_tooltest_test_server")?;
    if std::path::Path::new(server).exists() {
        Some(server)
    } else {
        None
    }
}

fn flaky_server() -> Option<&'static str> {
    let server = option_env!("CARGO_BIN_EXE_tooltest_flaky_stdio_server")?;
    if std::path::Path::new(server).exists() {
        Some(server)
    } else {
        None
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("tooltest-{name}-{nanos}"))
}

fn external_tests_enabled() -> bool {
    matches!(
        env::var("TOOLTEST_EXTERNAL_TESTS").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn external_cases() -> u32 {
    env::var("TOOLTEST_EXTERNAL_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1)
}

#[test]
fn config_default_emits_default_tooltest_toml() {
    let output = run_tooltest(&["config", "default"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# Tooltest lint configuration."));
    assert!(stdout.contains("version = 1"));
    assert!(stdout.contains("id = \"no_crash\""));
    assert!(stdout.contains("id = \"mcp_schema_min_version\""));
    assert!(stdout.contains("id = \"missing_structured_content\""));
    assert!(stdout.contains("level = \"error\""));
    assert!(stdout.contains("level = \"warning\""));
    assert!(stdout.contains("level = \"disabled\""));
    assert!(stdout.contains("# Enable by setting level = \"warning\" or \"error\"."));
    assert!(stdout.contains("https://json-schema.org/draft/2020-12/schema"));
    assert!(stdout.contains("https://json-schema.org/draft/2019-09/schema"));
    assert!(stdout.contains("http://json-schema.org/draft-07/schema"));
    assert!(stdout.contains("http://json-schema.org/draft-06/schema"));
    assert!(stdout.contains("http://json-schema.org/draft-04/schema"));
}

#[test]
fn test_server_binary_runs_with_empty_input() {
    let Some(server) = test_server() else {
        return;
    };
    let output = Command::new(server)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_remove("EXPECT_ARG")
        .env_remove("EXPECT_CWD")
        .env_remove("FORCE_CWD_ERROR")
        .env_remove("TOOLTEST_INVALID_OUTPUT_SCHEMA")
        .env_remove("TOOLTEST_REQUIRE_VALUE")
        .env_remove("TOOLTEST_VALUE_TYPE")
        .output()
        .expect("run test server");
    assert!(output.status.success());
}

#[test]
fn stdio_command_reports_success() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&["stdio", "--command", server, "--env", "FOO=bar"]);

    let outer_json = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "stderr: {}\nouter json:\n{}",
        String::from_utf8_lossy(&output.stderr),
        outer_json
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Outcome: success"));

    let json_output = run_tooltest(&["--json", "stdio", "--command", server, "--env", "FOO=bar"]);

    assert!(
        json_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&json_output.stderr)
    );

    let json_stdout = String::from_utf8_lossy(&json_output.stdout);
    let payload: serde_json::Value = serde_json::from_str(json_stdout.trim()).expect("json output");
    assert_eq!(payload["outcome"]["status"], "success");
}

#[test]
fn stdio_command_reports_success_with_state_machine_mode() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--json",
        "--state-machine-config",
        r#"{"seed_numbers":[1],"seed_strings":["hello"]}"#,
        "stdio",
        "--command",
        server,
    ]);

    let outer_json = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "stderr: {}\nouter json:\n{}",
        String::from_utf8_lossy(&output.stderr),
        outer_json
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json output");
    assert_eq!(payload["outcome"]["status"], "success");
}

#[test]
fn stdio_command_reports_coverage_warning_for_missing_string() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--cases",
        "50",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_REQUIRE_VALUE=1",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("Outcome: failure"), "stdout: {stdout}");
    assert!(stdout.contains("Coverage warnings:"), "stdout: {stdout}");
    assert!(stdout.contains("missing_string"), "stdout: {stdout}");
}

#[test]
fn stdio_command_reports_coverage_warning_for_missing_integer() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_REQUIRE_VALUE=1",
        "--env",
        "TOOLTEST_VALUE_TYPE=integer",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("Outcome: failure"), "stdout: {stdout}");
    assert!(stdout.contains("Coverage warnings:"), "stdout: {stdout}");
    assert!(stdout.contains("missing_integer"), "stdout: {stdout}");
}

#[test]
fn stdio_command_reports_coverage_warning_for_missing_number() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_REQUIRE_VALUE=1",
        "--env",
        "TOOLTEST_VALUE_TYPE=number",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("Outcome: failure"), "stdout: {stdout}");
    assert!(stdout.contains("Coverage warnings:"), "stdout: {stdout}");
    assert!(stdout.contains("missing_number"), "stdout: {stdout}");
}

#[test]
fn stdio_command_reports_uncallable_traces_in_human_output() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--cases",
        "1",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "--show-uncallable",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_TEST_SERVER_EXTRA_TOOL=alpha,bravo",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("Outcome: success"), "stdout: {stdout}");
    assert!(stdout.contains("Uncallable traces:"), "stdout: {stdout}");

    let mut tools = Vec::new();
    let mut lines = stdout.lines().peekable();
    let mut in_section = false;
    while let Some(line) = lines.next() {
        if line == "Uncallable traces:" {
            in_section = true;
            continue;
        }
        if !in_section {
            continue;
        }
        if line == "Warnings:" || line == "Trace:" {
            break;
        }
        if let Some(tool) = line
            .strip_prefix("- ")
            .and_then(|line| line.strip_suffix(':'))
        {
            tools.push(tool.to_string());
            let next = lines.next().unwrap_or_default();
            assert_eq!(next.trim(), "(no calls)", "stdout: {stdout}");
        }
    }

    assert_eq!(tools.len(), 2, "stdout: {stdout}");
    let mut sorted = tools.clone();
    sorted.sort();
    assert_eq!(tools, sorted, "stdout: {stdout}");
}

#[test]
fn stdio_command_omits_uncallable_traces_by_default() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--cases",
        "1",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_TEST_SERVER_EXTRA_TOOL=alpha,bravo",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(!stdout.contains("Uncallable traces:"), "stdout: {stdout}");
    assert!(!stdout.contains("Trace:"), "stdout: {stdout}");
}

#[test]
fn stdio_command_reports_uncallable_traces_in_json() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, result) = run_tooltest_run_result_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "--show-uncallable",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_TEST_SERVER_EXTRA_TOOL=alpha,bravo",
    ]);

    assert_eq!(output.status.code(), Some(0));
    let coverage = result.coverage.expect("coverage");
    let traces = coverage.uncallable_traces;
    assert_eq!(traces.len(), 2, "uncallable traces: {traces:?}");
    let keys: Vec<_> = traces.keys().cloned().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    for calls in traces.values() {
        assert!(calls.is_empty(), "uncallable trace list: {calls:?}");
    }
}

#[test]
fn stdio_command_omits_uncallable_traces_in_json_by_default() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, result) = run_tooltest_run_result_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_TEST_SERVER_EXTRA_TOOL=alpha,bravo",
    ]);

    assert_eq!(output.status.code(), Some(0));
    let coverage = result.coverage.expect("coverage");
    assert!(
        coverage.uncallable_traces.is_empty(),
        "uncallable traces: {:?}",
        coverage.uncallable_traces
    );
    assert!(result.trace.is_empty(), "trace: {:?}", result.trace);
}

#[test]
fn stdio_command_positive_error_omits_coverage_output() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, result) = run_tooltest_run_result_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_INVALID_OUTPUT_SCHEMA=1",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(result.coverage.is_none(), "coverage: {:?}", result.coverage);
}

#[test]
fn stdio_command_parses_uncallable_trace_timestamps() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, result) = run_tooltest_run_result_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--min-sequence-len",
        "3",
        "--max-sequence-len",
        "3",
        "--show-uncallable",
        "--uncallable-limit",
        "2",
        "--state-machine-config",
        r#"{}"#,
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_TEST_SERVER_CALL_ERROR=1",
    ]);

    assert_eq!(output.status.code(), Some(0));
    let coverage = result.coverage.expect("coverage");
    let calls = coverage.uncallable_traces.get("echo").expect("echo traces");
    assert_eq!(calls.len(), 2, "calls: {calls:?}");
    for call in calls {
        let _ = DateTime::parse_from_rfc3339(&call.timestamp).expect("timestamp RFC3339");
    }
}

#[test]
fn stdio_command_accepts_required_object_value() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_REQUIRE_VALUE=1",
        "--env",
        "TOOLTEST_VALUE_TYPE=object",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("Outcome: success"), "stdout: {stdout}");
    assert!(!stdout.contains("Coverage warnings:"), "stdout: {stdout}");
}

#[test]
fn stdio_command_accepts_lenient_sourcing_flag() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--lenient-sourcing",
        "--cases",
        "1",
        "stdio",
        "--command",
        server,
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn stdio_command_accepts_mine_text_flag() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&["--mine-text", "--cases", "1", "stdio", "--command", server]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn stdio_command_includes_corpus_dump_in_json() {
    let Some(server) = test_server() else {
        return;
    };
    let payload = run_tooltest_json(&[
        "--json",
        "--dump-corpus",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
    ]);

    let corpus = payload["corpus"].as_object().expect("corpus object");
    let strings = corpus["strings"].as_array().expect("corpus strings");
    assert!(
        strings.iter().any(|value| value == "status"),
        "corpus strings: {strings:?}"
    );
}

#[test]
fn stdio_command_dumps_corpus_to_stderr_when_not_json() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--dump-corpus",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("corpus:"), "stderr: {stderr}");
}

#[test]
fn stdio_command_logs_corpus_deltas_to_stderr() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--log-corpus-deltas",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("corpus delta after 'echo'"),
        "stderr: {stderr}"
    );
}

#[test]
fn cli_can_disable_lenient_sourcing_via_flag() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, payload) = run_tooltest_json_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--state-machine-config",
        r#"{"lenient_sourcing":true}"#,
        "--no-lenient-sourcing",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_REQUIRE_VALUE=1",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(payload["outcome"]["status"], "failure");
    let warnings = payload["coverage"]["warnings"]
        .as_array()
        .expect("coverage warnings");
    assert!(
        warnings
            .iter()
            .any(|warning| warning["reason"] == "missing_string"),
        "warnings: {warnings:?}"
    );
}

#[test]
fn cli_can_enable_lenient_sourcing_via_flag() {
    let Some(server) = test_server() else {
        return;
    };
    let payload = run_tooltest_json(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--state-machine-config",
        r#"{"lenient_sourcing":false}"#,
        "--lenient-sourcing",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_REQUIRE_VALUE=1",
    ]);

    let warnings = payload["coverage"]["warnings"]
        .as_array()
        .expect("coverage warnings");
    assert!(warnings.is_empty(), "warnings: {warnings:?}");
}

#[test]
fn cli_allows_tool_allowlist_match() {
    let Some(server) = test_server() else {
        return;
    };
    let payload = run_tooltest_json(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--tool-allowlist",
        "echo",
        "stdio",
        "--command",
        server,
    ]);

    assert_eq!(payload["outcome"]["status"], "success");
}

#[test]
fn cli_allows_tool_allowlist_with_extra_tools() {
    let Some(server) = test_server() else {
        return;
    };
    let payload = run_tooltest_json(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--tool-allowlist",
        "echo",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_TEST_SERVER_EXTRA_TOOL=alpha",
    ]);

    assert_eq!(payload["outcome"]["status"], "success");
}

#[test]
fn cli_rejects_tool_allowlist_with_invalid_extra_tools() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, payload) = run_tooltest_json_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--tool-allowlist",
        "echo",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_TEST_SERVER_INVALID_TOOL=1",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(payload["outcome"]["status"], "failure");
}

#[test]
fn cli_rejects_tool_allowlist_miss() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, payload) = run_tooltest_json_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--tool-allowlist",
        "Echo",
        "stdio",
        "--command",
        server,
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(payload["outcome"]["status"], "failure");
    let reason = payload["outcome"]["reason"]
        .as_str()
        .expect("failure reason");
    assert!(reason.contains("no eligible tools"), "reason: {reason}");
}

#[test]
fn cli_rejects_tool_blocklist_match() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, payload) = run_tooltest_json_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--tool-blocklist",
        "echo",
        "stdio",
        "--command",
        server,
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(payload["outcome"]["status"], "failure");
    let reason = payload["outcome"]["reason"]
        .as_str()
        .expect("failure reason");
    assert!(reason.contains("no eligible tools"), "reason: {reason}");
}

#[test]
fn cli_rejects_pre_run_hook_failure_with_details() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, payload) = run_tooltest_json_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--pre-run-hook",
        r#"echo pre-run-out; echo pre-run-err 1>&2; exit 7"#,
        "stdio",
        "--command",
        server,
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(payload["outcome"]["status"], "failure");
    assert_eq!(payload["outcome"]["code"], "pre_run_hook_failed");
    let details = &payload["outcome"]["details"];
    assert_eq!(details["exit_code"], 7);
    let stdout = details["stdout"].as_str().unwrap_or("");
    let stderr = details["stderr"].as_str().unwrap_or("");
    assert!(stdout.contains("pre-run-out"), "stdout: {stdout}");
    assert!(stderr.contains("pre-run-err"), "stderr: {stderr}");
}

#[test]
fn cli_rejects_pre_run_hook_start_failure() {
    let Some(server) = test_server() else {
        return;
    };
    let (output, payload) = run_tooltest_json_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--pre-run-hook",
        "echo ok",
        "stdio",
        "--command",
        server,
        "--env",
        "PATH=",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(payload["outcome"]["status"], "failure");
    assert_eq!(payload["outcome"]["code"], "pre_run_hook_failed");
    let reason = payload["outcome"]["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("pre-run hook failed to start"),
        "reason: {reason}"
    );
    let details = &payload["outcome"]["details"];
    assert!(details["exit_code"].is_null());
}

#[test]
fn cli_reports_pre_run_hook_failure_during_execution() {
    let Some(server) = test_server() else {
        return;
    };
    let dir = temp_dir("pre-run-fail-late");
    fs::create_dir_all(&dir).expect("create dir");
    let marker = dir.join("hook-marker");
    let hook = format!(
        "if [ -f \"{marker}\" ]; then echo pre-run-err 1>&2; exit 9; fi; touch \"{marker}\"",
        marker = marker.display()
    );
    let (output, payload) = run_tooltest_json_allow_failure(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--pre-run-hook",
        &hook,
        "stdio",
        "--command",
        server,
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(payload["outcome"]["status"], "failure");
    assert_eq!(payload["outcome"]["code"], "pre_run_hook_failed");
    let details = &payload["outcome"]["details"];
    assert_eq!(details["exit_code"], 9);
    assert!(marker.exists(), "pre-run hook did not create marker");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_pre_run_hook_inherits_stdio_env_and_cwd() {
    let Some(server) = test_server() else {
        return;
    };
    let cwd = temp_dir("pre-run-hook");
    fs::create_dir_all(&cwd).expect("create cwd");
    let cwd_string = cwd.to_string_lossy().into_owned();
    let hook = r#"test "$HOOK_ENV" = "expected" && test "$(pwd)" = "$HOOK_CWD""#;
    let payload = run_tooltest_json(&[
        "--json",
        "--cases",
        "1",
        "--max-sequence-len",
        "1",
        "--pre-run-hook",
        hook,
        "stdio",
        "--command",
        server,
        "--env",
        "HOOK_ENV=expected",
        "--env",
        &format!("HOOK_CWD={cwd_string}"),
        "--cwd",
        &cwd_string,
    ]);
    let _ = fs::remove_dir_all(&cwd);

    assert_eq!(payload["outcome"]["status"], "success");
}

#[test]
fn cli_runs_pre_run_hook_before_validation() {
    let Some(server) = test_server() else {
        return;
    };
    let dir = temp_dir("pre-run-before-validation");
    fs::create_dir_all(&dir).expect("create dir");
    let marker = dir.join("hook-ran");
    let hook = format!("printf 'hook' > \"{}\"", marker.display());
    let (output, payload) = run_tooltest_json_allow_failure(&[
        "--json",
        "--pre-run-hook",
        &hook,
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_INVALID_OUTPUT_SCHEMA=1",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(payload["outcome"]["status"], "failure");
    assert!(marker.exists(), "pre-run hook did not create marker");
}

#[test]
fn run_stdio_reports_success_with_env_and_cwd() {
    let Some(server) = test_server() else {
        return;
    };
    let cwd = temp_dir("run-stdio");
    fs::create_dir_all(&cwd).expect("create cwd");
    let expected_arg = "--expected";
    let output = Command::new(env!("CARGO_BIN_EXE_tooltest"))
        .args([
            "--json",
            "stdio",
            "--command",
            server,
            &format!("--arg={expected_arg}"),
            "--env",
            &format!("EXPECT_ARG={expected_arg}"),
            "--env",
            &format!("EXPECT_CWD={}", cwd.display()),
            "--env",
            "TOOLTEST_TEST_SERVER_ALLOW_STDIN=1",
            "--env",
            "LLVM_PROFILE_FILE=/dev/null",
            "--cwd",
            &cwd.to_string_lossy(),
        ])
        .output()
        .expect("run tooltest");

    assert!(output.status.success());
}

#[test]
fn tooltest_dogfoods_tooltest_stdio() {
    let Some(server) = flaky_server() else {
        return;
    };
    let config_dir = temp_dir("dogfood");
    fs::create_dir_all(&config_dir).expect("create temp dir");
    let config_path = config_dir.join("state-machine.json");
    let config_payload = serde_json::json!({
        "seed_numbers": [1, 3, 30],
    });
    let config_payload =
        serde_json::to_string(&config_payload).expect("serialize state machine config");
    fs::write(&config_path, config_payload).expect("write config");
    let config_arg = format!("@{}", config_path.display());
    let dogfood_env = format!("TOOLTEST_MCP_DOGFOOD_COMMAND={server}");
    let tooltest = env!("CARGO_BIN_EXE_tooltest");
    let trace_path = config_dir.join("trace-all.jsonl");
    let trace_arg = trace_path.to_string_lossy().to_string();

    let (output, run_result) = run_tooltest_run_result_allow_failure(&[
        "--json",
        "--full-trace",
        "--trace-all",
        &trace_arg,
        "--tool-allowlist",
        "tooltest",
        "--cases",
        "50",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "--no-lenient-sourcing",
        "--state-machine-config",
        &config_arg,
        "stdio",
        "--command",
        tooltest,
        "--arg",
        "mcp",
        "--env",
        &dogfood_env,
    ]);

    let outer_json = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "stderr: {}\nouter json:\n{}",
        String::from_utf8_lossy(&output.stderr),
        outer_json
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stdout-noise bucket hit"),
        "expected stdout-noise marker in stderr\nouter json:\n{}",
        outer_json
    );
    assert!(
        stderr.contains("crash bucket hit"),
        "expected crash marker in stderr\nouter json:\n{}",
        outer_json
    );
    assert!(
        matches!(run_result.outcome, RunOutcome::Success),
        "outer run failed: {:?}\nouter json:\n{}",
        run_result.outcome,
        outer_json
    );

    let trace_payload = fs::read_to_string(&trace_path).expect("read trace-all output");
    let mut lines = trace_payload.lines();
    let header = lines.next().expect("trace-all header");
    let header_value: serde_json::Value =
        serde_json::from_str(header).expect("trace-all header json");
    assert_eq!(header_value["format"], "trace_all_v1");

    #[derive(serde::Deserialize)]
    struct TraceRecord {
        #[allow(dead_code)]
        case: u64,
        trace: Vec<TraceEntry>,
    }

    let mut inner_results = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let record: TraceRecord = serde_json::from_str(line).expect("trace-all record");
        for entry in record.trace {
            let TraceEntry::ToolCall {
                invocation,
                response,
                failure_reason,
            } = entry
            else {
                continue;
            };
            if invocation.name.as_ref() != "tooltest" {
                continue;
            }
            assert!(
                failure_reason.is_none(),
                "tooltest call failed: {failure_reason:?}"
            );
            let response = response.expect("tooltest response");
            assert_ne!(
                response.is_error,
                Some(true),
                "tooltest response reported isError"
            );
            let structured = response
                .structured_content
                .expect("tooltest structured content");
            let inner: RunResult = serde_json::from_value(structured).expect("inner run result");
            inner_results.push(inner);
        }
    }

    assert!(
        !inner_results.is_empty(),
        "missing tooltest traces in trace-all output\nouter json:\n{}",
        outer_json
    );

    let mut saw_success = false;
    let mut saw_in_band_error = false;
    let mut saw_catastrophic = false;
    let mut unexpected_failures = Vec::new();

    for inner in inner_results {
        match &inner.outcome {
            RunOutcome::Success => {
                saw_success = true;
            }
            RunOutcome::Failure(failure) => {
                let reason = failure.reason.as_str();
                if reason.contains("TransportClosed") || reason.contains("session error") {
                    saw_catastrophic = true;
                } else {
                    unexpected_failures.push(failure.reason.clone());
                }
            }
        }
        if let Some(coverage) = inner.coverage.as_ref() {
            let failures = coverage.failures.get("flaky_echo").copied().unwrap_or(0);
            if failures > 0 {
                saw_in_band_error = true;
            }
        }
    }

    assert!(
        unexpected_failures.is_empty(),
        "unexpected inner failures: {unexpected_failures:?}\nouter json:\n{}",
        outer_json
    );
    assert!(
        saw_success,
        "expected at least one inner success\nouter json:\n{}",
        outer_json
    );
    assert!(
        saw_in_band_error,
        "expected at least one in-band error\nouter json:\n{}",
        outer_json
    );
    assert!(
        saw_catastrophic,
        "expected at least one catastrophic failure\nouter json:\n{}",
        outer_json
    );
}

#[cfg(unix)]
#[test]
fn tooltest_dogfoods_tooltest_stdio_via_shell_wrapper() {
    let Some(flaky) = flaky_server() else {
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let config_dir = temp_dir("dogfood-shell");
    fs::create_dir_all(&config_dir).expect("create temp dir");
    let config_path = config_dir.join("state-machine.json");
    let config_payload = serde_json::json!({
        "seed_numbers": [1, 3, 30],
    });
    let config_payload =
        serde_json::to_string(&config_payload).expect("serialize state machine config");
    fs::write(&config_path, config_payload).expect("write config");
    let config_arg = format!("@{}", config_path.display());
    let tooltest = env!("CARGO_BIN_EXE_tooltest");
    let wrapper_path = config_dir.join("tooltest-mcp-wrapper.sh");
    let wrapper_script = format!(
        r#"#!/bin/sh
set -eu
exec env -i TOOLTEST_MCP_DOGFOOD_COMMAND="{flaky}" LLVM_PROFILE_FILE=/dev/null TOOLTEST_TEST_SERVER_ALLOW_STDIN=1 "{tooltest}" mcp --stdio
"#,
        flaky = flaky,
        tooltest = tooltest
    );
    fs::write(&wrapper_path, wrapper_script).expect("write wrapper script");
    let mut perms = fs::metadata(&wrapper_path)
        .expect("stat wrapper script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&wrapper_path, perms).expect("chmod wrapper script");
    let wrapper_arg = wrapper_path.to_string_lossy().to_string();
    let trace_path = config_dir.join("trace-all.jsonl");
    let trace_arg = trace_path.to_string_lossy().to_string();

    let (output, run_result) = run_tooltest_run_result_allow_failure(&[
        "--json",
        "--full-trace",
        "--trace-all",
        &trace_arg,
        "--tool-allowlist",
        "tooltest",
        "--cases",
        "50",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "--no-lenient-sourcing",
        "--state-machine-config",
        &config_arg,
        "stdio",
        "--command",
        &wrapper_arg,
    ]);

    let outer_json = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "stderr: {}\nouter json:\n{}",
        String::from_utf8_lossy(&output.stderr),
        outer_json
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stdout-noise bucket hit"),
        "expected stdout-noise marker in stderr\nouter json:\n{}",
        outer_json
    );
    assert!(
        stderr.contains("crash bucket hit"),
        "expected crash marker in stderr\nouter json:\n{}",
        outer_json
    );
    assert!(
        matches!(run_result.outcome, RunOutcome::Success),
        "outer run failed: {:?}\nouter json:\n{}",
        run_result.outcome,
        outer_json
    );

    let trace_payload = fs::read_to_string(&trace_path).expect("read trace-all output");
    let mut lines = trace_payload.lines();
    let header = lines.next().expect("trace-all header");
    let header_value: serde_json::Value =
        serde_json::from_str(header).expect("trace-all header json");
    assert_eq!(header_value["format"], "trace_all_v1");

    #[derive(serde::Deserialize)]
    struct TraceRecord {
        #[allow(dead_code)]
        case: u64,
        trace: Vec<TraceEntry>,
    }

    let mut inner_results = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let record: TraceRecord = serde_json::from_str(line).expect("trace-all record");
        for entry in record.trace {
            let TraceEntry::ToolCall {
                invocation,
                response,
                failure_reason,
            } = entry
            else {
                continue;
            };
            if invocation.name.as_ref() != "tooltest" {
                continue;
            }
            assert!(
                failure_reason.is_none(),
                "tooltest call failed: {failure_reason:?}"
            );
            let response = response.expect("tooltest response");
            assert_ne!(
                response.is_error,
                Some(true),
                "tooltest response reported isError"
            );
            let structured = response
                .structured_content
                .expect("tooltest structured content");
            let inner: RunResult = serde_json::from_value(structured).expect("inner run result");
            inner_results.push(inner);
        }
    }

    assert!(
        !inner_results.is_empty(),
        "missing tooltest traces in trace-all output\nouter json:\n{}",
        outer_json
    );

    let mut saw_success = false;
    let mut saw_in_band_error = false;
    let mut saw_catastrophic = false;
    let mut unexpected_failures = Vec::new();

    for inner in inner_results {
        match &inner.outcome {
            RunOutcome::Success => {
                saw_success = true;
            }
            RunOutcome::Failure(failure) => {
                let reason = failure.reason.as_str();
                if reason.contains("TransportClosed") || reason.contains("session error") {
                    saw_catastrophic = true;
                } else {
                    unexpected_failures.push(failure.reason.clone());
                }
            }
        }
        if let Some(coverage) = inner.coverage.as_ref() {
            let failures = coverage.failures.get("flaky_echo").copied().unwrap_or(0);
            if failures > 0 {
                saw_in_band_error = true;
            }
        }
    }

    assert!(
        unexpected_failures.is_empty(),
        "unexpected inner failures: {unexpected_failures:?}\nouter json:\n{}",
        outer_json
    );
    assert!(
        saw_success,
        "expected at least one inner success\nouter json:\n{}",
        outer_json
    );
    assert!(
        saw_in_band_error,
        "expected at least one in-band error\nouter json:\n{}",
        outer_json
    );
    assert!(
        saw_catastrophic,
        "expected at least one catastrophic failure\nouter json:\n{}",
        outer_json
    );
}

#[test]
fn test_server_exits_on_expectation_failure() {
    let Some(server) = test_server() else {
        return;
    };
    let output = Command::new(server)
        .env("EXPECT_ARG", "missing-arg")
        .output()
        .expect("run test server");
    let expected = if cfg!(coverage) { Some(101) } else { Some(2) };
    assert_eq!(output.status.code(), expected);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("tooltest_test_server"));
}

#[test]
fn test_server_exits_on_forced_cwd_error() {
    let Some(server) = test_server() else {
        return;
    };
    let output = Command::new(server)
        .env("EXPECT_CWD", "unused")
        .env("FORCE_CWD_ERROR", "1")
        .output()
        .expect("run test server");
    let expected = if cfg!(coverage) { Some(101) } else { Some(2) };
    assert_eq!(output.status.code(), expected);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to read cwd"));
}

#[test]
fn test_server_exits_cleanly_without_input() {
    let Some(server) = test_server() else {
        return;
    };
    let output = Command::new(server)
        .env_remove("EXPECT_ARG")
        .env_remove("EXPECT_CWD")
        .stdin(Stdio::null())
        .output()
        .expect("run test server");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn stdio_command_rejects_bad_env_entry() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&["stdio", "--command", server, "--env", "NOPE"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid env entry"));
}

#[test]
fn stdio_command_rejects_empty_env_key() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&["stdio", "--command", server, "--env", "=value"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid env entry"));
}

#[test]
fn sequence_len_zero_exits() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&["--min-sequence-len", "0", "stdio", "--command", server]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("min-sequence-len"));
}

#[test]
fn sequence_len_inverted_exits() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--min-sequence-len",
        "4",
        "--max-sequence-len",
        "2",
        "stdio",
        "--command",
        server,
    ]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("min-sequence-len"));
}

#[test]
fn sequence_len_inverted_exits_with_json_error() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--json",
        "--min-sequence-len",
        "4",
        "--max-sequence-len",
        "2",
        "stdio",
        "--command",
        server,
    ]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("\"status\": \"error\""));
}

#[test]
fn state_machine_config_invalid_json_exits() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--state-machine-config",
        "{bad json}",
        "stdio",
        "--command",
        server,
    ]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid state-machine-config"));
}

#[test]
fn state_machine_coverage_warnings_reported() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--cases",
        "1",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_REQUIRE_VALUE=1",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("Outcome: failure"), "stdout: {stdout}");
    assert!(stdout.contains("Coverage warnings:"), "stdout: {stdout}");
    assert!(stdout.contains("missing_string"), "stdout: {stdout}");
}

#[test]
fn state_machine_schema_warning_emits_human_warning_code() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--cases",
        "1",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "stdio",
        "--command",
        server,
        "--env",
        "TOOLTEST_SCHEMA_DEFS_WARNING=1",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("Warnings:"), "stdout: {stdout}");
    assert!(
        stdout.contains("lint.json_schema_keyword_compat"),
        "stdout: {stdout}"
    );
}

#[test]
fn trace_all_emits_trace_lines() {
    let Some(server) = test_server() else {
        return;
    };
    let dir = temp_dir("trace-all");
    fs::create_dir_all(&dir).expect("create trace dir");
    let trace_path = dir.join("trace.jsonl");
    let trace_path_str = trace_path.to_str().expect("trace path");
    let output = run_tooltest(&[
        "--cases",
        "1",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "--trace-all",
        trace_path_str,
        "stdio",
        "--command",
        server,
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    let trace_contents = fs::read_to_string(&trace_path).expect("read trace file");
    assert!(
        trace_contents.contains("\"format\":\"trace_all_v1\""),
        "trace: {trace_contents}"
    );
    assert!(
        trace_contents.contains("\"case\":0"),
        "trace: {trace_contents}"
    );
    fs::remove_dir_all(&dir).expect("remove trace dir");
}

#[test]
fn trace_all_rejects_directory_path() {
    let Some(server) = test_server() else {
        return;
    };
    let dir = temp_dir("trace-all-dir");
    fs::create_dir_all(&dir).expect("create trace dir");
    let dir_path = dir.to_str().expect("trace dir path");
    let output = run_tooltest(&["--trace-all", dir_path, "stdio", "--command", server]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to write trace file"),
        "stderr: {stderr}"
    );
    fs::remove_dir_all(&dir).expect("remove trace dir");
}

#[test]
fn state_machine_config_does_not_trigger_coverage_validation() {
    let Some(server) = test_server() else {
        return;
    };
    let config = r#"{"seed_strings":["alpha"]}"#;
    let output = run_tooltest(&[
        "--cases",
        "1",
        "--min-sequence-len",
        "1",
        "--max-sequence-len",
        "1",
        "--state-machine-config",
        config,
        "stdio",
        "--command",
        server,
        "--env",
        "REQUIRE_VALUE=1",
    ]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Outcome: success"));
    assert!(!stdout.contains("Code: coverage_validation_failed"));
}

#[test]
fn state_machine_config_invalid_json_exits_with_json_error() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--json",
        "--state-machine-config",
        "{bad json}",
        "stdio",
        "--command",
        server,
    ]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let payload: serde_json::Value = serde_json::from_str(stderr.trim()).expect("json error");
    assert_eq!(payload["status"], "error");
    assert!(payload["message"]
        .as_str()
        .unwrap_or("")
        .contains("state-machine-config"));
}

#[test]
fn stdio_command_passes_args() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "stdio",
        "--command",
        server,
        "--arg",
        "expected-arg",
        "--env",
        "EXPECT_ARG=expected-arg",
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn stdio_command_sets_cwd() {
    let Some(server) = test_server() else {
        return;
    };
    let dir = temp_dir("cwd");
    fs::create_dir_all(&dir).expect("create temp dir");
    let dir_string = dir.to_string_lossy().into_owned();
    let env_value = format!("EXPECT_CWD={dir_string}");
    let output = run_tooltest(&[
        "stdio",
        "--command",
        server,
        "--cwd",
        &dir_string,
        "--env",
        &env_value,
    ]);
    let _ = fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn http_command_reports_failure() {
    let output = run_tooltest(&["http", "--url", "http://127.0.0.1:0/mcp"]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Outcome: failure"));
    assert!(stdout.contains("Reason:"));
}

#[test]
fn http_command_accepts_auth_token() {
    let output = run_tooltest(&[
        "--json",
        "http",
        "--url",
        "http://127.0.0.1:0/mcp",
        "--auth-token",
        "Bearer test-token",
    ]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json output");
    assert_eq!(payload["outcome"]["status"], "failure");
}

#[test]
fn run_http_failure_returns_exit_code_1() {
    let output = run_tooltest(&[
        "--state-machine-config",
        r#"{"seed_numbers":[1]}"#,
        "http",
        "--url",
        "http://127.0.0.1:0/mcp",
    ]);

    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn run_http_failure_with_dump_corpus_skips_output() {
    let output = run_tooltest(&["--dump-corpus", "http", "--url", "http://127.0.0.1:0/mcp"]);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("corpus:"), "stderr: {stderr}");
}

#[test]
fn run_invalid_sequence_len_returns_exit_code_2() {
    let output = run_tooltest(&[
        "--min-sequence-len",
        "0",
        "http",
        "--url",
        "http://127.0.0.1:0/mcp",
    ]);

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn run_invalid_state_machine_config_returns_exit_code_2() {
    let output = run_tooltest(&[
        "--state-machine-config",
        "not-json",
        "http",
        "--url",
        "http://127.0.0.1:0/mcp",
    ]);

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn run_missing_state_machine_config_file_returns_exit_code_2() {
    let output = run_tooltest(&[
        "--state-machine-config",
        "@/nonexistent-tooltest-config.json",
        "http",
        "--url",
        "http://127.0.0.1:0/mcp",
    ]);

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn run_invalid_uncallable_limit_returns_exit_code_2() {
    let output = run_tooltest(&[
        "--uncallable-limit",
        "0",
        "http",
        "--url",
        "http://127.0.0.1:0/mcp",
    ]);

    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn run_stdio_success_returns_exit_code_0() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&["stdio", "--command", server]);

    assert!(output.status.success());
}
#[test]
fn stdio_command_runs_playwright_mcp() {
    if !external_tests_enabled() {
        return;
    }
    let cases = external_cases().to_string();
    let config = r#"{"seed_strings":["https://google.com"]}"#;
    let command_line = "npx -y @playwright/mcp@latest";
    let (output, payload) = run_tooltest_json_allow_failure(&[
        "--cases",
        &cases,
        "--max-sequence-len",
        "1",
        "--json",
        "--state-machine-config",
        config,
        "stdio",
        "--command",
        command_line,
    ]);

    assert!(
        output.status.success(),
        "stderr: {}\njson: {payload:?}",
        String::from_utf8_lossy(&output.stderr),
    );
}
