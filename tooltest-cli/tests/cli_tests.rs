use std::fs;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn run_tooltest(args: &[&str]) -> Output {
    let tooltest = env!("CARGO_BIN_EXE_tooltest");
    Command::new(tooltest)
        .args(args)
        .output()
        .expect("run tooltest")
}

fn run_tooltest_json(args: &[&str]) -> serde_json::Value {
    let output = run_tooltest(args);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
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

fn test_server() -> Option<&'static str> {
    let server = option_env!("CARGO_BIN_EXE_tooltest_cli_test_server")?;
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
    std::env::temp_dir().join(format!("tooltest-cli-{name}-{nanos}"))
}

#[test]
fn stdio_command_reports_success() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&["stdio", "--command", server, "--env", "FOO=bar"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
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

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
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
            "--cwd",
            &cwd.to_string_lossy(),
        ])
        .output()
        .expect("run tooltest");

    assert!(output.status.success());
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
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("tooltest_cli_test_server"));
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
    assert_eq!(output.status.code(), Some(2));
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
fn state_machine_coverage_validation_failure_emits_details_and_trace() {
    let Some(server) = test_server() else {
        return;
    };
    let config =
        r#"{"seed_strings":["alpha"],"coverage_rules":[{"rule":"min_calls_per_tool","min":2}]}"#;
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

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Outcome: failure"));
    assert!(stdout.contains("Code: coverage_validation_failed"));
    assert!(stdout.contains("Details:"));
    assert!(stdout.contains("Trace:"));
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
fn run_stdio_success_returns_exit_code_0() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&["stdio", "--command", server]);

    assert!(output.status.success());
}
