use std::fs;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn run_tooltest(args: &[&str]) -> Output {
    let tooltest = env!("CARGO_BIN_EXE_tooltest");
    let mut full_args: Vec<&str> = args.to_vec();
    if args.iter().any(|arg| *arg == "stdio") {
        full_args.push("--env");
        full_args.push("LLVM_PROFILE_FILE=/dev/null");
        full_args.push("--env");
        full_args.push("TOOLTEST_TEST_SERVER_ALLOW_STDIN=1");
    }
    Command::new(tooltest)
        .args(full_args)
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
    let server = option_env!("CARGO_BIN_EXE_tooltest_test_server")?;
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
fn run_stdio_success_returns_exit_code_0() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&["stdio", "--command", server]);

    assert!(output.status.success());
}
