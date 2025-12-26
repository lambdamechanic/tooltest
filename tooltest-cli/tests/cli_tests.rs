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

fn test_server() -> Option<&'static str> {
    option_env!("CARGO_BIN_EXE_tooltest_cli_test_server")
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
    let payload: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json output");
    assert_eq!(payload["outcome"]["status"], "success");
}

#[test]
fn stdio_command_reports_success_with_state_machine_mode() {
    let Some(server) = test_server() else {
        return;
    };
    let output = run_tooltest(&[
        "--generator-mode",
        "state-machine",
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
    let payload: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json output");
    assert_eq!(payload["outcome"]["status"], "failure");
}

#[test]
fn http_command_accepts_auth_token() {
    let output = run_tooltest(&[
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
