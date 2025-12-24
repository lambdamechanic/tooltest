use std::process::{Command, Output};

fn run_tooltest(args: &[&str]) -> Output {
    let tooltest = env!("CARGO_BIN_EXE_tooltest");
    Command::new(tooltest)
        .args(args)
        .output()
        .expect("run tooltest")
}

#[test]
fn stdio_command_reports_success() {
    let server = env!("CARGO_BIN_EXE_tooltest_cli_test_server");
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
fn stdio_command_rejects_bad_env_entry() {
    let server = env!("CARGO_BIN_EXE_tooltest_cli_test_server");
    let output = run_tooltest(&["stdio", "--command", server, "--env", "NOPE"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid env entry"));
}

#[test]
fn stdio_command_rejects_empty_env_key() {
    let server = env!("CARGO_BIN_EXE_tooltest_cli_test_server");
    let output = run_tooltest(&["stdio", "--command", server, "--env", "=value"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid env entry"));
}

#[test]
fn sequence_len_zero_exits() {
    let server = env!("CARGO_BIN_EXE_tooltest_cli_test_server");
    let output = run_tooltest(&["--min-sequence-len", "0", "stdio", "--command", server]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("min-sequence-len"));
}

#[test]
fn sequence_len_inverted_exits() {
    let server = env!("CARGO_BIN_EXE_tooltest_cli_test_server");
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
fn http_command_reports_failure() {
    let output = run_tooltest(&["http", "--url", "http://127.0.0.1:0/mcp"]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json output");
    assert_eq!(payload["outcome"]["status"], "failure");
}
