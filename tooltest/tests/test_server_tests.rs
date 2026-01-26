use std::io::{self, Write};
use std::sync::Mutex;

#[path = "../src/test_server.rs"]
mod test_server;

use rmcp::model::{
    CallToolRequest, CallToolRequestParam, ClientJsonRpcMessage, ClientNotification, ClientRequest,
    Extensions, InitializeRequest, InitializeRequestParam, InitializedNotification, JsonRpcRequest,
    JsonRpcVersion2_0, ListToolsRequest, PingRequest, RequestId, ServerJsonRpcMessage,
    ServerResult,
};
use serde_json::json;
use test_server::{
    current_dir, handle_message, invalid_tool_stub, list_tools_response, run, run_main, run_server,
    tool_stub, validate_expectations, write_response,
};

static ENV_LOCK: Mutex<()> = Mutex::new(());
const EXPECTATION_ENV_KEYS: &[&str] = &[
    "EXPECT_ARG",
    "EXPECT_CWD",
    "FORCE_CWD_ERROR",
    "TOOLTEST_INVALID_OUTPUT_SCHEMA",
    "TOOLTEST_REQUIRE_VALUE",
    "TOOLTEST_TEST_SERVER_NO_EXIT",
    "TOOLTEST_TEST_SERVER_NO_STDIN",
    "TOOLTEST_TEST_SERVER_STDIN",
    "TOOLTEST_TEST_SERVER_EXTRA_TOOL",
    "TOOLTEST_TEST_SERVER_INVALID_TOOL",
    "TOOLTEST_VALUE_TYPE",
];

fn reset_env() {
    for key in EXPECTATION_ENV_KEYS {
        std::env::remove_var(key);
    }
}

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: String) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("write failed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush failed"))
    }
}

struct FlushFailingWriter;

impl Write for FlushFailingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush failed"))
    }
}

fn list_tools_line() -> String {
    let request = ClientRequest::ListToolsRequest(ListToolsRequest {
        method: Default::default(),
        params: None,
        extensions: Extensions::default(),
    });
    let message = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: RequestId::Number(1),
        request,
    });
    serde_json::to_string(&message).expect("serialize request")
}

fn call_tool_line() -> String {
    let request = ClientRequest::CallToolRequest(CallToolRequest {
        method: Default::default(),
        params: CallToolRequestParam {
            name: "echo".to_string().into(),
            arguments: None,
        },
        extensions: Extensions::default(),
    });
    let message = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: RequestId::Number(2),
        request,
    });
    serde_json::to_string(&message).expect("serialize request")
}

fn ping_line() -> String {
    let request = ClientRequest::PingRequest(PingRequest::default());
    let message = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: RequestId::Number(3),
        request,
    });
    serde_json::to_string(&message).expect("serialize request")
}

fn initialize_line() -> String {
    let request =
        ClientRequest::InitializeRequest(InitializeRequest::new(InitializeRequestParam::default()));
    let message = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: RequestId::Number(4),
        request,
    });
    serde_json::to_string(&message).expect("serialize request")
}

fn list_tools_message() -> ClientJsonRpcMessage {
    serde_json::from_str(&list_tools_line()).expect("list tools message")
}

fn tools_from_list_response(response: ServerJsonRpcMessage) -> Vec<String> {
    match response {
        ServerJsonRpcMessage::Response(response) => match response.result {
            ServerResult::ListToolsResult(result) => result
                .tools
                .into_iter()
                .map(|tool| tool.name.to_string())
                .collect(),
            other => panic!("unexpected result: {other:?}"),
        },
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn main_reports_expectation_failure() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("EXPECT_ARG", "definitely-missing-arg".to_string());
    let mut lines = Vec::<io::Result<String>>::new().into_iter();
    let mut output = Vec::new();
    let result = run(&mut lines, &mut output);
    assert!(result.is_err());
}

#[test]
fn env_guard_restores_previous_value() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    std::env::set_var("EXPECT_ARG", "alpha");
    let _guard = EnvGuard::set("EXPECT_ARG", "beta".to_string());
    assert_eq!(std::env::var("EXPECT_ARG").ok().as_deref(), Some("beta"));
    drop(_guard);
    assert_eq!(std::env::var("EXPECT_ARG").ok().as_deref(), Some("alpha"));
}

#[test]
fn env_guard_removes_when_unset() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    std::env::remove_var("EXPECT_ARG");
    let _guard = EnvGuard::set("EXPECT_ARG", "beta".to_string());
    assert!(std::env::var("EXPECT_ARG").is_ok());
    drop(_guard);
    assert!(std::env::var("EXPECT_ARG").is_err());
}

#[test]
fn validate_expectations_errors_on_missing_arg() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("EXPECT_ARG", "nope".to_string());
    let result = validate_expectations();
    assert!(result.is_err());
}

#[test]
fn validate_expectations_accepts_existing_arg() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let arg = std::env::args().next().unwrap_or_default();
    let _guard = EnvGuard::set("EXPECT_ARG", arg);
    let result = validate_expectations();
    assert!(result.is_ok());
}

#[test]
fn validate_expectations_errors_on_cwd_mismatch() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("EXPECT_CWD", "/definitely/wrong".to_string());
    let result = validate_expectations();
    assert!(result.is_err());
}

#[test]
fn validate_expectations_errors_on_unreadable_cwd() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("EXPECT_CWD", "/missing".to_string());
    let _force = EnvGuard::set("FORCE_CWD_ERROR", "1".to_string());
    let result = validate_expectations();
    assert!(result.is_err());
}

#[test]
fn validate_expectations_accepts_matching_cwd() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let cwd = std::env::current_dir().expect("cwd");
    let _guard = EnvGuard::set("EXPECT_CWD", cwd.to_string_lossy().to_string());
    let result = validate_expectations();
    assert!(result.is_ok());
}

#[test]
fn validate_expectations_rejects_invalid_value_type() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("TOOLTEST_VALUE_TYPE", "nope".to_string());
    let result = validate_expectations();
    assert!(result.is_err());
}

#[test]
fn handle_message_includes_extra_tool_from_env() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("TOOLTEST_TEST_SERVER_EXTRA_TOOL", "extra".to_string());
    let response = handle_message(list_tools_message()).expect("response");
    let tools = tools_from_list_response(response);
    assert!(tools.contains(&"extra".to_string()));
    assert!(tools.contains(&"echo".to_string()));
}

#[test]
fn handle_message_includes_multiple_extra_tools_from_env() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard =
        EnvGuard::set("TOOLTEST_TEST_SERVER_EXTRA_TOOL", "alpha, ,bravo".to_string());
    let response = handle_message(list_tools_message()).expect("response");
    let tools = tools_from_list_response(response);
    assert!(tools.contains(&"alpha".to_string()));
    assert!(tools.contains(&"bravo".to_string()));
    assert!(tools.contains(&"echo".to_string()));
}

#[test]
fn handle_message_includes_invalid_tool_when_enabled() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("TOOLTEST_TEST_SERVER_INVALID_TOOL", "1".to_string());
    let response = handle_message(list_tools_message()).expect("response");
    let tools = tools_from_list_response(response);
    assert!(tools.contains(&"invalid".to_string()));
    assert!(tools.contains(&"echo".to_string()));
}

#[test]
fn invalid_tool_stub_builds_string_input_schema() {
    let tool = invalid_tool_stub("bad");
    assert_eq!(tool.input_schema.get("type"), Some(&json!("string")));
}

#[test]
fn validate_expectations_accepts_valid_value_type() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("TOOLTEST_VALUE_TYPE", "number".to_string());
    let result = validate_expectations();
    assert!(result.is_ok());
}

#[test]
fn current_dir_errors_when_forced() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _force = EnvGuard::set("FORCE_CWD_ERROR", "1".to_string());
    assert!(current_dir().is_err());
}

#[test]
fn run_succeeds_with_empty_input() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    std::env::remove_var("EXPECT_ARG");
    std::env::remove_var("EXPECT_CWD");
    let mut lines = Vec::<io::Result<String>>::new().into_iter();
    let mut output = Vec::new();
    assert!(run(&mut lines, &mut output).is_ok());
    assert!(output.is_empty());
}

#[test]
fn run_main_succeeds_with_empty_input() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("TOOLTEST_TEST_SERVER_NO_STDIN", "1".to_string());
    run_main();
}

#[test]
fn run_main_accepts_in_memory_stdin() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("TOOLTEST_TEST_SERVER_STDIN", "".to_string());
    run_main();
}

#[test]
#[cfg(coverage)]
fn run_main_succeeds_with_default_stdin_in_coverage() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    run_main();
}

#[test]
fn run_main_reports_failure_without_exiting() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _no_exit = EnvGuard::set("TOOLTEST_TEST_SERVER_NO_EXIT", "1".to_string());
    let _no_stdin = EnvGuard::set("TOOLTEST_TEST_SERVER_NO_STDIN", "1".to_string());
    let _missing_arg = EnvGuard::set("EXPECT_ARG", "missing-arg".to_string());
    let result = std::panic::catch_unwind(run_main);
    assert!(result.is_err());
}

#[test]
fn handle_message_ignores_unhandled_requests() {
    let request = ClientRequest::PingRequest(PingRequest::default());
    let message = ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: RequestId::Number(1),
        request,
    });
    assert!(handle_message(message).is_none());
}

#[test]
fn handle_message_ignores_notifications() {
    let message = ClientJsonRpcMessage::notification(ClientNotification::InitializedNotification(
        InitializedNotification::default(),
    ));
    assert!(handle_message(message).is_none());
}

#[test]
fn run_server_skips_invalid_and_empty_lines() {
    let mut lines = vec![Ok("".to_string()), Ok("not-json".to_string())].into_iter();
    let mut output = Vec::new();
    run_server(&mut lines, &mut output);
    assert!(output.is_empty());
}

#[test]
fn run_server_handles_read_errors() {
    let mut lines = vec![Err(io::Error::other("read failed"))].into_iter();
    let mut output = Vec::new();
    run_server(&mut lines, &mut output);
    assert!(output.is_empty());
}

#[test]
fn run_server_skips_unhandled_requests() {
    let mut lines = vec![Ok(ping_line())].into_iter();
    let mut output = Vec::new();
    run_server(&mut lines, &mut output);
    assert!(output.is_empty());
}

#[test]
fn run_server_handles_call_tool_request() {
    let mut lines = vec![Ok(call_tool_line())].into_iter();
    let mut output = Vec::new();
    run_server(&mut lines, &mut output);
    assert!(!output.is_empty());
}

#[test]
fn run_server_handles_list_tools_request() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let mut lines = vec![Ok(list_tools_line())].into_iter();
    let mut output = Vec::new();
    run_server(&mut lines, &mut output);

    let payload = String::from_utf8(output).expect("utf8");
    let response: serde_json::Value = serde_json::from_str(payload.trim()).expect("json");
    assert_eq!(
        response["result"]["tools"]
            .as_array()
            .map(|items| items.len()),
        Some(1)
    );
}

#[test]
fn run_server_handles_initialize_request() {
    let mut lines = vec![Ok(initialize_line())].into_iter();
    let mut output = Vec::new();
    run_server(&mut lines, &mut output);

    let payload = String::from_utf8(output).expect("utf8");
    let response: serde_json::Value = serde_json::from_str(payload.trim()).expect("json");
    assert!(response["result"]["protocolVersion"].is_string());
}

#[test]
fn tool_stub_requires_value_when_env_set() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("TOOLTEST_REQUIRE_VALUE", "1".to_string());
    let tool = tool_stub();
    let required = tool
        .input_schema
        .get("required")
        .and_then(|value| value.as_array());
    assert!(required.is_some());
}

#[test]
fn tool_stub_uses_invalid_output_schema_when_env_set() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    let _guard = EnvGuard::set("TOOLTEST_INVALID_OUTPUT_SCHEMA", "1".to_string());
    let tool = tool_stub();
    let output_schema = tool.output_schema.as_ref().expect("output schema");
    let output_type = output_schema.get("type").and_then(|value| value.as_str());
    assert_eq!(output_type, Some("string"));
}

#[test]
fn validate_expectations_succeeds_without_expectations() {
    let _lock = ENV_LOCK.lock().expect("lock env");
    reset_env();
    std::env::remove_var("EXPECT_ARG");
    std::env::remove_var("EXPECT_CWD");
    std::env::remove_var("TOOLTEST_VALUE_TYPE");
    let result = validate_expectations();
    assert!(result.is_ok());
}

#[test]
fn list_tools_helpers_report_errors_in_cli_tests() {
    let response = list_tools_response(RequestId::Number(1), vec![]);
    let result = write_response(&mut FailingWriter, &response);
    assert!(result.is_err());
}

#[test]
fn failing_writer_flush_reports_error() {
    let mut writer = FailingWriter;
    assert!(writer.flush().is_err());
}

#[test]
fn run_server_reports_write_errors() {
    let mut lines = vec![Ok(list_tools_line())].into_iter();
    let mut writer = FailingWriter;
    run_server(&mut lines, &mut writer);
}

#[test]
fn write_response_reports_flush_errors() {
    let response = list_tools_response(RequestId::Number(1), vec![]);
    let result = write_response(&mut FlushFailingWriter, &response);
    assert!(result.is_err());
}
