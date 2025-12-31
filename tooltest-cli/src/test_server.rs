use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, InitializeResult, JsonRpcMessage,
    JsonRpcResponse, JsonRpcVersion2_0, RequestId, ServerInfo, ServerJsonRpcMessage, ServerResult,
    Tool,
};
use serde_json::json;

pub fn run_main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut lines = stdin.lock().lines();
    if let Err(message) = run(&mut lines, &mut stdout) {
        eprintln!("tooltest_cli_test_server: {message}");
        std::process::exit(2);
    }
}

fn run(
    lines: &mut dyn Iterator<Item = io::Result<String>>,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    validate_expectations()?;
    run_server(lines, stdout);
    Ok(())
}

fn validate_expectations() -> Result<(), String> {
    if let Ok(expected_arg) = env::var("EXPECT_ARG") {
        let mut matched = false;
        for arg in env::args() {
            if arg == expected_arg {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(format!("expected arg '{expected_arg}' not found"));
        }
    }

    if let Ok(expected_cwd) = env::var("EXPECT_CWD") {
        let expected_path = PathBuf::from(expected_cwd);
        let expected_path = expected_path.canonicalize().unwrap_or(expected_path);
        let cwd = current_dir().map_err(|error| format!("failed to read cwd: {error}"))?;
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        if cwd != expected_path {
            return Err(format!(
                "expected cwd '{}' but got '{}'",
                expected_path.display(),
                cwd.display()
            ));
        }
    }

    if let Ok(value_type) = env::var("TOOLTEST_VALUE_TYPE") {
        match value_type.as_str() {
            "string" | "integer" | "number" | "object" => {}
            _ => {
                return Err(format!(
                    "invalid TOOLTEST_VALUE_TYPE '{value_type}', expected string, integer, number, or object"
                ));
            }
        }
    }

    Ok(())
}

fn current_dir() -> io::Result<PathBuf> {
    if env::var("FORCE_CWD_ERROR").is_ok() {
        return Err(io::Error::other("forced"));
    }
    env::current_dir()
}

fn run_server(lines: &mut dyn Iterator<Item = io::Result<String>>, stdout: &mut dyn Write) {
    for line in lines {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("tooltest_cli_test_server: failed to read stdin: {error}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let message: ClientJsonRpcMessage = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(error) => {
                eprintln!("tooltest_cli_test_server: invalid json: {error}");
                continue;
            }
        };
        let Some(response) = handle_message(message) else {
            continue;
        };
        if let Err(error) = write_response(stdout, &response) {
            eprintln!("tooltest_cli_test_server: failed to write stdout: {error}");
            break;
        }
    }
}

fn write_response(stdout: &mut dyn Write, response: &ServerJsonRpcMessage) -> io::Result<()> {
    let payload = serde_json::to_string(response).expect("serialize response");
    writeln!(stdout, "{payload}")?;
    stdout.flush()
}

fn handle_message(message: ClientJsonRpcMessage) -> Option<ServerJsonRpcMessage> {
    match message {
        JsonRpcMessage::Request(request) => match &request.request {
            ClientRequest::InitializeRequest(_) => Some(init_response(request.id.clone())),
            ClientRequest::ListToolsRequest(_) => {
                Some(list_tools_response(request.id.clone(), vec![tool_stub()]))
            }
            ClientRequest::CallToolRequest(_) => {
                Some(call_tool_response(request.id.clone(), tool_response()))
            }
            _ => None,
        },
        _ => None,
    }
}

fn tool_stub() -> Tool {
    let value_type = env::var("TOOLTEST_VALUE_TYPE").unwrap_or_else(|_| "string".to_string());
    let mut input_schema = serde_json::Map::new();
    input_schema.insert("type".to_string(), json!("object"));
    input_schema.insert(
        "properties".to_string(),
        json!({
            "value": { "type": value_type }
        }),
    );
    if env::var_os("TOOLTEST_REQUIRE_VALUE").is_some() {
        input_schema.insert("required".to_string(), json!(["value"]));
    }
    let input_schema = serde_json::Value::Object(input_schema);
    let output_schema = json!({
        "type": "object",
        "properties": {
            "status": { "type": "string", "const": "ok" }
        },
        "required": ["status"]
    });
    Tool {
        name: "echo".to_string().into(),
        title: None,
        description: None,
        input_schema: Arc::new(
            input_schema
                .as_object()
                .cloned()
                .expect("input schema object"),
        ),
        output_schema: Some(Arc::new(
            output_schema
                .as_object()
                .cloned()
                .expect("output schema object"),
        )),
        annotations: None,
        icons: None,
        meta: None,
    }
}

fn tool_response() -> CallToolResult {
    CallToolResult::structured(json!({ "status": "ok" }))
}

fn call_tool_response(id: RequestId, response: CallToolResult) -> ServerJsonRpcMessage {
    ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id,
        result: ServerResult::CallToolResult(response),
    })
}

fn list_tools_response(id: RequestId, tools: Vec<Tool>) -> ServerJsonRpcMessage {
    ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id,
        result: ServerResult::ListToolsResult(rmcp::model::ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        }),
    })
}

fn init_response(id: RequestId) -> ServerJsonRpcMessage {
    ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id,
        result: ServerResult::InitializeResult(InitializeResult {
            protocol_version: ServerInfo::default().protocol_version,
            capabilities: ServerInfo::default().capabilities,
            server_info: ServerInfo::default().server_info,
            instructions: None,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{
        CallToolRequest, CallToolRequestParam, ClientNotification, Extensions, InitializeRequest,
        InitializeRequestParam, InitializedNotification, JsonRpcRequest, ListToolsRequest,
        PingRequest,
    };
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const EXPECTATION_ENV_KEYS: &[&str] = &[
        "EXPECT_ARG",
        "EXPECT_CWD",
        "FORCE_CWD_ERROR",
        "TOOLTEST_REQUIRE_VALUE",
        "TOOLTEST_VALUE_TYPE",
    ];

    fn reset_env() {
        for key in EXPECTATION_ENV_KEYS {
            env::remove_var(key);
        }
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: String) -> Self {
            let previous = env::var(key).ok();
            env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                env::set_var(self.key, value);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "write failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "flush failed"))
        }
    }

    struct FlushFailingWriter;

    impl Write for FlushFailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "flush failed"))
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
        let request = ClientRequest::InitializeRequest(InitializeRequest::new(
            InitializeRequestParam::default(),
        ));
        let message = ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: RequestId::Number(4),
            request,
        });
        serde_json::to_string(&message).expect("serialize request")
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
        env::set_var("EXPECT_ARG", "alpha");
        let _guard = EnvGuard::set("EXPECT_ARG", "beta".to_string());
        assert_eq!(env::var("EXPECT_ARG").ok().as_deref(), Some("beta"));
        drop(_guard);
        assert_eq!(env::var("EXPECT_ARG").ok().as_deref(), Some("alpha"));
    }

    #[test]
    fn env_guard_removes_when_unset() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        reset_env();
        env::remove_var("EXPECT_ARG");
        let _guard = EnvGuard::set("EXPECT_ARG", "beta".to_string());
        assert!(env::var("EXPECT_ARG").is_ok());
        drop(_guard);
        assert!(env::var("EXPECT_ARG").is_err());
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
        let arg = env::args().next().unwrap_or_default();
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
        let cwd = env::current_dir().expect("cwd");
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
        env::remove_var("EXPECT_ARG");
        env::remove_var("EXPECT_CWD");
        let mut lines = Vec::<io::Result<String>>::new().into_iter();
        let mut output = Vec::new();
        assert!(run(&mut lines, &mut output).is_ok());
        assert!(output.is_empty());
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
        let message = ClientJsonRpcMessage::notification(
            ClientNotification::InitializedNotification(InitializedNotification::default()),
        );
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
        let mut lines = vec![Err(io::Error::new(io::ErrorKind::Other, "read failed"))].into_iter();
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
    fn validate_expectations_succeeds_without_expectations() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        reset_env();
        env::remove_var("EXPECT_ARG");
        env::remove_var("EXPECT_CWD");
        env::remove_var("TOOLTEST_VALUE_TYPE");
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
}
