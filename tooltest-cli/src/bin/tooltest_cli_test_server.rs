use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(test)]
use std::cell::Cell;

use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, InitializeResult, JsonRpcMessage,
    JsonRpcResponse, JsonRpcVersion2_0, RequestId, ServerInfo, ServerJsonRpcMessage, ServerResult,
    Tool,
};
use serde_json::json;

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut lines = stdin.lock().lines();
    run(&mut lines, &mut stdout);
}

fn run(lines: &mut dyn Iterator<Item = io::Result<String>>, stdout: &mut dyn Write) {
    if let Err(message) = validate_expectations() {
        handle_expectations_error(&message);
    }
    run_server(lines, stdout);
}

#[cfg(not(test))]
fn handle_expectations_error(message: &str) -> ! {
    eprintln!("tooltest_cli_test_server: {message}");
    std::process::exit(2);
}

#[cfg(test)]
fn handle_expectations_error(message: &str) -> ! {
    panic!("tooltest_cli_test_server: {message}");
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

    Ok(())
}

fn current_dir() -> io::Result<PathBuf> {
    #[cfg(test)]
    {
        if FORCE_CWD_ERROR.with(|flag| flag.get()) {
            return Err(io::Error::new(io::ErrorKind::Other, "forced"));
        }
    }
    env::current_dir()
}

#[cfg(test)]
thread_local! {
    static FORCE_CWD_ERROR: Cell<bool> = Cell::new(false);
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
    let input_schema = json!({
        "type": "object",
        "properties": {
            "value": { "type": "string" }
        }
    });
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
        CallToolRequest, CallToolRequestParam, ClientNotification, ClientRequest, Extensions,
        InitializeRequest, InitializeRequestParam, InitializedNotification, JsonRpcRequest,
        ListToolsRequest, PingRequest,
    };
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        let _guard = EnvGuard::set("EXPECT_ARG", "definitely-missing-arg".to_string());
        let result = std::panic::catch_unwind(|| main());
        assert!(result.is_err());
    }

    #[test]
    fn env_guard_restores_previous_value() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        env::set_var("EXPECT_ARG", "previous");
        {
            let _guard = EnvGuard::set("EXPECT_ARG", "current".to_string());
            assert_eq!(env::var("EXPECT_ARG").as_deref(), Ok("current"));
        }
        assert_eq!(env::var("EXPECT_ARG").as_deref(), Ok("previous"));
        env::remove_var("EXPECT_ARG");
    }

    #[test]
    fn env_guard_removes_when_unset() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        env::remove_var("EXPECT_ARG");
        {
            let _guard = EnvGuard::set("EXPECT_ARG", "current".to_string());
            assert_eq!(env::var("EXPECT_ARG").as_deref(), Ok("current"));
        }
        assert!(env::var("EXPECT_ARG").is_err());
    }

    #[test]
    fn validate_expectations_succeeds_without_expectations() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        env::remove_var("EXPECT_ARG");
        env::remove_var("EXPECT_CWD");
        assert!(validate_expectations().is_ok());
    }

    #[test]
    fn validate_expectations_accepts_existing_arg() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        let arg0 = env::args().next().expect("arg0");
        let _guard = EnvGuard::set("EXPECT_ARG", arg0);
        assert!(validate_expectations().is_ok());
    }

    #[test]
    fn validate_expectations_accepts_matching_cwd() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        let current = env::current_dir().expect("cwd");
        let _guard = EnvGuard::set("EXPECT_CWD", current.display().to_string());
        assert!(validate_expectations().is_ok());
    }

    #[test]
    fn validate_expectations_errors_on_missing_arg() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        let _guard = EnvGuard::set("EXPECT_ARG", "definitely-missing-arg".to_string());
        let result = validate_expectations();
        assert!(result.is_err());
    }

    #[test]
    fn validate_expectations_errors_on_cwd_mismatch() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        let current = env::current_dir().expect("cwd");
        let mismatched = current.join("does-not-exist");
        let _guard = EnvGuard::set("EXPECT_CWD", mismatched.display().to_string());
        let result = validate_expectations();
        assert!(result.is_err());
    }

    #[test]
    fn validate_expectations_errors_on_unreadable_cwd() {
        let _lock = ENV_LOCK.lock().expect("lock env");
        let _force = force_cwd_error();
        let _guard = EnvGuard::set("EXPECT_CWD", "unused".to_string());
        let result = validate_expectations();
        assert!(result.is_err());
    }

    #[test]
    fn current_dir_errors_when_forced() {
        let _force = force_cwd_error();
        assert!(current_dir().is_err());
    }

    #[test]
    fn run_succeeds_with_empty_input() {
        let mut lines = Vec::<io::Result<String>>::new().into_iter();
        let mut output = Vec::new();
        run(&mut lines, &mut output);
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
    fn run_server_handles_read_errors() {
        let mut lines = vec![Err(io::Error::new(io::ErrorKind::Other, "read failed"))].into_iter();
        let mut output = Vec::new();
        run_server(&mut lines, &mut output);
        assert!(output.is_empty());
    }

    #[test]
    fn run_server_reports_write_errors() {
        let mut lines = vec![Ok(list_tools_line())].into_iter();
        let mut writer = FailingWriter;
        run_server(&mut lines, &mut writer);
    }

    #[test]
    fn failing_writer_flushes_with_error() {
        let mut writer = FailingWriter;
        assert!(writer.flush().is_err());
    }

    #[test]
    fn write_response_reports_flush_errors() {
        let response = init_response(RequestId::Number(1));
        let mut writer = FlushFailingWriter;
        assert!(write_response(&mut writer, &response).is_err());
    }

    struct CwdErrorGuard;

    impl Drop for CwdErrorGuard {
        fn drop(&mut self) {
            FORCE_CWD_ERROR.with(|flag| flag.set(false));
        }
    }

    fn force_cwd_error() -> CwdErrorGuard {
        FORCE_CWD_ERROR.with(|flag| flag.set(true));
        CwdErrorGuard
    }
}
