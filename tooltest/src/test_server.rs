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
    run_main_with_exit(default_exit);
}

fn default_exit(message: String) {
    eprintln!("tooltest_test_server: {message}");
    #[cfg(not(coverage))]
    {
        if env::var("TOOLTEST_TEST_SERVER_NO_EXIT").is_ok() {
            panic!("tooltest_test_server: {message}");
        }
        std::process::exit(2);
    }
    #[cfg(coverage)]
    {
        panic!("tooltest_test_server: {message}");
    }
}

fn stdin_lines() -> Box<dyn Iterator<Item = io::Result<String>>> {
    let stdin = io::stdin();
    Box::new(stdin.lock().lines())
}

fn run_main_with_exit(exit: impl FnOnce(String)) {
    let mut stdout = io::stdout();
    let use_empty_stdin = env::var("TOOLTEST_TEST_SERVER_NO_STDIN").is_ok();
    let stdin_payload = env::var("TOOLTEST_TEST_SERVER_STDIN").ok();
    let allow_stdin = env::var("TOOLTEST_TEST_SERVER_ALLOW_STDIN").is_ok();
    let mut lines = select_lines(use_empty_stdin, stdin_payload, allow_stdin);
    if let Err(message) = run(&mut lines, &mut stdout) {
        exit(message);
    }
}

fn select_lines(
    use_empty_stdin: bool,
    stdin_payload: Option<String>,
    allow_stdin: bool,
) -> Box<dyn Iterator<Item = io::Result<String>>> {
    if use_empty_stdin {
        return Box::new(std::iter::empty());
    }
    if let Some(stdin_payload) = stdin_payload {
        return Box::new(io::Cursor::new(stdin_payload).lines());
    }
    #[cfg(coverage)]
    {
        if allow_stdin {
            return stdin_lines();
        }
        return Box::new(std::iter::empty());
    }
    #[cfg(not(coverage))]
    {
        let _ = allow_stdin;
        stdin_lines()
    }
}

#[cfg(test)]
mod tests {
    use super::select_lines;

    #[test]
    fn select_lines_accepts_stdin_when_allowed() {
        let _ = select_lines(false, None, true);
    }

    #[test]
    fn select_lines_returns_empty_iterator_when_disabled() {
        let mut lines = select_lines(true, None, false);
        assert!(lines.next().is_none());
    }

    #[test]
    fn select_lines_returns_empty_iterator_when_stdin_blocked() {
        let mut lines = select_lines(false, None, false);
        assert!(lines.next().is_none());
    }

    #[test]
    fn select_lines_uses_inline_payload_when_provided() {
        let mut lines = select_lines(false, Some("ok\n".to_string()), false);
        let line = lines.next().expect("line").expect("line ok");
        assert_eq!(line, "ok");
    }
}

pub fn run(
    lines: &mut dyn Iterator<Item = io::Result<String>>,
    stdout: &mut dyn Write,
) -> Result<(), String> {
    validate_expectations()?;
    run_server(lines, stdout);
    Ok(())
}

pub fn validate_expectations() -> Result<(), String> {
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

pub fn current_dir() -> io::Result<PathBuf> {
    if env::var("FORCE_CWD_ERROR").is_ok() {
        return Err(io::Error::other("forced"));
    }
    env::current_dir()
}

pub fn run_server(lines: &mut dyn Iterator<Item = io::Result<String>>, stdout: &mut dyn Write) {
    for line in lines {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("tooltest_test_server: failed to read stdin: {error}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let message: ClientJsonRpcMessage = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(error) => {
                eprintln!("tooltest_test_server: invalid json: {error}");
                continue;
            }
        };
        let Some(response) = handle_message(message) else {
            continue;
        };
        if let Err(error) = write_response(stdout, &response) {
            eprintln!("tooltest_test_server: failed to write stdout: {error}");
            break;
        }
    }
}

pub fn write_response(stdout: &mut dyn Write, response: &ServerJsonRpcMessage) -> io::Result<()> {
    let payload = serde_json::to_string(response).expect("serialize response");
    writeln!(stdout, "{payload}")?;
    stdout.flush()
}

pub fn handle_message(message: ClientJsonRpcMessage) -> Option<ServerJsonRpcMessage> {
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

pub fn tool_stub() -> Tool {
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
    let output_schema = if env::var_os("TOOLTEST_INVALID_OUTPUT_SCHEMA").is_some() {
        json!({
            "type": "string"
        })
    } else {
        json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "const": "ok" }
            },
            "required": ["status"]
        })
    };
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

pub fn list_tools_response(id: RequestId, tools: Vec<Tool>) -> ServerJsonRpcMessage {
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
