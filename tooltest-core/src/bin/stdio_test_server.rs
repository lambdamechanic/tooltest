use std::io::{self, BufRead, Write};

use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, JsonRpcMessage, ServerJsonRpcMessage, Tool,
};
use serde_json::json;
use tooltest_test_support::{
    call_tool_response, init_response, list_tools_response, tool_with_schemas,
};

#[cfg(test)]
#[path = "../../tests/internal/stdio_test_server_tests.rs"]
mod tests;

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    run_server(stdin.lock().lines(), &mut stdout);
}

fn run_server<I, W>(lines: I, stdout: &mut W)
where
    I: IntoIterator<Item = io::Result<String>>,
    W: Write,
{
    for line in lines {
        let Ok(line) = line else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }
        let message: ClientJsonRpcMessage = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(_) => continue,
        };
        let Some(response) = handle_message(message) else {
            continue;
        };
        write_response(stdout, &response);
    }
}

fn write_response<W: Write>(stdout: &mut W, response: &ServerJsonRpcMessage) {
    let payload = serde_json::to_string(response).expect("serialize response");
    let _ = writeln!(stdout, "{payload}");
    let _ = stdout.flush();
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
    tool_with_schemas("echo", input_schema, Some(output_schema))
}

fn tool_response() -> CallToolResult {
    CallToolResult::structured(json!({ "status": "ok" }))
}
