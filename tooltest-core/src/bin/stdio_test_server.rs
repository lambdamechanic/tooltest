use std::io::{self, Write};

#[cfg(not(test))]
use std::io::BufRead;

use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, InitializeResult, JsonRpcMessage,
    JsonRpcResponse, JsonRpcVersion2_0, RequestId, ServerInfo, ServerJsonRpcMessage, ServerResult,
    Tool,
};
use serde_json::json;

#[cfg(test)]
#[path = "../../tests/internal/stdio_test_server_tests.rs"]
mod tests;

#[cfg(not(test))]
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

fn tool_with_schemas(
    name: &str,
    input_schema: serde_json::Value,
    output_schema: Option<serde_json::Value>,
) -> Tool {
    Tool {
        name: name.to_string().into(),
        title: None,
        description: None,
        input_schema: std::sync::Arc::new(
            input_schema
                .as_object()
                .cloned()
                .expect("input schema object"),
        ),
        output_schema: output_schema.map(|schema| {
            std::sync::Arc::new(schema.as_object().cloned().expect("output schema object"))
        }),
        annotations: None,
        icons: None,
        meta: None,
    }
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
