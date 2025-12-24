use std::io::{self, BufRead, Write};
use std::sync::Arc;

use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, InitializeResult, JsonRpcMessage,
    JsonRpcResponse, JsonRpcVersion2_0, RequestId, ServerInfo, ServerJsonRpcMessage, ServerResult,
    Tool,
};
use serde_json::json;

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
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
        if let Ok(payload) = serde_json::to_string(&response) {
            let _ = writeln!(stdout, "{payload}");
            let _ = stdout.flush();
        }
    }
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
