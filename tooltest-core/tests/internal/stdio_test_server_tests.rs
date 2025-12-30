use super::*;
use rmcp::model::{
CallToolRequestParam, ClientNotification, ErrorData, InitializeRequest,
InitializeRequestParam, InitializedNotification, JsonRpcNotification, JsonRpcResponse,
JsonRpcVersion2_0, ListPromptsRequest, ListToolsRequest, NumberOrString,
PaginatedRequestParam, Request, ServerJsonRpcMessage, ServerNotification, ServerRequest,
ServerResult, ToolListChangedNotification,
};
use std::io::Write;

fn is_initialize_response(response: &ServerJsonRpcMessage) -> bool {
matches!(
    response,
    ServerJsonRpcMessage::Response(JsonRpcResponse {
        result: ServerResult::InitializeResult(_),
        ..
    })
)
}

fn unwrap_call_tool_result(message: ServerJsonRpcMessage) -> CallToolResult {
let (result, _) = message.into_response().expect("expected response message");
match result {
    ServerResult::CallToolResult(result) => result,
    _ => panic!("expected call tool result"),
}
}

#[test]
fn run_server_handles_empty_input() {
let lines: Vec<io::Result<String>> = Vec::new();
let mut output = Vec::new();
run_server(lines, &mut output);
assert!(output.is_empty());
}

#[test]
fn run_server_skips_empty_and_invalid_input() {
let lines = vec![
    Ok("   ".to_string()),
    Ok("not-json".to_string()),
    Err(io::Error::new(io::ErrorKind::Other, "boom")),
];
let mut output = Vec::new();
run_server(lines, &mut output);
assert!(output.is_empty());
}

#[test]
fn run_server_ignores_unhandled_message() {
let request = ClientJsonRpcMessage::request(
    ClientRequest::ListPromptsRequest(ListPromptsRequest {
        method: Default::default(),
        params: Some(PaginatedRequestParam { cursor: None }),
        extensions: Default::default(),
    }),
    NumberOrString::Number(1),
);
let payload = serde_json::to_string(&request).expect("serialize request");
let lines = vec![Ok(payload)];
let mut output = Vec::new();
run_server(lines, &mut output);
assert!(output.is_empty());
}

#[test]
fn handle_message_ignores_unhandled_request() {
let request = ClientJsonRpcMessage::request(
    ClientRequest::ListPromptsRequest(ListPromptsRequest {
        method: Default::default(),
        params: Some(PaginatedRequestParam { cursor: None }),
        extensions: Default::default(),
    }),
    NumberOrString::Number(1),
);
assert!(handle_message(request).is_none());
}

#[test]
fn handle_message_handles_tool_call() {
let request = ClientJsonRpcMessage::request(
    ClientRequest::CallToolRequest(Request::new(CallToolRequestParam {
        name: "echo".into(),
        arguments: None,
    })),
    NumberOrString::Number(3),
);
let response = handle_message(request).expect("response");
let result = unwrap_call_tool_result(response);
assert!(result.structured_content.is_some());
}

#[test]
fn handle_message_handles_initialize() {
let request = ClientJsonRpcMessage::request(
    ClientRequest::InitializeRequest(InitializeRequest::new(
        InitializeRequestParam::default(),
    )),
    NumberOrString::Number(1),
);
let response = std::hint::black_box(handle_message(request).expect("response"));
assert!(is_initialize_response(&response));
}

#[test]
#[should_panic(expected = "expected response message")]
fn unwrap_call_tool_result_panics_on_error_response() {
let message = ServerJsonRpcMessage::error(
    ErrorData::internal_error("boom", None),
    NumberOrString::Number(9),
);
let _ = unwrap_call_tool_result(message);
}

#[test]
#[should_panic(expected = "expected response message")]
fn unwrap_call_tool_result_panics_on_request() {
let message = ServerJsonRpcMessage::request(
    ServerRequest::PingRequest(Default::default()),
    NumberOrString::Number(10),
);
let _ = unwrap_call_tool_result(message);
}

#[test]
#[should_panic(expected = "expected response message")]
fn unwrap_call_tool_result_panics_on_notification() {
let message = ServerJsonRpcMessage::notification(
    ServerNotification::ToolListChangedNotification(ToolListChangedNotification::default()),
);
let _ = unwrap_call_tool_result(message);
}

#[test]
#[should_panic(expected = "expected call tool result")]
fn unwrap_call_tool_result_panics_on_non_call_tool_result() {
let message = list_tools_response(NumberOrString::Number(4), vec![]);
let _ = unwrap_call_tool_result(message);
}

#[test]
fn handle_message_ignores_notifications() {
let notification = ClientJsonRpcMessage::Notification(JsonRpcNotification {
    jsonrpc: JsonRpcVersion2_0,
    notification: ClientNotification::InitializedNotification(
        InitializedNotification::default(),
    ),
});
assert!(handle_message(notification).is_none());
}

#[test]
fn handle_message_ignores_error() {
let error = ClientJsonRpcMessage::error(
    ErrorData::internal_error("boom", None),
    NumberOrString::Number(9),
);
assert!(handle_message(error).is_none());
}

#[test]
fn is_initialize_response_rejects_non_initialize_response() {
let response = list_tools_response(NumberOrString::Number(2), vec![]);
assert!(!is_initialize_response(&response));
}

#[test]
fn write_response_handles_write_errors() {
struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "write failed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "flush failed"))
    }
}

let mut writer = FailingWriter;
let response = list_tools_response(NumberOrString::Number(5), vec![]);
write_response(&mut writer, &response);
}

#[test]
fn run_server_emits_responses() {
let unhandled = ClientJsonRpcMessage::request(
    ClientRequest::ListPromptsRequest(ListPromptsRequest {
        method: Default::default(),
        params: Some(PaginatedRequestParam { cursor: None }),
        extensions: Default::default(),
    }),
    NumberOrString::Number(1),
);
let list_tools = ClientJsonRpcMessage::request(
    ClientRequest::ListToolsRequest(ListToolsRequest {
        method: Default::default(),
        params: Some(PaginatedRequestParam { cursor: None }),
        extensions: Default::default(),
    }),
    NumberOrString::Number(2),
);
let lines = vec![
    Ok(serde_json::to_string(&unhandled).expect("serialize unhandled")),
    Ok(serde_json::to_string(&list_tools).expect("serialize list tools")),
    Err(io::Error::new(io::ErrorKind::Other, "done")),
];
let mut output = Vec::new();
run_server(lines, &mut output);
assert!(!output.is_empty());
}
