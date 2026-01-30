use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, Write};
use std::sync::Arc;

use rmcp::model::{
    CallToolRequest, CallToolResult, ClientJsonRpcMessage, ClientRequest, Content,
    InitializeResult, JsonRpcMessage, JsonRpcResponse, JsonRpcVersion2_0, RequestId, ServerInfo,
    ServerJsonRpcMessage, ServerResult, Tool,
};
use serde_json::json;

const SERVER_NAME: &str = "tooltest_flaky_stdio_server";
const TOOL_NAME: &str = "flaky_echo";
const BUCKET_MODULO: u64 = 50;
const CRASH_BUCKET: u64 = 0;
const STDOUT_NOISE_BUCKET: u64 = 1;
const ERROR_BUCKET_MAX: u64 = 11;

pub fn run_main() {
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
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("{SERVER_NAME}: failed to read stdin: {error}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let message: ClientJsonRpcMessage = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(error) => {
                eprintln!("{SERVER_NAME}: invalid json: {error}");
                continue;
            }
        };
        let Some(response) = handle_message(message) else {
            continue;
        };
        match response {
            ResponseAction::Json(response) => {
                if let Err(error) = write_response(stdout, &response) {
                    eprintln!("{SERVER_NAME}: failed to write stdout: {error}");
                    break;
                }
            }
            ResponseAction::JsonWithStdoutNoise { noise, response } => {
                if let Err(error) = writeln!(stdout, "{noise}") {
                    eprintln!("{SERVER_NAME}: failed to write stdout noise: {error}");
                    break;
                }
                if let Err(error) = stdout.flush() {
                    eprintln!("{SERVER_NAME}: failed to flush stdout noise: {error}");
                    break;
                }
                if let Err(error) = write_response(stdout, &response) {
                    eprintln!("{SERVER_NAME}: failed to write stdout: {error}");
                    break;
                }
            }
        }
    }
}

fn write_response(stdout: &mut dyn Write, response: &ServerJsonRpcMessage) -> io::Result<()> {
    let payload = serde_json::to_string(response).expect("serialize response");
    writeln!(stdout, "{payload}")?;
    stdout.flush()
}

enum ResponseAction {
    Json(ServerJsonRpcMessage),
    JsonWithStdoutNoise {
        noise: String,
        response: ServerJsonRpcMessage,
    },
}

fn handle_message(message: ClientJsonRpcMessage) -> Option<ResponseAction> {
    match message {
        JsonRpcMessage::Request(request) => match &request.request {
            ClientRequest::InitializeRequest(_) => {
                Some(ResponseAction::Json(init_response(request.id.clone())))
            }
            ClientRequest::ListToolsRequest(_) => Some(ResponseAction::Json(list_tools_response(
                request.id.clone(),
                vec![tool_stub()],
            ))),
            ClientRequest::CallToolRequest(CallToolRequest { params, .. }) => {
                Some(tool_response(request.id.clone(), params.arguments.clone()))
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
            "value": {
                "type": "string",
                "minLength": 1,
                "maxLength": 11
            }
        },
        "required": ["value"]
    });
    let output_schema = json!({
        "type": "object",
        "properties": {
            "status": { "type": "string", "const": "ok" },
            "value": { "type": "string" },
            "length": { "type": "integer", "minimum": 1 },
            "hash": { "type": "integer", "minimum": 0 },
            "bucket": { "type": "integer", "minimum": 0, "maximum": 49 },
            "mode": { "type": "string", "enum": ["success", "stdout_noise"] }
        },
        "required": ["status", "value", "length", "hash", "bucket", "mode"]
    });
    tool_with_schemas(TOOL_NAME, input_schema, Some(output_schema))
}

fn tool_with_schemas(
    name: &str,
    input_schema: serde_json::Value,
    output_schema: Option<serde_json::Value>,
) -> Tool {
    Tool {
        name: name.to_string().into(),
        title: None,
        description: Some("Hashes input to pick success, error, crash, or stdout-noise.".into()),
        input_schema: Arc::new(
            input_schema
                .as_object()
                .cloned()
                .expect("input schema object"),
        ),
        output_schema: output_schema
            .map(|schema| Arc::new(schema.as_object().cloned().expect("output schema object"))),
        annotations: None,
        icons: None,
        meta: None,
    }
}

fn tool_response(id: RequestId, arguments: Option<rmcp::model::JsonObject>) -> ResponseAction {
    let value = match extract_value(arguments) {
        Ok(value) => value,
        Err(message) => {
            return ResponseAction::Json(call_tool_response(
                id,
                CallToolResult::error(vec![Content::text(message)]),
            ));
        }
    };
    let length = value.chars().count();
    let hash = hash_value(&value);
    let bucket = hash % BUCKET_MODULO;
    match bucket {
        CRASH_BUCKET => {
            eprintln!(
                "{SERVER_NAME}: crash bucket hit (hash {hash}, bucket {bucket}, value={value:?})"
            );
            std::process::exit(101);
        }
        STDOUT_NOISE_BUCKET => {
            eprintln!(
                "{SERVER_NAME}: stdout-noise bucket hit (hash {hash}, bucket {bucket}, value={value:?})"
            );
            ResponseAction::JsonWithStdoutNoise {
                noise: format!("DEBUG: {SERVER_NAME} stdout noise for hash {hash}"),
                response: call_tool_response(
                    id,
                    CallToolResult::structured(success_payload(
                        &value,
                        length,
                        hash,
                        bucket,
                        "stdout_noise",
                    )),
                ),
            }
        }
        2..=ERROR_BUCKET_MAX => ResponseAction::Json(call_tool_response(
            id,
            CallToolResult::error(vec![Content::text(format!(
                "well-behaved failure (hash {hash}, bucket {bucket})"
            ))]),
        )),
        _ => ResponseAction::Json(call_tool_response(
            id,
            CallToolResult::structured(success_payload(&value, length, hash, bucket, "success")),
        )),
    }
}

fn extract_value(arguments: Option<rmcp::model::JsonObject>) -> Result<String, String> {
    let Some(arguments) = arguments else {
        return Err("missing arguments".to_string());
    };
    let Some(value) = arguments.get("value") else {
        return Err("missing required 'value' string".to_string());
    };
    let Some(value) = value.as_str() else {
        return Err("value must be a string".to_string());
    };
    Ok(value.to_string())
}

fn hash_value(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn success_payload(
    value: &str,
    length: usize,
    hash: u64,
    bucket: u64,
    mode: &str,
) -> serde_json::Value {
    json!({
        "status": "ok",
        "value": value,
        "length": length,
        "hash": hash,
        "bucket": bucket,
        "mode": mode,
    })
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
        CallToolRequest, CallToolRequestParam, ClientJsonRpcMessage, ClientNotification,
        ClientRequest, Extensions, InitializeRequest, InitializeRequestParam,
        InitializedNotification, JsonRpcRequest, JsonRpcVersion2_0, ListToolsRequest,
        NumberOrString, PingRequest, RequestId, ServerResult,
    };
    use serde_json::{json, Value as JsonValue};
    use std::io::{self, Write};
    use tooltest_test_support as _;

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

    struct FlushThenFailWriter {
        saw_flush: bool,
    }

    impl Write for FlushThenFailWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.saw_flush {
                Err(io::Error::other("write failed"))
            } else {
                Ok(buf.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.saw_flush = true;
            Ok(())
        }
    }

    fn request_line(request: ClientRequest, id: i64) -> String {
        let message = ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: RequestId::Number(id),
            request,
        });
        serde_json::to_string(&message).expect("serialize request")
    }

    fn initialize_line() -> String {
        let request = ClientRequest::InitializeRequest(InitializeRequest::new(
            InitializeRequestParam::default(),
        ));
        request_line(request, 1)
    }

    fn list_tools_line() -> String {
        let request = ClientRequest::ListToolsRequest(ListToolsRequest {
            method: Default::default(),
            params: None,
            extensions: Extensions::default(),
        });
        request_line(request, 2)
    }

    fn call_tool_line(value: &str) -> String {
        let mut arguments = serde_json::Map::new();
        arguments.insert("value".to_string(), JsonValue::String(value.to_string()));
        let request = ClientRequest::CallToolRequest(CallToolRequest {
            method: Default::default(),
            params: CallToolRequestParam {
                name: TOOL_NAME.to_string().into(),
                arguments: Some(arguments),
            },
            extensions: Extensions::default(),
        });
        request_line(request, 3)
    }

    fn notification_line() -> String {
        let message = ClientJsonRpcMessage::notification(
            ClientNotification::InitializedNotification(InitializedNotification::default()),
        );
        serde_json::to_string(&message).expect("serialize notification")
    }

    fn call_result_from_response(response: ServerJsonRpcMessage) -> CallToolResult {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::CallToolResult(result) => result,
                other => panic!("unexpected response result: {other:?}"),
            },
            other => panic!("unexpected response: {other:?}"),
        }
    }

    fn call_result_from_action(action: ResponseAction) -> CallToolResult {
        match action {
            ResponseAction::Json(response) => call_result_from_response(response),
            ResponseAction::JsonWithStdoutNoise { response, .. } => {
                call_result_from_response(response)
            }
        }
    }

    fn find_value_for_bucket(target: u64) -> String {
        for idx in 0..5000 {
            let value = format!("value-{idx}");
            if hash_value(&value) % BUCKET_MODULO == target {
                return value;
            }
        }
        panic!("no value found for bucket {target}");
    }

    #[test]
    fn hash_value_is_stable_for_same_input() {
        let first = hash_value("alpha");
        let second = hash_value("alpha");
        assert_eq!(first, second);
    }

    #[test]
    fn success_payload_includes_expected_fields() {
        let payload = success_payload("value", 5, 9, 12, "success");
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["value"], "value");
        assert_eq!(payload["length"], 5);
        assert_eq!(payload["hash"], 9);
        assert_eq!(payload["bucket"], 12);
        assert_eq!(payload["mode"], "success");
    }

    #[test]
    fn tool_with_schemas_allows_missing_output_schema() {
        let tool = tool_with_schemas("custom", json!({ "type": "object" }), None);
        assert_eq!(tool.name.as_ref(), "custom");
        assert!(tool.output_schema.is_none());
    }

    #[test]
    fn tool_stub_includes_output_schema() {
        let tool = tool_stub();
        assert_eq!(tool.name.as_ref(), TOOL_NAME);
        assert!(tool.output_schema.is_some());
    }

    #[test]
    fn extract_value_reports_missing_and_invalid() {
        assert_eq!(
            extract_value(None).expect_err("missing args"),
            "missing arguments"
        );
        let empty = serde_json::Map::new();
        assert_eq!(
            extract_value(Some(empty)).expect_err("missing value"),
            "missing required 'value' string"
        );
        let mut wrong = serde_json::Map::new();
        wrong.insert("value".to_string(), json!(123));
        assert_eq!(
            extract_value(Some(wrong)).expect_err("value type"),
            "value must be a string"
        );
        let mut ok = serde_json::Map::new();
        ok.insert("value".to_string(), json!("ok"));
        assert_eq!(extract_value(Some(ok)).expect("ok"), "ok");
    }

    #[test]
    fn tool_response_handles_error_and_success_buckets() {
        let error_value = find_value_for_bucket(2);
        let mut error_args = serde_json::Map::new();
        error_args.insert("value".to_string(), JsonValue::String(error_value));
        let error_action = tool_response(RequestId::Number(1), Some(error_args));
        let error_result = call_result_from_action(error_action);
        assert_eq!(error_result.is_error, Some(true));

        let success_value = find_value_for_bucket(20);
        let mut success_args = serde_json::Map::new();
        success_args.insert("value".to_string(), JsonValue::String(success_value));
        let success_action = tool_response(RequestId::Number(2), Some(success_args));
        let success_result = call_result_from_action(success_action);
        assert_eq!(success_result.is_error, Some(false));
        let structured = success_result
            .structured_content
            .expect("structured content");
        assert_eq!(structured["mode"], "success");
    }

    #[test]
    fn tool_response_returns_stdout_noise_action() {
        let value = find_value_for_bucket(STDOUT_NOISE_BUCKET);
        let mut args = serde_json::Map::new();
        args.insert("value".to_string(), JsonValue::String(value));
        let action = tool_response(RequestId::Number(1), Some(args));
        assert!(matches!(action, ResponseAction::JsonWithStdoutNoise { .. }));
        let result = call_result_from_action(action);
        let structured = result.structured_content.expect("structured content");
        assert_eq!(structured["mode"], "stdout_noise");
    }

    #[test]
    fn handle_message_handles_requests_and_ignores_notifications() {
        let init = ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: RequestId::Number(1),
            request: ClientRequest::InitializeRequest(InitializeRequest::new(
                InitializeRequestParam::default(),
            )),
        });
        let init_action = handle_message(init).expect("init action");
        assert!(matches!(
            init_action,
            ResponseAction::Json(ServerJsonRpcMessage::Response(response))
                if matches!(response.result, ServerResult::InitializeResult(_))
        ));

        let list_action = handle_message(ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: RequestId::Number(2),
            request: ClientRequest::ListToolsRequest(ListToolsRequest {
                method: Default::default(),
                params: None,
                extensions: Extensions::default(),
            }),
        }))
        .expect("list tools action");
        assert!(matches!(
            list_action,
            ResponseAction::Json(ServerJsonRpcMessage::Response(response))
                if matches!(response.result, ServerResult::ListToolsResult(_))
        ));

        let message = ClientJsonRpcMessage::notification(
            ClientNotification::InitializedNotification(InitializedNotification::default()),
        );
        assert!(handle_message(message).is_none());
    }

    #[test]
    fn write_response_writes_json() {
        let response = init_response(RequestId::Number(1));
        let mut output = Vec::new();
        write_response(&mut output, &response).expect("write response");
        let output = String::from_utf8(output).expect("utf8");
        assert!(output.contains("\"result\""));
    }

    #[test]
    fn write_response_propagates_write_error() {
        let response = init_response(RequestId::Number(1));
        let mut writer = FailingWriter;
        let error = write_response(&mut writer, &response).expect_err("write error");
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn failing_writer_flush_reports_error() {
        let mut writer = FailingWriter;
        let error = writer.flush().expect_err("flush error");
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn write_response_propagates_flush_error() {
        let response = init_response(RequestId::Number(1));
        let mut writer = FlushFailingWriter;
        let error = write_response(&mut writer, &response).expect_err("flush error");
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn run_server_handles_empty_invalid_and_ignored_lines() {
        let lines = vec![
            Ok("".to_string()),
            Ok("not-json".to_string()),
            Ok(notification_line()),
            Ok(initialize_line()),
        ];
        let mut output = Vec::new();
        run_server(lines, &mut output);
        let output = String::from_utf8(output).expect("utf8");
        assert!(!output.trim().is_empty());
    }

    #[test]
    fn run_server_handles_list_tools_request() {
        let lines = vec![Ok(list_tools_line())];
        let mut output = Vec::new();
        run_server(lines, &mut output);
        let output = String::from_utf8(output).expect("utf8");
        let response: ServerJsonRpcMessage =
            serde_json::from_str(output.trim()).expect("response json");
        assert!(matches!(
            response,
            ServerJsonRpcMessage::Response(response)
                if matches!(response.result, ServerResult::ListToolsResult(_))
        ));
    }

    #[test]
    fn run_server_breaks_on_read_error() {
        let lines = vec![Err(io::Error::other("boom"))];
        let mut output = Vec::new();
        run_server(lines, &mut output);
        assert!(output.is_empty());
    }

    #[test]
    fn run_server_breaks_on_write_error() {
        let lines = vec![Ok(initialize_line())];
        let mut output = FailingWriter;
        run_server(lines, &mut output);
    }

    #[test]
    fn run_server_emits_stdout_noise_and_response() {
        let value = find_value_for_bucket(STDOUT_NOISE_BUCKET);
        let lines = vec![Ok(call_tool_line(&value))];
        let mut output = Vec::new();
        run_server(lines, &mut output);
        let output = String::from_utf8(output).expect("utf8");
        let mut lines = output.lines();
        let noise = lines.next().expect("noise line");
        assert!(noise.contains("stdout noise"));
        let response_line = lines.next().expect("response line");
        let response: ServerJsonRpcMessage =
            serde_json::from_str(response_line).expect("response json");
        let result = call_result_from_response(response);
        let structured = result.structured_content.expect("structured content");
        assert_eq!(structured["mode"], "stdout_noise");
    }

    #[test]
    fn run_server_stdout_noise_write_error() {
        let value = find_value_for_bucket(STDOUT_NOISE_BUCKET);
        let lines = vec![Ok(call_tool_line(&value))];
        let mut output = FailingWriter;
        run_server(lines, &mut output);
    }

    #[test]
    fn run_server_stdout_noise_flush_error() {
        let value = find_value_for_bucket(STDOUT_NOISE_BUCKET);
        let lines = vec![Ok(call_tool_line(&value))];
        let mut output = FlushFailingWriter;
        run_server(lines, &mut output);
    }

    #[test]
    fn run_server_stdout_noise_response_write_error() {
        let value = find_value_for_bucket(STDOUT_NOISE_BUCKET);
        let lines = vec![Ok(call_tool_line(&value))];
        let mut output = FlushThenFailWriter { saw_flush: false };
        run_server(lines, &mut output);
    }

    #[test]
    fn handle_message_ignores_unknown_request() {
        let request = ClientRequest::PingRequest(PingRequest::default());
        let message = ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: RequestId::Number(1),
            request,
        });
        assert!(handle_message(message).is_none());
    }

    #[test]
    fn tool_response_reports_missing_arguments() {
        let action = tool_response(RequestId::Number(1), None);
        let result = call_result_from_action(action);
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn call_result_from_response_panics_on_unexpected_result() {
        let response = list_tools_response(RequestId::Number(1), Vec::new());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            call_result_from_response(response)
        }));
        assert!(result.is_err());
    }

    #[test]
    fn call_result_from_response_panics_on_error_message() {
        let response = ServerJsonRpcMessage::error(
            rmcp::ErrorData::invalid_params("boom", None),
            NumberOrString::Number(1),
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            call_result_from_response(response)
        }));
        assert!(result.is_err());
    }

    #[test]
    fn find_value_for_bucket_panics_on_unreachable_target() {
        let result = std::panic::catch_unwind(|| find_value_for_bucket(BUCKET_MODULO));
        assert!(result.is_err());
    }
}
