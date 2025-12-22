use std::sync::{Arc, Mutex};

use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, Content, InitializeResult, JsonRpcMessage,
    JsonRpcNotification, JsonRpcResponse, JsonRpcVersion2_0, ListToolsRequest,
    PaginatedRequestParam, ServerInfo, ServerJsonRpcMessage, ServerResult,
};
use rmcp::transport::Transport;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tooltest_core::{
    ClientInitializeError, ErrorCode, ErrorData, ServiceError, SessionDriver, SessionError,
    ToolInvocation,
};

struct TestTransport {
    requests: Arc<Mutex<Vec<ClientJsonRpcMessage>>>,
    responses: Arc<AsyncMutex<mpsc::UnboundedReceiver<ServerJsonRpcMessage>>>,
    response_tx: mpsc::UnboundedSender<ServerJsonRpcMessage>,
}

impl TestTransport {
    fn new() -> Self {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(AsyncMutex::new(response_rx)),
            response_tx,
        }
    }

    fn request_log(&self) -> Arc<Mutex<Vec<ClientJsonRpcMessage>>> {
        Arc::clone(&self.requests)
    }
}

impl Transport<rmcp::service::RoleClient> for TestTransport {
    type Error = std::convert::Infallible;

    fn send(
        &mut self,
        item: ClientJsonRpcMessage,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        let requests = Arc::clone(&self.requests);
        let response_tx = self.response_tx.clone();
        let message = item.clone();
        if let JsonRpcMessage::Request(request) = &item {
            let response = match &request.request {
                ClientRequest::InitializeRequest(_) => Some(init_response(request.id.clone())),
                ClientRequest::CallToolRequest(_) => Some(call_tool_response(request.id.clone())),
                _ => None,
            };
            if let Some(response) = response {
                let _ = response_tx.send(response);
            }
        }
        requests.lock().expect("requests").push(message);
        std::future::ready(Ok(()))
    }

    fn receive(&mut self) -> impl std::future::Future<Output = Option<ServerJsonRpcMessage>> {
        let responses = Arc::clone(&self.responses);
        async move {
            let mut receiver = responses.lock().await;
            receiver.recv().await
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[tokio::test]
async fn connect_sends_initialize_and_initialized() {
    let transport = TestTransport::new();
    let requests = transport.request_log();
    let driver = SessionDriver::connect_with_transport(transport)
        .await
        .expect("connect");

    let invocation = ToolInvocation {
        name: "echo".into(),
        arguments: json!({"value": "hello"}).as_object().cloned(),
    };
    let trace = driver.send_tool_call(invocation).await.expect("tool call");

    let requests = requests.lock().expect("requests");
    assert!(matches!(requests[0], JsonRpcMessage::Request(_)));
    assert!(matches!(
        requests[1],
        JsonRpcMessage::Notification(JsonRpcNotification { .. })
    ));
    assert!(matches!(requests[2], JsonRpcMessage::Request(_)));
    assert_eq!(trace.response.is_error, Some(false));
}

#[tokio::test]
async fn run_invocations_collects_trace() {
    let transport = TestTransport::new();
    let driver = SessionDriver::connect_with_transport(transport)
        .await
        .expect("connect");

    let invocations = vec![
        ToolInvocation {
            name: "one".into(),
            arguments: json!({"a": 1}).as_object().cloned(),
        },
        ToolInvocation {
            name: "two".into(),
            arguments: json!({"b": 2}).as_object().cloned(),
        },
    ];
    let trace = driver.run_invocations(invocations).await.expect("trace");

    assert_eq!(trace.len(), 2);
}

#[cfg(coverage)]
#[tokio::test]
async fn connect_http_stub_returns_error() {
    let config = tooltest_core::HttpConfig {
        url: "http://localhost:8080/mcp".to_string(),
        auth_token: None,
    };
    let result = SessionDriver::connect_http(&config).await;
    assert!(matches!(result, Err(SessionError::Transport(_))));
}

#[cfg(coverage)]
#[tokio::test]
async fn connect_stdio_stub_returns_error() {
    let config = tooltest_core::StdioConfig::new("mcp-server");
    let result = SessionDriver::connect_stdio(&config).await;
    assert!(matches!(result, Err(SessionError::Transport(_))));
}

#[test]
fn session_error_from_variants() {
    let error = SessionError::from(ClientInitializeError::Cancelled);
    assert!(matches!(error, SessionError::Initialize(_)));

    let error = SessionError::from(ServiceError::TransportClosed);
    assert!(matches!(error, SessionError::Service(_)));

    let error = SessionError::from(std::io::Error::other("io"));
    assert!(matches!(error, SessionError::Transport(_)));
}

#[test]
fn error_data_constants_round_trip() {
    let error = ErrorData::new(ErrorCode::INVALID_REQUEST, "nope", None);
    assert_eq!(error.code, ErrorCode::INVALID_REQUEST);
    assert_eq!(error.message.as_ref(), "nope");
}

#[tokio::test]
async fn test_transport_unhandled_request_and_close() {
    let mut transport = TestTransport::new();
    let request = ClientJsonRpcMessage::request(
        ClientRequest::ListToolsRequest(ListToolsRequest {
            method: Default::default(),
            params: Some(PaginatedRequestParam { cursor: None }),
            extensions: Default::default(),
        }),
        rmcp::model::NumberOrString::Number(99),
    );
    let _ = transport.send(request).await;
    transport.close().await.expect("close");
}

fn call_tool_response(id: rmcp::model::RequestId) -> ServerJsonRpcMessage {
    let result = CallToolResult::success(vec![Content::text("ok")]);
    ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id,
        result: ServerResult::CallToolResult(result),
    })
}

fn init_response(id: rmcp::model::RequestId) -> ServerJsonRpcMessage {
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
