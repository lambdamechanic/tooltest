use std::sync::{Arc, Mutex};

use ctor::ctor;

#[ctor]
fn init_test_logger() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default())
        .is_test(true)
        .try_init();
}

use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, ErrorData, InitializeResult,
    JsonRpcMessage, JsonRpcResponse, JsonRpcVersion2_0, RequestId, ServerInfo,
    ServerJsonRpcMessage, ServerResult, Tool,
};
use rmcp::service::RoleClient;
use rmcp::transport::Transport;
use serde_json::json;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

pub fn tool_with_schemas(
    name: &str,
    input_schema: serde_json::Value,
    output_schema: Option<serde_json::Value>,
) -> Tool {
    Tool {
        name: name.to_string().into(),
        title: None,
        description: None,
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

pub fn call_tool_response(id: RequestId, response: CallToolResult) -> ServerJsonRpcMessage {
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

pub fn init_response(id: RequestId) -> ServerJsonRpcMessage {
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

pub fn stub_tool(name: &str) -> Tool {
    Tool::new(
        name.to_string(),
        "stub tool",
        json!({ "type": "object" }).as_object().cloned().unwrap(),
    )
}

pub struct ListToolsTransport {
    tools: Vec<Tool>,
    responses: Arc<AsyncMutex<mpsc::UnboundedReceiver<ServerJsonRpcMessage>>>,
    response_tx: mpsc::UnboundedSender<ServerJsonRpcMessage>,
}

impl ListToolsTransport {
    pub fn new(tools: Vec<Tool>) -> Self {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        Self {
            tools,
            responses: Arc::new(AsyncMutex::new(response_rx)),
            response_tx,
        }
    }
}

impl Transport<RoleClient> for ListToolsTransport {
    type Error = std::convert::Infallible;

    fn send(
        &mut self,
        item: ClientJsonRpcMessage,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        let response_tx = self.response_tx.clone();
        let tools = self.tools.clone();
        if let JsonRpcMessage::Request(request) = &item {
            let response = match &request.request {
                ClientRequest::InitializeRequest(_) => Some(init_response(request.id.clone())),
                ClientRequest::ListToolsRequest(_) => {
                    Some(list_tools_response(request.id.clone(), tools))
                }
                _ => None,
            };
            let _ = response.map(|response| response_tx.send(response));
        }
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

#[derive(Debug)]
pub struct TransportError(pub &'static str);

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for TransportError {}

pub struct FaultyListToolsTransport {
    responses: Arc<AsyncMutex<mpsc::UnboundedReceiver<ServerJsonRpcMessage>>>,
    response_tx: mpsc::UnboundedSender<ServerJsonRpcMessage>,
}

impl FaultyListToolsTransport {
    pub fn new() -> Self {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        Self {
            responses: Arc::new(AsyncMutex::new(response_rx)),
            response_tx,
        }
    }
}

impl Default for FaultyListToolsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport<RoleClient> for FaultyListToolsTransport {
    type Error = TransportError;

    fn send(
        &mut self,
        item: ClientJsonRpcMessage,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        let response_tx = self.response_tx.clone();
        if let JsonRpcMessage::Request(request) = &item {
            match &request.request {
                ClientRequest::InitializeRequest(_) => {
                    let _ = response_tx.send(init_response(request.id.clone()));
                }
                ClientRequest::ListToolsRequest(_) => {
                    return std::future::ready(Err(TransportError("list tools")));
                }
                _ => {}
            }
        }
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

pub struct RunnerTransport {
    tools: Vec<Tool>,
    response: CallToolResult,
    list_tools_error: Option<ErrorData>,
    call_tool_error: Option<ErrorData>,
    requests: Arc<Mutex<Vec<ClientJsonRpcMessage>>>,
    responses: Arc<AsyncMutex<mpsc::UnboundedReceiver<ServerJsonRpcMessage>>>,
    response_tx: mpsc::UnboundedSender<ServerJsonRpcMessage>,
}

impl RunnerTransport {
    pub fn new(tool: Tool, response: CallToolResult) -> Self {
        Self::new_with_tools(vec![tool], response)
    }

    pub fn new_with_tools(tools: Vec<Tool>, response: CallToolResult) -> Self {
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        Self {
            tools,
            response,
            list_tools_error: None,
            call_tool_error: None,
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(AsyncMutex::new(response_rx)),
            response_tx,
        }
    }

    pub fn with_list_tools_error(mut self, error: ErrorData) -> Self {
        self.list_tools_error = Some(error);
        self
    }

    pub fn with_call_tool_error(mut self, error: ErrorData) -> Self {
        self.call_tool_error = Some(error);
        self
    }
}

impl Transport<RoleClient> for RunnerTransport {
    type Error = std::convert::Infallible;

    fn send(
        &mut self,
        item: ClientJsonRpcMessage,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        let requests = Arc::clone(&self.requests);
        let response_tx = self.response_tx.clone();
        let tools = self.tools.clone();
        let response = self.response.clone();
        let list_tools_error = self.list_tools_error.clone();
        let call_tool_error = self.call_tool_error.clone();
        let message = item.clone();
        if let JsonRpcMessage::Request(request) = &item {
            let server_message = match &request.request {
                ClientRequest::InitializeRequest(_) => Some(init_response(request.id.clone())),
                ClientRequest::ListToolsRequest(_) => list_tools_error
                    .map(|error| ServerJsonRpcMessage::error(error, request.id.clone()))
                    .or_else(|| Some(list_tools_response(request.id.clone(), tools))),
                ClientRequest::CallToolRequest(_) => call_tool_error
                    .map(|error| ServerJsonRpcMessage::error(error, request.id.clone()))
                    .or_else(|| Some(call_tool_response(request.id.clone(), response))),
                _ => None,
            };
            if let Some(response) = server_message {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{
        ClientNotification, ClientRequest, InitializeRequest, InitializeRequestParam,
        InitializedNotification, ListPromptsRequest, ListToolsRequest, NumberOrString,
        PaginatedRequestParam, ServerJsonRpcMessage, ServerResult,
    };

    fn run_async<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn init_message(id: i64) -> ClientJsonRpcMessage {
        ClientJsonRpcMessage::request(
            ClientRequest::InitializeRequest(InitializeRequest::new(
                InitializeRequestParam::default(),
            )),
            NumberOrString::Number(id),
        )
    }

    fn list_tools_message(id: i64) -> ClientJsonRpcMessage {
        ClientJsonRpcMessage::request(
            ClientRequest::ListToolsRequest(ListToolsRequest {
                method: Default::default(),
                params: Some(PaginatedRequestParam { cursor: None }),
                extensions: Default::default(),
            }),
            NumberOrString::Number(id),
        )
    }

    fn list_prompts_message(id: i64) -> ClientJsonRpcMessage {
        ClientJsonRpcMessage::request(
            ClientRequest::ListPromptsRequest(ListPromptsRequest {
                method: Default::default(),
                params: Some(PaginatedRequestParam { cursor: None }),
                extensions: Default::default(),
            }),
            NumberOrString::Number(id),
        )
    }

    fn initialized_notification_message() -> ClientJsonRpcMessage {
        ClientJsonRpcMessage::notification(ClientNotification::InitializedNotification(
            InitializedNotification::default(),
        ))
    }

    fn assert_init_response(response: ServerJsonRpcMessage) {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::InitializeResult(_) => {}
                other => panic!("unexpected result: {other:?}"),
            },
            other => panic!("unexpected message: {other:?}"),
        }
    }

    fn assert_list_tools_response(response: ServerJsonRpcMessage, expected: &Tool) {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::ListToolsResult(result) => {
                    assert!(result.tools.iter().any(|tool| tool.name == expected.name));
                }
                other => panic!("unexpected result: {other:?}"),
            },
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn transport_error_formats_message() {
        let error = TransportError("boom");
        assert_eq!(error.to_string(), "boom");
    }

    #[test]
    fn list_tools_transport_close_ok() {
        run_async(async {
            let mut transport = ListToolsTransport::new(vec![stub_tool("echo")]);
            transport.close().await.expect("close");
        });
    }

    #[test]
    fn faulty_list_tools_transport_handles_initialize_and_list_tools() {
        run_async(async {
            let mut transport = FaultyListToolsTransport::default();
            transport.send(init_message(1)).await.expect("init send");
            let response = transport.receive().await.expect("init response");
            assert_init_response(response);
            let error = transport
                .send(list_tools_message(2))
                .await
                .expect_err("list tools send");
            assert_eq!(error.to_string(), "list tools");
            transport.close().await.expect("close");
        });
    }

    #[test]
    fn list_tools_transport_handles_list_tools_request() {
        run_async(async {
            let tool = stub_tool("echo");
            let mut transport = ListToolsTransport::new(vec![tool.clone()]);
            transport.send(init_message(1)).await.expect("init send");
            let response = transport.receive().await.expect("init response");
            assert_init_response(response);

            transport
                .send(list_tools_message(2))
                .await
                .expect("list tools send");
            let response = transport.receive().await.expect("list tools response");
            assert_list_tools_response(response, &tool);
            transport.close().await.expect("close");
        });
    }

    #[test]
    fn list_tools_transport_ignores_unhandled_requests() {
        run_async(async {
            let mut transport = ListToolsTransport::new(vec![stub_tool("echo")]);
            transport.send(list_prompts_message(3)).await.expect("send");
            {
                let mut receiver = transport.responses.lock().await;
                assert!(receiver.try_recv().is_err());
            }
            transport.close().await.expect("close");
        });
    }

    #[test]
    fn list_tools_transport_ignores_notifications() {
        run_async(async {
            let mut transport = ListToolsTransport::new(vec![stub_tool("echo")]);
            transport
                .send(initialized_notification_message())
                .await
                .expect("send");
            {
                let mut receiver = transport.responses.lock().await;
                assert!(receiver.try_recv().is_err());
            }
            transport.close().await.expect("close");
        });
    }

    #[test]
    #[should_panic(expected = "unexpected result")]
    fn assert_list_tools_response_panics_on_unexpected_result() {
        let message = ServerJsonRpcMessage::Response(rmcp::model::JsonRpcResponse {
            jsonrpc: rmcp::model::JsonRpcVersion2_0,
            id: rmcp::model::RequestId::Number(1),
            result: ServerResult::InitializeResult(InitializeResult::default()),
        });
        assert_list_tools_response(message, &stub_tool("echo"));
    }

    #[test]
    #[should_panic(expected = "unexpected message")]
    fn assert_list_tools_response_panics_on_unexpected_message() {
        let message = ServerJsonRpcMessage::Notification(rmcp::model::JsonRpcNotification {
            jsonrpc: rmcp::model::JsonRpcVersion2_0,
            notification: rmcp::model::ServerNotification::CustomNotification(
                rmcp::model::CustomNotification::new("test", None),
            ),
        });
        assert_list_tools_response(message, &stub_tool("echo"));
    }

    #[test]
    #[should_panic(expected = "unexpected result")]
    fn assert_init_response_panics_on_unexpected_result() {
        let message = ServerJsonRpcMessage::Response(rmcp::model::JsonRpcResponse {
            jsonrpc: rmcp::model::JsonRpcVersion2_0,
            id: rmcp::model::RequestId::Number(1),
            result: ServerResult::ListToolsResult(rmcp::model::ListToolsResult {
                tools: Vec::new(),
                next_cursor: None,
                meta: None,
            }),
        });
        assert_init_response(message);
    }

    #[test]
    #[should_panic(expected = "unexpected message")]
    fn assert_init_response_panics_on_unexpected_message() {
        let message = ServerJsonRpcMessage::Notification(rmcp::model::JsonRpcNotification {
            jsonrpc: rmcp::model::JsonRpcVersion2_0,
            notification: rmcp::model::ServerNotification::CustomNotification(
                rmcp::model::CustomNotification::new("test", None),
            ),
        });
        assert_init_response(message);
    }
}
