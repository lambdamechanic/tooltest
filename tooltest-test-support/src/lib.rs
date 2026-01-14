use std::sync::{Arc, Mutex};

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
            let mut response = None;
            if let ClientRequest::InitializeRequest(_) = &request.request {
                response = Some(init_response(request.id.clone()));
            } else if let ClientRequest::ListToolsRequest(_) = &request.request {
                response = Some(list_tools_response(request.id.clone(), tools));
            }
            if let Some(response) = response {
                let _ = response_tx.send(response);
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
