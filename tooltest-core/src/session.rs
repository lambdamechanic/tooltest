use crate::{AuthHeader, HttpConfig, StdioConfig, ToolInvocation, TraceEntry};
use rmcp::model::CallToolRequestParam;
use rmcp::service::{ClientInitializeError, RoleClient, RunningService, ServiceError, ServiceExt};

/// Errors emitted by the rmcp-backed session driver.
///
/// The rmcp error variants are boxed to keep the enum size small; match on
/// `SessionError` and then inspect the boxed error as needed.
#[derive(Debug)]
pub enum SessionError {
    /// Initialization failed while establishing the session.
    Initialize(Box<ClientInitializeError>),
    /// The session failed while sending or receiving requests.
    Service(Box<ServiceError>),
    /// Failed to spawn or configure the stdio transport.
    Transport(Box<std::io::Error>),
    /// Provided HTTP auth header is invalid.
    InvalidAuthHeader { name: String, value: String },
}

impl From<ClientInitializeError> for SessionError {
    fn from(error: ClientInitializeError) -> Self {
        Self::Initialize(Box::new(error))
    }
}

impl From<ServiceError> for SessionError {
    fn from(error: ServiceError) -> Self {
        Self::Service(Box::new(error))
    }
}

impl From<std::io::Error> for SessionError {
    fn from(error: std::io::Error) -> Self {
        Self::Transport(Box::new(error))
    }
}

/// Session driver that uses rmcp client/session APIs.
pub struct SessionDriver {
    service: RunningService<RoleClient, ()>,
}

impl SessionDriver {
    /// Connects to an MCP server over stdio using rmcp child-process transport.
    #[cfg(not(test))]
    pub async fn connect_stdio(config: &StdioConfig) -> Result<Self, SessionError> {
        use rmcp::transport::TokioChildProcess;
        use tokio::process::Command;

        let mut command = Command::new(&config.command);
        command.args(&config.args).envs(&config.env);
        if let Some(cwd) = &config.cwd {
            command.current_dir(cwd);
        }
        let transport = TokioChildProcess::new(command)?;
        Self::connect_with_transport(transport).await
    }

    /// Test stub for stdio transport setup.
    ///
    /// Use `connect_with_transport` with a test transport when unit testing
    /// successful stdio flows.
    #[cfg(test)]
    pub async fn connect_stdio(_config: &StdioConfig) -> Result<Self, SessionError> {
        Err(SessionError::Transport(Box::new(std::io::Error::other(
            "stdio transport disabled in tests",
        ))))
    }

    /// Connects to an MCP server over HTTP using rmcp streamable HTTP transport.
    #[cfg(not(test))]
    pub async fn connect_http(config: &HttpConfig) -> Result<Self, SessionError> {
        let transport = build_http_transport(config)?;
        Self::connect_with_transport(transport).await
    }

    /// Test stub for HTTP transport setup.
    ///
    /// Use `connect_with_transport` with a test transport when unit testing
    /// successful HTTP flows.
    #[cfg(test)]
    pub async fn connect_http(_config: &HttpConfig) -> Result<Self, SessionError> {
        Err(SessionError::Transport(Box::new(std::io::Error::other(
            "http transport disabled in tests",
        ))))
    }

    /// Connects using a custom rmcp transport implementation.
    pub async fn connect_with_transport<T, E, A>(transport: T) -> Result<Self, SessionError>
    where
        T: rmcp::transport::IntoTransport<RoleClient, E, A>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let service = ().serve(transport).await?;
        Ok(Self { service })
    }

    /// Returns the underlying rmcp peer for advanced interactions.
    pub fn peer(&self) -> &rmcp::service::Peer<RoleClient> {
        self.service.peer()
    }

    /// Sends a tool invocation via rmcp and records the response.
    pub async fn send_tool_call(
        &self,
        invocation: ToolInvocation,
    ) -> Result<TraceEntry, SessionError> {
        let params = CallToolRequestParam {
            name: invocation.name.clone().into(),
            arguments: invocation.arguments.as_object().cloned(),
        };
        let response = self.service.peer().call_tool(params).await?;
        let response = serde_json::to_value(&response).expect("call tool result should serialize");
        Ok(TraceEntry {
            invocation,
            response,
        })
    }

    /// Sends a sequence of tool invocations via rmcp.
    pub async fn run_invocations<I>(&self, invocations: I) -> Result<Vec<TraceEntry>, SessionError>
    where
        I: IntoIterator<Item = ToolInvocation>,
    {
        let mut trace = Vec::new();
        for invocation in invocations {
            trace.push(self.send_tool_call(invocation).await?);
        }
        Ok(trace)
    }
}

#[cfg(not(test))]
fn build_http_transport(
    config: &HttpConfig,
) -> Result<rmcp::transport::StreamableHttpClientTransport<reqwest::Client>, SessionError> {
    use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
    use rmcp::transport::StreamableHttpClientTransport;

    let mut transport_config = StreamableHttpClientTransportConfig::with_uri(config.url.as_str());
    if let Some(auth_header) = &config.auth_header {
        let token = normalize_auth_header(auth_header)?;
        transport_config = transport_config.auth_header(token);
    }
    Ok(StreamableHttpClientTransport::from_config(transport_config))
}

/// Validates the configured header name and returns a bearer token string.
///
/// The input value may include a `Bearer ` prefix; if present it is stripped
/// to match rmcp's expected auth token format.
fn normalize_auth_header(auth_header: &AuthHeader) -> Result<String, SessionError> {
    if !auth_header.name.eq_ignore_ascii_case("authorization") {
        return Err(SessionError::InvalidAuthHeader {
            name: auth_header.name.clone(),
            value: auth_header.value.clone(),
        });
    }
    let value = auth_header.value.trim();
    let token = value.strip_prefix("Bearer ").unwrap_or(value);
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use rmcp::model::{
        CallToolResult, ClientJsonRpcMessage, ClientRequest, Content, ErrorCode, ErrorData,
        InitializeResult, JsonRpcMessage, JsonRpcNotification, JsonRpcResponse, JsonRpcVersion2_0,
        ListToolsRequest, PaginatedRequestParam, ServerInfo, ServerJsonRpcMessage, ServerResult,
    };
    use rmcp::transport::Transport;
    use serde_json::json;
    use tokio::sync::mpsc;
    use tokio::sync::Mutex as AsyncMutex;

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

    impl Transport<RoleClient> for TestTransport {
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
                    ClientRequest::CallToolRequest(_) => {
                        Some(call_tool_response(request.id.clone()))
                    }
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

        let _ = driver.peer();
        let invocation = ToolInvocation {
            name: "echo".to_string(),
            arguments: json!({"value": "hello"}),
        };
        let trace = driver.send_tool_call(invocation).await.expect("tool call");

        let requests = requests.lock().expect("requests");
        assert!(matches!(requests[0], JsonRpcMessage::Request(_)));
        assert!(matches!(
            requests[1],
            JsonRpcMessage::Notification(JsonRpcNotification { .. })
        ));
        assert!(matches!(requests[2], JsonRpcMessage::Request(_)));
        assert_eq!(trace.response["isError"], false);
    }

    #[tokio::test]
    async fn run_invocations_collects_trace() {
        let transport = TestTransport::new();
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");

        let invocations = vec![
            ToolInvocation {
                name: "one".to_string(),
                arguments: json!({"a": 1}),
            },
            ToolInvocation {
                name: "two".to_string(),
                arguments: json!({"b": 2}),
            },
        ];
        let trace = driver.run_invocations(invocations).await.expect("trace");

        assert_eq!(trace.len(), 2);
    }

    #[test]
    fn invalid_auth_header_rejected() {
        let auth_header = AuthHeader {
            name: "Bad Header".to_string(),
            value: "value".to_string(),
        };
        let error = normalize_auth_header(&auth_header).expect_err("invalid header");
        assert!(matches!(
            error,
            SessionError::InvalidAuthHeader { name, value }
                if name == "Bad Header" && value == "value"
        ));
    }

    #[test]
    fn bearer_prefix_is_trimmed() {
        let auth_header = AuthHeader {
            name: "Authorization".to_string(),
            value: "Bearer token".to_string(),
        };
        let token = normalize_auth_header(&auth_header).expect("token");
        assert_eq!(token, "token");
    }

    #[tokio::test]
    async fn connect_http_stub_returns_error() {
        let config = HttpConfig {
            url: "http://localhost:8080/mcp".to_string(),
            auth_header: None,
        };
        let result = SessionDriver::connect_http(&config).await;
        assert!(matches!(result, Err(SessionError::Transport(_))));
    }

    #[tokio::test]
    async fn connect_stdio_stub_returns_error() {
        let config = StdioConfig::new("mcp-server");
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
}
