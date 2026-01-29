use axum::Router;
use futures::stream::Stream;
use rmcp::handler::server::common::schema_for_type;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    ClientJsonRpcMessage, ClientNotification, ClientRequest, InitializeRequest,
    InitializeRequestParam, InitializedNotification, NumberOrString,
    GetPromptRequestParam, GetPromptResult, ListPromptsResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParam, Prompt, PromptMessage, PromptMessageContent,
    PromptMessageRole, ReadResourceRequestParam, ReadResourceResult, ResourceContents, Tool,
    RawResource, AnnotateAble, Resource,
};
use rmcp::transport::{
    streamable_http_server::session::local::LocalSessionManager, stdio, StreamableHttpServerConfig,
    StreamableHttpService,
};
use rmcp::{ErrorData, RoleServer, ServiceExt};
use serde_json::json;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use tooltest_core::TooltestInput;

const TOOLTEST_TOOL_NAME: &str = "tooltest";
const TOOLTEST_TOOL_DESCRIPTION: &str =
    "Run tooltest against an MCP server using the shared tooltest input.";
const TOOLTEST_FIX_LOOP_PROMPT_NAME: &str = "tooltest-fix-loop";
const TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION: &str =
    "Guidance for iterating on tooltest failures in MCP servers.";
const TOOLTEST_FIX_LOOP_RESOURCE_URI: &str = "tooltest://guides/fix-loop";
const TOOLTEST_FIX_LOOP_RESOURCE_NAME: &str = "tooltest-fix-loop";
const TOOLTEST_FIX_LOOP_RESOURCE_DESCRIPTION: &str =
    "Step-by-step guidance for running tooltest to fix MCP issues.";
const TOOLTEST_FIX_LOOP_PROMPT: &str = r#"You have access to this repository and can run commands.
Goal: make the repository's MCP server(s) conform to the MCP spec as exercised by tooltest.

Figure out how to start the MCP server from this repo (stdio or streamable HTTP).

Select a small, related subset of tools intended to be used together. Default to testing at most 50 tools at a time, and strongly prefer a smaller group. Use `--tool-allowlist` (or `tool_allowlist` in MCP input) to enforce this.

Run tooltest against it (examples below).

When tooltest reports failures, fix the underlying issues in the smallest reasonable patch.

Re-run tooltest and repeat until it exits 0.

If you see "state-machine generator failed to reach minimum sequence length", re-run with `--lenient-sourcing` or seed values in `--state-machine-config`.

If you need per-case traces for debugging, add `--trace-all /tmp/tooltest-traces.jsonl` (any writable path).

If you are invoking tooltest via the MCP tool instead of the CLI, pass the same options in the tool input.

Don't rename tools or change schemas unless required; prefer backward-compatible fixes.

Add/adjust tests if needed.

Commands (choose the right one):

CLI stdio (allowlist example): tooltest stdio --command "<command that starts the repo's MCP server>" --tool-allowlist foo --tool-allowlist bar

CLI http (allowlist example): tooltest http --url "http://127.0.0.1:9000/mcp" --tool-allowlist foo --tool-allowlist bar

MCP tool (allowlist example):
{
  "target": { "stdio": { "command": "<command that starts the repo's MCP server>" } },
  "tool_allowlist": ["foo", "bar"]
}

Return a short summary of what you changed and why, plus the final passing tooltest output snippet.
"#;

fn exit_immediately() -> bool {
    std::env::var_os("TOOLTEST_MCP_EXIT_IMMEDIATELY").is_some()
}

fn use_test_transport() -> bool {
    std::env::var_os("TOOLTEST_MCP_TEST_TRANSPORT").is_some()
}

struct NoopSink;

impl futures::Sink<rmcp::service::TxJsonRpcMessage<RoleServer>> for NoopSink {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: Pin<&mut Self>,
        _item: rmcp::service::TxJsonRpcMessage<RoleServer>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

type TestStream =
    rmcp::service::RxJsonRpcMessage<RoleServer>;

struct TestStreamState {
    messages: VecDeque<TestStream>,
    panic_on_empty: bool,
}

impl TestStreamState {
    fn new(messages: Vec<TestStream>, panic_on_empty: bool) -> Self {
        Self {
            messages: VecDeque::from(messages),
            panic_on_empty,
        }
    }
}

impl Stream for TestStreamState {
    type Item = TestStream;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(message) = self.messages.pop_front() {
            return Poll::Ready(Some(message));
        }
        if self.panic_on_empty {
            panic!("test transport exhausted");
        }
        Poll::Ready(None)
    }
}

fn stdio_test_transport() -> (NoopSink, TestStreamState) {
    let init = ClientJsonRpcMessage::request(
        ClientRequest::InitializeRequest(InitializeRequest::new(InitializeRequestParam::default())),
        NumberOrString::Number(1),
    );
    let initialized = ClientJsonRpcMessage::notification(
        ClientNotification::InitializedNotification(InitializedNotification::default()),
    );
    (
        NoopSink,
        TestStreamState::new(vec![init, initialized], false),
    )
}

fn stdio_bad_transport() -> (NoopSink, TestStreamState) {
    (NoopSink, TestStreamState::new(Vec::new(), false))
}

fn stdio_panic_transport() -> (NoopSink, TestStreamState) {
    let init = ClientJsonRpcMessage::request(
        ClientRequest::InitializeRequest(InitializeRequest::new(InitializeRequestParam::default())),
        NumberOrString::Number(1),
    );
    let initialized = ClientJsonRpcMessage::notification(
        ClientNotification::InitializedNotification(InitializedNotification::default()),
    );
    (
        NoopSink,
        TestStreamState::new(vec![init, initialized], true),
    )
}

#[derive(Clone, Default)]
pub struct McpServer;

impl McpServer {
    pub fn new() -> Self {
        Self
    }
}

impl ServerHandler for McpServer {
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        std::future::ready(Ok(ListToolsResult {
            tools: vec![tooltest_tool()],
            ..Default::default()
        }))
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListPromptsResult {
            prompts: vec![fix_loop_prompt()],
            ..Default::default()
        }))
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetPromptResult, rmcp::ErrorData>> + Send + '_
    {
        let name = request.name;
        std::future::ready(if name == TOOLTEST_FIX_LOOP_PROMPT_NAME {
            Ok(fix_loop_prompt_result())
        } else {
            Err(prompt_not_found_error(&name))
        })
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListResourcesResult {
            resources: vec![fix_loop_resource()],
            ..Default::default()
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, rmcp::ErrorData>> + Send + '_
    {
        let uri = request.uri;
        std::future::ready(if uri == TOOLTEST_FIX_LOOP_RESOURCE_URI {
            Ok(ReadResourceResult {
                contents: vec![fix_loop_resource_contents()],
            })
        } else {
            Err(ErrorData::resource_not_found(
                format!("resource '{uri}' not found"),
                None,
            ))
        })
    }
}

fn tooltest_tool() -> Tool {
    Tool {
        name: TOOLTEST_TOOL_NAME.into(),
        title: None,
        description: Some(TOOLTEST_TOOL_DESCRIPTION.into()),
        input_schema: schema_for_type::<TooltestInput>(),
        output_schema: None,
        annotations: None,
        icons: None,
        meta: None,
    }
}

fn fix_loop_prompt() -> Prompt {
    Prompt::new(
        TOOLTEST_FIX_LOOP_PROMPT_NAME,
        Some(TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION),
        None,
    )
}

fn fix_loop_prompt_result() -> GetPromptResult {
    GetPromptResult {
        description: Some(TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION.to_string()),
        messages: vec![PromptMessage {
            role: PromptMessageRole::User,
            content: PromptMessageContent::Text {
                text: TOOLTEST_FIX_LOOP_PROMPT.to_string(),
            },
        }],
    }
}

fn prompt_not_found_error(name: &str) -> ErrorData {
    ErrorData::invalid_params(
        format!("prompt '{name}' not found"),
        Some(json!({ "available_prompts": [TOOLTEST_FIX_LOOP_PROMPT_NAME] })),
    )
}

fn fix_loop_resource() -> Resource {
    RawResource {
        uri: TOOLTEST_FIX_LOOP_RESOURCE_URI.to_string(),
        name: TOOLTEST_FIX_LOOP_RESOURCE_NAME.to_string(),
        title: None,
        description: Some(TOOLTEST_FIX_LOOP_RESOURCE_DESCRIPTION.to_string()),
        mime_type: Some("text/plain".to_string()),
        size: None,
        icons: None,
        meta: None,
    }
    .no_annotation()
}

fn fix_loop_resource_contents() -> ResourceContents {
    ResourceContents::TextResourceContents {
        uri: TOOLTEST_FIX_LOOP_RESOURCE_URI.to_string(),
        mime_type: Some("text/plain".to_string()),
        text: TOOLTEST_FIX_LOOP_PROMPT.to_string(),
        meta: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        McpServer, NoopSink, TOOLTEST_FIX_LOOP_PROMPT, TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION,
        TOOLTEST_FIX_LOOP_PROMPT_NAME, TOOLTEST_FIX_LOOP_RESOURCE_URI, TOOLTEST_TOOL_DESCRIPTION,
        TOOLTEST_TOOL_NAME,
    };
    use futures::SinkExt;
    use rmcp::model::{
        ClientJsonRpcMessage, ClientRequest, EmptyResult, ErrorCode, GetPromptRequest,
        GetPromptRequestParam, ListPromptsRequest, ListResourcesRequest, ListToolsRequest,
        NumberOrString, PaginatedRequestParam, ReadResourceRequest, ReadResourceRequestParam,
        ServerJsonRpcMessage, ServerResult,
    };
    use rmcp::model::AnnotateAble;
    use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
    use rmcp::transport::Transport;
    use rmcp::RoleServer;
    use tokio::sync::mpsc;

    struct TestTransport {
        incoming: mpsc::UnboundedReceiver<RxJsonRpcMessage<RoleServer>>,
        outgoing: mpsc::UnboundedSender<TxJsonRpcMessage<RoleServer>>,
    }

    impl Transport<RoleServer> for TestTransport {
        type Error = std::convert::Infallible;

        fn send(
            &mut self,
            item: TxJsonRpcMessage<RoleServer>,
        ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
            let _ = self.outgoing.send(item);
            std::future::ready(Ok(()))
        }

        fn receive(
            &mut self,
        ) -> impl std::future::Future<Output = Option<RxJsonRpcMessage<RoleServer>>> + Send {
            self.incoming.recv()
        }

        fn close(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
            std::future::ready(Ok(()))
        }
    }

    fn test_transport(
    ) -> (
        TestTransport,
        mpsc::UnboundedSender<RxJsonRpcMessage<RoleServer>>,
        mpsc::UnboundedReceiver<TxJsonRpcMessage<RoleServer>>,
    ) {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        (
            TestTransport {
                incoming: incoming_rx,
                outgoing: outgoing_tx,
            },
            incoming_tx,
            outgoing_rx,
        )
    }

    async fn send_request(request: ClientRequest) -> ServerJsonRpcMessage {
        let (transport, incoming_tx, mut outgoing_rx) = test_transport();
        let running = rmcp::service::serve_directly(McpServer::new(), transport, None);
        let message = ClientJsonRpcMessage::request(request, NumberOrString::Number(1));
        incoming_tx.send(message).expect("send");
        let response = outgoing_rx.recv().await.expect("response");
        let _ = running.cancel().await;
        drop(incoming_tx);
        response
    }

    fn list_tools_from_response(response: ServerJsonRpcMessage) -> Option<Vec<rmcp::model::Tool>> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::ListToolsResult(result) => Some(result.tools),
                _ => None,
            },
            _ => None,
        }
    }

    fn list_prompts_from_response(
        response: ServerJsonRpcMessage,
    ) -> Option<Vec<rmcp::model::Prompt>> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::ListPromptsResult(result) => Some(result.prompts),
                _ => None,
            },
            _ => None,
        }
    }

    fn get_prompt_from_response(
        response: ServerJsonRpcMessage,
    ) -> Option<rmcp::model::GetPromptResult> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::GetPromptResult(result) => Some(result),
                _ => None,
            },
            _ => None,
        }
    }

    fn list_resources_from_response(
        response: ServerJsonRpcMessage,
    ) -> Option<Vec<rmcp::model::Resource>> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::ListResourcesResult(result) => Some(result.resources),
                _ => None,
            },
            _ => None,
        }
    }

    fn read_resource_from_response(
        response: ServerJsonRpcMessage,
    ) -> Option<rmcp::model::ReadResourceResult> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::ReadResourceResult(result) => Some(result),
                _ => None,
            },
            _ => None,
        }
    }

    fn prompt_text_from_message(message: &rmcp::model::PromptMessage) -> Option<&str> {
        match &message.content {
            rmcp::model::PromptMessageContent::Text { text } => Some(text.as_str()),
            _ => None,
        }
    }

    fn resource_text_from_content(
        content: &rmcp::model::ResourceContents,
    ) -> Option<(&str, Option<&str>)> {
        match content {
            rmcp::model::ResourceContents::TextResourceContents { text, mime_type, .. } => {
                Some((text.as_str(), mime_type.as_deref()))
            }
            _ => None,
        }
    }

    #[tokio::test]
    async fn noop_sink_close_completes() {
        let mut sink = NoopSink;
        sink.close().await.expect("close");
    }

    #[tokio::test]
    async fn list_tools_includes_tooltest() {
        let response = send_request(ClientRequest::ListToolsRequest(ListToolsRequest {
            method: Default::default(),
            params: None,
            extensions: Default::default(),
        }))
        .await;
        let tools = list_tools_from_response(response).expect("list tools response");
        let tool = tools
            .iter()
            .find(|tool| tool.name.as_ref() == TOOLTEST_TOOL_NAME)
            .expect("tooltest tool");
        assert_eq!(tool.description.as_deref(), Some(TOOLTEST_TOOL_DESCRIPTION));
        assert!(!tool.input_schema.is_empty());
    }

    #[tokio::test]
    async fn list_prompts_includes_fix_loop() {
        let response = send_request(ClientRequest::ListPromptsRequest(ListPromptsRequest {
            method: Default::default(),
            params: Some(PaginatedRequestParam { cursor: None }),
            extensions: Default::default(),
        }))
        .await;
        let prompts = list_prompts_from_response(response).expect("list prompts response");
        let prompt = prompts
            .iter()
            .find(|prompt| prompt.name == TOOLTEST_FIX_LOOP_PROMPT_NAME)
            .expect("prompt");
        assert_eq!(
            prompt.description.as_deref(),
            Some(TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION)
        );
    }

    #[tokio::test]
    async fn get_prompt_returns_fix_loop_literal() {
        let response = send_request(ClientRequest::GetPromptRequest(GetPromptRequest {
            method: Default::default(),
            params: GetPromptRequestParam {
                name: TOOLTEST_FIX_LOOP_PROMPT_NAME.to_string(),
                arguments: None,
            },
            extensions: Default::default(),
        }))
        .await;
        let result = get_prompt_from_response(response).expect("get prompt response");
        let message = result.messages.first().expect("prompt message");
        let text = prompt_text_from_message(message).expect("text prompt content");
        assert_eq!(text, TOOLTEST_FIX_LOOP_PROMPT);
    }

    #[tokio::test]
    async fn list_resources_includes_fix_loop() {
        let response = send_request(ClientRequest::ListResourcesRequest(
            ListResourcesRequest {
                method: Default::default(),
                params: Some(PaginatedRequestParam { cursor: None }),
                extensions: Default::default(),
            },
        ))
        .await;
        let resources = list_resources_from_response(response).expect("list resources response");
        let resource = resources
            .iter()
            .find(|resource| resource.uri == TOOLTEST_FIX_LOOP_RESOURCE_URI)
            .expect("resource");
        assert_eq!(resource.mime_type.as_deref(), Some("text/plain"));
    }

    #[tokio::test]
    async fn read_resource_returns_fix_loop_text() {
        let response = send_request(ClientRequest::ReadResourceRequest(ReadResourceRequest {
            method: Default::default(),
            params: ReadResourceRequestParam {
                uri: TOOLTEST_FIX_LOOP_RESOURCE_URI.to_string(),
            },
            extensions: Default::default(),
        }))
        .await;
        let result = read_resource_from_response(response).expect("read resource response");
        let content = result.contents.first().expect("resource content");
        let (text, mime_type) = resource_text_from_content(content).expect("text content");
        assert_eq!(mime_type, Some("text/plain"));
        assert_eq!(text, TOOLTEST_FIX_LOOP_PROMPT);
    }

    #[tokio::test]
    async fn get_prompt_unknown_returns_error() {
        let response = send_request(ClientRequest::GetPromptRequest(GetPromptRequest {
            method: Default::default(),
            params: GetPromptRequestParam {
                name: "unknown".to_string(),
                arguments: None,
            },
            extensions: Default::default(),
        }))
        .await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn read_resource_unknown_returns_error() {
        let response = send_request(ClientRequest::ReadResourceRequest(ReadResourceRequest {
            method: Default::default(),
            params: ReadResourceRequestParam {
                uri: "tooltest://guides/unknown".to_string(),
            },
            extensions: Default::default(),
        }))
        .await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::RESOURCE_NOT_FOUND);
    }

    #[tokio::test]
    async fn response_helpers_return_none_for_errors() {
        let response =
            ServerJsonRpcMessage::error(rmcp::ErrorData::invalid_params("boom", None), NumberOrString::Number(1));
        assert!(list_tools_from_response(response.clone()).is_none());
        assert!(list_prompts_from_response(response.clone()).is_none());
        assert!(get_prompt_from_response(response.clone()).is_none());
        assert!(list_resources_from_response(response.clone()).is_none());
        assert!(read_resource_from_response(response).is_none());
    }

    #[tokio::test]
    async fn response_helpers_return_none_for_unexpected_results() {
        let response = ServerJsonRpcMessage::response(
            ServerResult::EmptyResult(EmptyResult {}),
            NumberOrString::Number(2),
        );
        assert!(list_tools_from_response(response.clone()).is_none());
        assert!(list_prompts_from_response(response.clone()).is_none());
        assert!(get_prompt_from_response(response.clone()).is_none());
        assert!(list_resources_from_response(response.clone()).is_none());
        assert!(read_resource_from_response(response).is_none());
    }

    #[test]
    fn prompt_text_from_message_returns_none_for_non_text() {
        let resource = rmcp::model::RawResource::new("tooltest://example", "example")
            .no_annotation();
        let message = rmcp::model::PromptMessage {
            role: rmcp::model::PromptMessageRole::User,
            content: rmcp::model::PromptMessageContent::ResourceLink { link: resource },
        };
        assert!(prompt_text_from_message(&message).is_none());
    }

    #[test]
    fn resource_text_from_content_returns_none_for_blob() {
        let content = rmcp::model::ResourceContents::BlobResourceContents {
            uri: "tooltest://example".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            blob: "deadbeef".to_string(),
            meta: None,
        };
        assert!(resource_text_from_content(&content).is_none());
    }
}

pub async fn run_stdio() -> Result<(), String> {
    let exit_immediately = exit_immediately();
    let service = if use_test_transport() {
        let transport = if std::env::var_os("TOOLTEST_MCP_BAD_TRANSPORT").is_some() {
            stdio_bad_transport()
        } else if std::env::var_os("TOOLTEST_MCP_PANIC_TRANSPORT").is_some() {
            stdio_panic_transport()
        } else {
            stdio_test_transport()
        };
        McpServer::new()
            .serve(transport)
            .await
            .map_err(|error| format!("failed to start MCP stdio server: {error}"))?
    } else {
        McpServer::new()
            .serve(stdio())
            .await
            .map_err(|error| format!("failed to start MCP stdio server: {error}"))?
    };
    if exit_immediately {
        if std::env::var_os("TOOLTEST_MCP_PANIC_TRANSPORT").is_some() {
            tokio::task::yield_now().await;
        }
        service
            .cancel()
            .await
            .map_err(|error| format!("MCP stdio server failed: {error}"))?;
        return Ok(());
    }
    service
        .waiting()
        .await
        .map_err(|error| format!("MCP stdio server failed: {error}"))?;
    Ok(())
}

async fn serve_http(listener: tokio::net::TcpListener, app: Router) -> Result<(), std::io::Error> {
    if std::env::var_os("TOOLTEST_MCP_FORCE_HTTP_ERROR").is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "forced http error",
        ));
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            if exit_immediately() {
                return;
            }
            std::future::pending::<()>().await;
        })
        .await
}

pub async fn run_http(bind: &str) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| format!("failed to bind MCP HTTP server at {bind}: {error}"))?;
    let service_factory = || Ok(McpServer::new());
    let _ = service_factory();
    let service: StreamableHttpService<McpServer, LocalSessionManager> = StreamableHttpService::new(
        service_factory,
        Default::default(),
        StreamableHttpServerConfig::default(),
    );
    let app = Router::new().nest_service("/mcp", service);
    serve_http(listener, app)
        .await
        .map_err(|error| format!("failed to serve MCP HTTP server at {bind}: {error}"))?;
    Ok(())
}
