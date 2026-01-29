use axum::Router;
use futures::stream::Stream;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    ClientJsonRpcMessage, ClientNotification, ClientRequest, InitializeRequest,
    InitializeRequestParam, InitializedNotification, NumberOrString,
};
use rmcp::transport::{
    streamable_http_server::session::local::LocalSessionManager, stdio, StreamableHttpServerConfig,
    StreamableHttpService,
};
use rmcp::{RoleServer, ServiceExt};
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

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

impl ServerHandler for McpServer {}

#[cfg(test)]
mod tests {
    use super::NoopSink;
    use futures::SinkExt;

    #[tokio::test]
    async fn noop_sink_close_completes() {
        let mut sink = NoopSink;
        sink.close().await.expect("close");
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
