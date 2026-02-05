use axum::Router;
use rmcp::handler::server::{
    router::tool::ToolRouter,
    wrapper::{Json, Parameters},
};
use rmcp::transport::{
    streamable_http_server::session::local::LocalSessionManager, StreamableHttpServerConfig,
    StreamableHttpService,
};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tooltest_core::{list_tools_http, list_tools_stdio, HttpConfig, SchemaConfig, StdioConfig};

#[derive(Clone)]
struct HttpTestServer {
    tool_router: ToolRouter<Self>,
}

impl HttpTestServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for HttpTestServer {}

#[derive(Deserialize, Serialize, JsonSchema)]
struct EchoInput {
    value: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct EchoOutput {
    status: String,
}

#[tool_router]
impl HttpTestServer {
    #[tool(name = "echo", description = "Echo input for list-tools tests")]
    async fn echo(&self, _params: Parameters<EchoInput>) -> Json<EchoOutput> {
        Json(EchoOutput {
            status: "ok".to_string(),
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn list_tools_http_succeeds_with_streamable_server() {
    let http_config = StreamableHttpServerConfig {
        stateful_mode: true,
        sse_keep_alive: None,
        ..Default::default()
    };
    let service: StreamableHttpService<HttpTestServer, LocalSessionManager> =
        StreamableHttpService::new(|| Ok(HttpTestServer::new()), Default::default(), http_config);
    let app = Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let config = HttpConfig {
        url: format!("http://{addr}/mcp"),
        auth_token: None,
    };
    let tools = list_tools_http(&config, &SchemaConfig::default())
        .await
        .expect("list tools");

    let _ = shutdown_tx.send(());
    let _ = server.await;

    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name.as_ref(), "echo");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_tools_stdio_succeeds_with_test_server() {
    let server = env!("CARGO_BIN_EXE_stdio_test_server");
    let config = StdioConfig::new(server);

    let tools = list_tools_stdio(&config, &SchemaConfig::default())
        .await
        .expect("list tools");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name.as_ref(), "echo");
}
