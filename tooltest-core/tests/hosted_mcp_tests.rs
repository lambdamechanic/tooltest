#![cfg(not(coverage))]

use rmcp::service::ServiceExt;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use tokio::time::{timeout, Duration};

mod support;

const HOSTED_MCP_URLS: [&str; 3] = [
    "https://pymcp.app.lambdamechanic.com/attack/mcp",
    "https://pymcp.app.lambdamechanic.com/kev/mcp",
    "https://pymcp.app.lambdamechanic.com/epss/mcp",
];

fn should_run_hosted_tests() -> bool {
    std::env::var("SKIP_HOSTED_MCP_TESTS").is_err()
}

fn auth_header_token() -> Option<String> {
    let token = std::env::var("HOSTED_MCP_AUTH_TOKEN").ok()?;
    let token = token.trim();
    let token = token.strip_prefix("Bearer ").unwrap_or(token);
    Some(token.to_string())
}

fn build_transport(url: &str) -> StreamableHttpClientTransport<reqwest::Client> {
    let mut config = StreamableHttpClientTransportConfig::with_uri(url);
    if let Some(token) = auth_header_token() {
        config = config.auth_header(token);
    }
    StreamableHttpClientTransport::from_config(config)
}

#[tokio::test]
async fn hosted_mcp_servers_list_tools() {
    support::init_tracing();
    if !should_run_hosted_tests() {
        eprintln!("set SKIP_HOSTED_MCP_TESTS=1 to skip hosted MCP integration tests");
        return;
    }

    for url in HOSTED_MCP_URLS {
        let transport = build_transport(url);
        let service = ().serve(transport).await.expect("connect");

        let tools = timeout(
            Duration::from_secs(15),
            service.list_tools(Default::default()),
        )
        .await
        .expect("list tools timeout")
        .expect("list tools");

        assert!(
            !tools.tools.is_empty(),
            "expected at least one tool from {url}"
        );

        let _ = service.cancel().await;
    }
}
