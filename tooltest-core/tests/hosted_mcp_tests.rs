#![cfg(not(coverage))]

use rmcp::service::ServiceExt;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use tokio::time::{timeout, Duration};

mod support;

const ATTACK_MCP_URL: &str = "https://pymcp.app.lambdamechanic.com/attack/mcp";
const KEV_MCP_URL: &str = "https://pymcp.app.lambdamechanic.com/kev/mcp";
const EPSS_MCP_URL: &str = "https://pymcp.app.lambdamechanic.com/epss/mcp";

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

async fn assert_hosted_tools(url: &str) {
    support::init_tracing();
    if !should_run_hosted_tests() {
        eprintln!("set SKIP_HOSTED_MCP_TESTS=1 to skip hosted MCP integration tests");
        return;
    }

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

#[tokio::test]
async fn hosted_mcp_attack_list_tools() {
    assert_hosted_tools(ATTACK_MCP_URL).await;
}

#[tokio::test]
async fn hosted_mcp_kev_list_tools() {
    assert_hosted_tools(KEV_MCP_URL).await;
}

#[tokio::test]
async fn hosted_mcp_epss_list_tools() {
    assert_hosted_tools(EPSS_MCP_URL).await;
}
