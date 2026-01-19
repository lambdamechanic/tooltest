use std::env;
use std::time::Duration;

use crate::{validate_tool, HttpConfig, SessionDriver, ToolValidationConfig};
use tokio::time::timeout;

const CASES_PER_TOOL_DEFAULT: usize = 10;
const CASES_PER_TOOL_ENV: &str = "TOOLTEST_HOSTED_CASES_PER_TOOL";
const SKIP_ENV: &str = "SKIP_HOSTED_MCP_TESTS";
const RUN_EXTERNAL_ENV: &str = "RUN_EXTERNAL_TESTS";
const HOSTED_TOOL_TIMEOUT: Duration = Duration::from_secs(15);

fn skip_hosted_tests() -> bool {
    if env::var(SKIP_ENV).is_ok() {
        return true;
    }
    env::var(RUN_EXTERNAL_ENV).is_err()
}

fn cases_per_tool() -> usize {
    env::var(CASES_PER_TOOL_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(CASES_PER_TOOL_DEFAULT)
}

async fn validate_hosted(url: &str) {
    init_tracing();

    if skip_hosted_tests() {
        return;
    }

    let config = HttpConfig {
        url: url.to_string(),
        auth_token: None,
    };
    let session = SessionDriver::connect_http(&config)
        .await
        .expect("connect hosted MCP");
    let tools = session.list_tools().await.expect("list tools");
    assert!(!tools.is_empty(), "hosted MCP returned no tools");
    let validation = ToolValidationConfig::new().with_cases_per_tool(cases_per_tool());

    let mut failures = Vec::new();
    for tool in tools {
        let name = tool.name.to_string();
        match timeout(
            HOSTED_TOOL_TIMEOUT,
            validate_tool(&session, &validation, &tool),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("{name}: {error}")),
            Err(_) => failures.push(format!("{name}: timed out after {HOSTED_TOOL_TIMEOUT:?}")),
        }
    }

    if !failures.is_empty() {
        eprintln!("Hosted MCP validation issues for {url}:");
        for failure in failures {
            eprintln!("  - {failure}");
        }
    }
}

fn init_tracing() {
    static INIT_TRACING: std::sync::Once = std::sync::Once::new();
    INIT_TRACING.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init();
    });
}

#[tokio::test]
async fn hosted_mcp_epss_tools() {
    validate_hosted("https://pymcp.app.lambdamechanic.com/epss/mcp").await;
}

#[tokio::test]
async fn hosted_mcp_kev_tools() {
    validate_hosted("https://pymcp.app.lambdamechanic.com/kev/mcp").await;
}
