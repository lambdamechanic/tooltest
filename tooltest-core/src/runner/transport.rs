use std::future::Future;
use std::pin::Pin;

use crate::{HttpConfig, RunConfig, RunFailure, RunResult, SessionDriver, StdioConfig};

use super::execution::{run_with_session, RunnerOptions};
use super::result::failure_result;

pub(super) type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SessionDriver, crate::SessionError>> + Send + 'a>>;

/// Execute a tooltest run against a stdio MCP endpoint.
///
/// Uses the same default and declarative assertions as [`run_with_session`].
pub async fn run_stdio(
    endpoint: &StdioConfig,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    run_with_transport(
        Box::pin(SessionDriver::connect_stdio(endpoint)),
        "stdio",
        config,
        options,
    )
    .await
}

/// Execute a tooltest run against an HTTP MCP endpoint.
///
/// Uses the same default and declarative assertions as [`run_with_session`].
pub async fn run_http(
    endpoint: &HttpConfig,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    run_with_transport(
        Box::pin(SessionDriver::connect_http(endpoint)),
        "http",
        config,
        options,
    )
    .await
}

pub(super) async fn run_with_transport(
    connect: ConnectFuture<'_>,
    label: &str,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    let session = match connect.await {
        Ok(session) => session,
        Err(error) => {
            return failure_result(
                RunFailure::new(format!("failed to connect {label} transport: {error:?}")),
                Vec::new(),
                None,
                Vec::new(),
                None,
                None,
            );
        }
    };
    run_with_session(&session, config, options).await
}
