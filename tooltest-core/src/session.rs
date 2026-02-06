//! Error handling strategy for the rmcp-backed session driver.
//!
//! We preserve rmcp error types inside `SessionError` to keep transport and
//! session layers aligned and to retain full error context for debugging.

use crate::{HttpConfig, StdioConfig, ToolInvocation};
use log::debug;
use rmcp::model::Tool;
use rmcp::service::{ClientInitializeError, RoleClient, RunningService, ServiceError, ServiceExt};
use serde::Serialize;
/// Errors emitted by the rmcp-backed session driver.
///
/// The rmcp error variants are boxed to keep the enum size small; match on
/// `SessionError` and then inspect the boxed error as needed.
#[non_exhaustive]
#[derive(Debug)]
pub enum SessionError {
    /// Initialization failed while establishing the session.
    Initialize(Box<ClientInitializeError>),
    /// The session failed while sending or receiving requests.
    Service(Box<ServiceError>),
    /// Failed to spawn or configure the stdio transport.
    Transport(Box<std::io::Error>),
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

#[cfg(test)]
#[path = "../tests/internal/session_unit_tests.rs"]
mod tests;

impl SessionDriver {
    /// Connects to an MCP server over stdio using rmcp child-process transport.
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

    /// Connects to an MCP server over HTTP using rmcp streamable HTTP transport.
    pub async fn connect_http(config: &HttpConfig) -> Result<Self, SessionError> {
        let transport = build_http_transport(config);
        Self::connect_with_transport(transport).await
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

    /// Sends a tool invocation via rmcp and returns the response.
    pub async fn call_tool(
        &self,
        invocation: ToolInvocation,
    ) -> Result<rmcp::model::CallToolResult, SessionError> {
        log_io("call_tool request", &invocation);
        let response = self.service.peer().call_tool(invocation).await?;
        log_io("call_tool response", &response);
        Ok(response)
    }

    /// Lists all tools available from the MCP session.
    pub async fn list_tools(&self) -> Result<Vec<Tool>, SessionError> {
        log_io_message("list_tools request");
        let tools = self.service.peer().list_all_tools().await?;
        log_io("list_tools response", &tools);
        Ok(tools)
    }

    /// Returns the server-reported MCP protocol version, if available.
    pub fn server_protocol_version(&self) -> Option<String> {
        self.service
            .peer()
            .peer_info()
            .map(|info| info.protocol_version.to_string())
    }
}

const IO_LOG_TARGET: &str = "tooltest.io_logs";

fn log_io_message(message: &str) {
    debug!(target: IO_LOG_TARGET, "{message}");
}

fn log_io<T: Serialize>(label: &str, value: &T) {
    debug!(
        target: IO_LOG_TARGET,
        "{label}: {}",
        serde_json::to_string(value)
            .unwrap_or_else(|error| format!("<serialize error: {error}>"))
    );
}

/// Builds an HTTP transport config for MCP communication.
#[cfg_attr(coverage, allow(dead_code))]
fn http_transport_config(
    config: &HttpConfig,
) -> rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig {
    use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;

    let mut transport_config = StreamableHttpClientTransportConfig::with_uri(config.url.as_str());
    if let Some(auth_token) = &config.auth_token {
        let token = auth_token.trim();
        let token = token.strip_prefix("Bearer ").unwrap_or(token);
        transport_config = transport_config.auth_header(token.to_string());
    }
    transport_config
}

/// Builds an HTTP transport for MCP communication.
fn build_http_transport(
    config: &HttpConfig,
) -> rmcp::transport::StreamableHttpClientTransport<reqwest::Client> {
    use rmcp::transport::StreamableHttpClientTransport;

    StreamableHttpClientTransport::from_config(http_transport_config(config))
}
