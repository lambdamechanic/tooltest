//! Error handling strategy for the rmcp-backed session driver.
//!
//! We preserve rmcp error types inside `SessionError` to keep transport and
//! session layers aligned and to retain full error context for debugging.

use crate::{HttpConfig, StdioConfig, ToolInvocation, TraceEntry};
use rmcp::model::Tool;
use rmcp::service::{ClientInitializeError, RoleClient, RunningService, ServiceError, ServiceExt};
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
        let transport = build_http_transport(config)?;
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

    /// Sends a tool invocation via rmcp and records the response.
    pub async fn send_tool_call(
        &self,
        invocation: ToolInvocation,
    ) -> Result<TraceEntry, SessionError> {
        let response = self.service.peer().call_tool(invocation.clone()).await?;
        Ok(TraceEntry {
            invocation,
            response,
        })
    }

    /// Lists all tools available from the MCP session.
    pub async fn list_tools(&self) -> Result<Vec<Tool>, SessionError> {
        let tools = self.service.peer().list_all_tools().await?;
        Ok(tools)
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
///
/// Errors are surfaced as `SessionError` to preserve rmcp error context.
fn build_http_transport(
    config: &HttpConfig,
) -> Result<rmcp::transport::StreamableHttpClientTransport<reqwest::Client>, SessionError> {
    use rmcp::transport::StreamableHttpClientTransport;

    Ok(StreamableHttpClientTransport::from_config(
        http_transport_config(config),
    ))
}

#[cfg(test)]
mod tests {
    use super::http_transport_config;
    use crate::HttpConfig;

    #[test]
    fn http_transport_config_strips_bearer_prefix() {
        let config = HttpConfig {
            url: "https://example.com/mcp".to_string(),
            auth_token: Some("Bearer test-token".to_string()),
        };
        let transport_config = http_transport_config(&config);
        assert_eq!(transport_config.auth_header.as_deref(), Some("test-token"));
    }

    #[test]
    fn http_transport_config_preserves_raw_token() {
        let config = HttpConfig {
            url: "https://example.com/mcp".to_string(),
            auth_token: Some("raw-token".to_string()),
        };
        let transport_config = http_transport_config(&config);
        assert_eq!(transport_config.auth_header.as_deref(), Some("raw-token"));
    }

    #[test]
    fn http_transport_config_skips_missing_token() {
        let config = HttpConfig {
            url: "https://example.com/mcp".to_string(),
            auth_token: None,
        };
        let transport_config = http_transport_config(&config);
        assert!(transport_config.auth_header.is_none());
    }
}
