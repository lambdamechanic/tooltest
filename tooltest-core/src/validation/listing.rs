use std::fmt;
use std::future::Future;

use rmcp::model::Tool;

use crate::schema::parse_list_tools;
use crate::{HttpConfig, SchemaConfig, SchemaError, SessionDriver, SessionError, StdioConfig};

/// Errors emitted while listing tools.
#[derive(Debug)]
pub enum ListToolsError {
    /// Failed to communicate with the MCP endpoint.
    Session(SessionError),
    /// MCP payload failed schema validation.
    Schema(SchemaError),
}

impl fmt::Display for ListToolsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListToolsError::Session(error) => write!(f, "session error: {error:?}"),
            ListToolsError::Schema(error) => write!(f, "schema error: {error}"),
        }
    }
}

impl std::error::Error for ListToolsError {}

impl From<SessionError> for ListToolsError {
    fn from(error: SessionError) -> Self {
        ListToolsError::Session(error)
    }
}

impl From<SchemaError> for ListToolsError {
    fn from(error: SchemaError) -> Self {
        ListToolsError::Schema(error)
    }
}

/// Lists tools from an HTTP MCP endpoint using the provided configuration.
///
/// ```no_run
/// use tooltest_core::{list_tools_http, HttpConfig, SchemaConfig};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let config = HttpConfig {
///     url: "http://localhost:3000/mcp".into(),
///     auth_token: None,
/// };
/// let tools = list_tools_http(&config, &SchemaConfig::default()).await?;
/// println!("found {} tools", tools.len());
/// # Ok(())
/// # }
/// # tokio::runtime::Runtime::new().unwrap().block_on(run());
/// ```
pub async fn list_tools_http(
    config: &HttpConfig,
    schema: &SchemaConfig,
) -> Result<Vec<Tool>, ListToolsError> {
    list_tools_with_connector(config, schema, SessionDriver::connect_http).await
}

/// Lists tools from a stdio MCP endpoint using the provided configuration.
///
/// ```no_run
/// use tooltest_core::{list_tools_stdio, SchemaConfig, StdioConfig};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let config = StdioConfig::new("./my-mcp-server");
/// let tools = list_tools_stdio(&config, &SchemaConfig::default()).await?;
/// assert!(!tools.is_empty());
/// # Ok(())
/// # }
/// # tokio::runtime::Runtime::new().unwrap().block_on(run());
/// ```
pub async fn list_tools_stdio(
    config: &StdioConfig,
    schema: &SchemaConfig,
) -> Result<Vec<Tool>, ListToolsError> {
    list_tools_with_connector(config, schema, SessionDriver::connect_stdio).await
}

/// Lists tools from an active session using MCP schema validation.
///
/// ```no_run
/// use tooltest_core::{list_tools_with_session, SchemaConfig, SessionDriver, StdioConfig};
///
/// # async fn run() {
/// let session = SessionDriver::connect_stdio(&StdioConfig::new("./my-mcp-server"))
///     .await
///     .expect("connect");
/// let tools = list_tools_with_session(&session, &SchemaConfig::default())
///     .await
///     .expect("list tools");
/// println!("tool names: {:?}", tools.iter().map(|tool| &tool.name).collect::<Vec<_>>());
/// # }
/// # tokio::runtime::Runtime::new().unwrap().block_on(run());
/// ```
pub async fn list_tools_with_session(
    session: &SessionDriver,
    schema: &SchemaConfig,
) -> Result<Vec<Tool>, ListToolsError> {
    let tools = session.list_tools().await?;
    let payload = serde_json::to_value(&rmcp::model::ListToolsResult {
        tools,
        next_cursor: None,
        meta: None,
    })
    .expect("list tools serialize");
    let parsed = parse_list_tools(payload, schema)?;
    Ok(parsed.tools)
}

async fn list_tools_with_connector<T, F, Fut>(
    config: T,
    schema: &SchemaConfig,
    connector: F,
) -> Result<Vec<Tool>, ListToolsError>
where
    F: FnOnce(T) -> Fut,
    Fut: Future<Output = Result<SessionDriver, SessionError>>,
{
    let session = connector(config).await?;
    list_tools_with_session(&session, schema).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tooltest_test_support::{FaultyListToolsTransport, ListToolsTransport, stub_tool};

    #[test]
    fn list_tools_error_display_formats() {
        let error = ListToolsError::Schema(SchemaError::InvalidListTools("boom".to_string()));
        assert!(format!("{error}").contains("schema error"));

        let io_error = std::io::Error::new(std::io::ErrorKind::Other, "nope");
        let error = ListToolsError::Session(SessionError::from(io_error));
        assert!(format!("{error}").contains("session error"));
    }

    #[tokio::test]
    async fn list_tools_with_connector_returns_tools() {
        let tool = stub_tool("echo");
        let transport = ListToolsTransport::new(vec![tool.clone()]);
        let tools = list_tools_with_connector((), &SchemaConfig::default(), move |_| async move {
            SessionDriver::connect_with_transport(transport).await
        })
        .await
        .expect("list tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name.as_ref(), tool.name.as_ref());
    }

    #[tokio::test]
    async fn list_tools_with_connector_propagates_session_error() {
        let error = list_tools_with_connector((), &SchemaConfig::default(), |_| async {
            Err(SessionError::from(std::io::Error::new(
                std::io::ErrorKind::Other,
                "nope",
            )))
        })
        .await
        .expect_err("session error");
        assert!(error.to_string().contains("session error"));
    }

    #[tokio::test]
    async fn list_tools_with_session_propagates_list_error() {
        let transport = FaultyListToolsTransport::default();
        let session = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");

        let error = list_tools_with_session(&session, &SchemaConfig::default())
            .await
            .expect_err("list tools error");
        assert!(error.to_string().contains("session error"));
    }

    #[tokio::test]
    async fn list_tools_with_session_reports_schema_error() {
        let mut tool = stub_tool("echo");
        tool.output_schema = Some(Arc::new(
            serde_json::json!({ "type": 5 })
                .as_object()
                .cloned()
                .unwrap(),
        ));
        let transport = ListToolsTransport::new(vec![tool]);
        let session = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");

        let error = list_tools_with_session(&session, &SchemaConfig::default())
            .await
            .expect_err("schema error");
        assert!(error.to_string().contains("schema error"));
    }

    #[cfg(coverage)]
    #[tokio::test]
    async fn list_tools_http_reports_session_error() {
        let config = HttpConfig {
            url: "http://127.0.0.1:0/mcp".to_string(),
            auth_token: None,
        };

        let error = list_tools_http(&config, &SchemaConfig::default())
            .await
            .expect_err("list tools error");
        assert!(error.to_string().contains("session error"));
    }

    #[cfg(coverage)]
    #[tokio::test]
    async fn list_tools_stdio_reports_session_error() {
        let config = StdioConfig::new("/no/such/tooltest-binary");

        let error = list_tools_stdio(&config, &SchemaConfig::default())
            .await
            .expect_err("list tools error");
        assert!(error.to_string().contains("session error"));
    }
}
