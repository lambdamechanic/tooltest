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
    list_tools_with_connector(config.clone(), schema, |config| async move {
        SessionDriver::connect_http(&config).await
    })
    .await
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
    list_tools_with_connector(config.clone(), schema, |config| async move {
        SessionDriver::connect_stdio(&config).await
    })
    .await
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

pub(crate) async fn list_tools_with_connector<T, F, Fut>(
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
