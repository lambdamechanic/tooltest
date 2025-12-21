//! Public API types for configuring and reporting tooltest runs.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub mod session;

pub use rmcp::model::{ErrorCode, ErrorData};
pub use rmcp::service::{ClientInitializeError, ServiceError};
pub use session::{SessionDriver, SessionError};

/// Schema versions supported by the tooltest core.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SchemaVersion {
    /// MCP schema version 2025-11-25.
    #[default]
    V2025_11_25,
    /// Any other explicitly configured schema version string.
    Other(String),
}

/// Configuration for MCP schema parsing and validation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaConfig {
    /// The selected MCP schema version.
    pub version: SchemaVersion,
}

/// Configuration for a stdio-based MCP endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StdioConfig {
    /// Command to execute for the MCP server.
    pub command: String,
    /// Command-line arguments passed to the MCP server.
    pub args: Vec<String>,
    /// Environment variables to add or override for the MCP process.
    pub env: BTreeMap<String, String>,
    /// Optional working directory for the MCP process.
    pub cwd: Option<String>,
}

impl StdioConfig {
    /// Creates a stdio configuration with defaults for args, env, and cwd.
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
        }
    }
}

/// Configuration for an HTTP-based MCP endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HttpConfig {
    /// The HTTP endpoint URL for MCP requests.
    pub url: String,
    /// Optional bearer token to attach to Authorization headers.
    pub auth_token: Option<String>,
}

/// Transport options for connecting to an MCP endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportConfig {
    /// Use stdio to communicate with an MCP server process.
    Stdio(StdioConfig),
    /// Use HTTP to communicate with an MCP server.
    Http(HttpConfig),
}

/// Predicate callback used to decide whether a tool invocation is eligible.
pub type ToolPredicate = Arc<dyn Fn(&str, &JsonValue) -> bool + Send + Sync>;

/// Declarative JSON assertion DSL container.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AssertionSet {
    /// Assertion rules evaluated during or after a run.
    pub rules: Vec<AssertionRule>,
}

/// A single assertion rule in the JSON DSL.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "scope", content = "rule", rename_all = "snake_case")]
pub enum AssertionRule {
    /// Assertions evaluated against each tool response.
    Response(ResponseAssertion),
    /// Assertions evaluated against the full run sequence.
    Sequence(SequenceAssertion),
}

/// Assertions evaluated against a tool response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseAssertion {
    /// Optional tool name filter; when set, only matching tools are checked.
    pub tool: Option<String>,
    /// Checks applied to the response payloads.
    pub checks: Vec<AssertionCheck>,
}

/// Assertions evaluated against the entire run sequence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceAssertion {
    /// Checks applied to the sequence payload.
    pub checks: Vec<AssertionCheck>,
}

/// A single JSON-pointer based check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssertionCheck {
    /// The target payload to inspect.
    pub target: AssertionTarget,
    /// JSON Pointer string used to select the value to compare.
    pub pointer: String,
    /// Expected JSON value at the pointer location.
    pub expected: JsonValue,
}

/// Payload targets that can be inspected by assertions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionTarget {
    /// The generated tool input object.
    Input,
    /// The raw tool output object.
    Output,
    /// The structured tool output object, when present.
    StructuredOutput,
    /// The full run sequence payload.
    Sequence,
}

/// Top-level configuration for executing a tooltest run.
#[derive(Clone)]
pub struct RunConfig {
    /// Transport configuration for the MCP endpoint.
    pub transport: TransportConfig,
    /// MCP schema configuration.
    pub schema: SchemaConfig,
    /// Optional predicate to filter eligible tools.
    pub predicate: Option<ToolPredicate>,
    /// Assertion rules to evaluate during the run.
    pub assertions: AssertionSet,
}

impl RunConfig {
    /// Creates a run configuration with defaults for schema and assertions.
    pub fn new(transport: TransportConfig) -> Self {
        Self {
            transport,
            schema: SchemaConfig::default(),
            predicate: None,
            assertions: AssertionSet::default(),
        }
    }

    /// Sets the schema configuration.
    pub fn with_schema(mut self, schema: SchemaConfig) -> Self {
        self.schema = schema;
        self
    }

    /// Sets the tool predicate used for eligibility filtering.
    pub fn with_predicate(mut self, predicate: ToolPredicate) -> Self {
        self.predicate = Some(predicate);
        self
    }

    /// Sets the assertion rules for the run.
    pub fn with_assertions(mut self, assertions: AssertionSet) -> Self {
        self.assertions = assertions;
        self
    }
}

impl fmt::Debug for RunConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunConfig")
            .field("transport", &self.transport)
            .field("schema", &self.schema)
            .field("predicate", &self.predicate.is_some())
            .field("assertions", &self.assertions)
            .finish()
    }
}

/// A generated tool invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolInvocation {
    /// The MCP tool name.
    pub name: String,
    /// Arguments passed to the tool.
    pub arguments: JsonValue,
}

/// A trace entry capturing one tool call and its response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceEntry {
    /// The invocation that was sent.
    pub invocation: ToolInvocation,
    /// The raw MCP response payload.
    pub response: JsonValue,
}

/// A minimized failing sequence from proptest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinimizedSequence {
    /// The minimized tool invocations that reproduce the failure.
    pub invocations: Vec<ToolInvocation>,
}

/// Outcome of a tooltest run.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RunOutcome {
    /// The run completed without assertion failures.
    Success,
    /// The run failed due to an error or assertion.
    Failure(RunFailure),
}

/// Failure details for a tooltest run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunFailure {
    /// Short description of the failure.
    pub reason: String,
}

/// Results of a tooltest run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunResult {
    /// Overall run outcome.
    pub outcome: RunOutcome,
    /// Full trace of tool invocations and responses.
    pub trace: Vec<TraceEntry>,
    /// Minimized sequence for failures, when available.
    pub minimized: Option<MinimizedSequence>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_config_defaults_to_latest() {
        let config = SchemaConfig::default();
        assert_eq!(config.version, SchemaVersion::V2025_11_25);
    }

    #[test]
    fn stdio_config_new_sets_defaults() {
        let config = StdioConfig::new("mcp-server");
        assert_eq!(config.command, "mcp-server");
        assert!(config.args.is_empty());
        assert!(config.env.is_empty());
        assert!(config.cwd.is_none());
    }

    #[test]
    fn run_config_builders_wire_fields() {
        let transport = TransportConfig::Http(HttpConfig {
            url: "https://example.test/mcp".to_string(),
            auth_token: Some("Bearer token".to_string()),
        });
        let schema = SchemaConfig {
            version: SchemaVersion::Other("2025-12-01".to_string()),
        };
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Response(ResponseAssertion {
                tool: Some("search".to_string()),
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/query".to_string(),
                    expected: json!("hello"),
                }],
            })],
        };
        let predicate: ToolPredicate = Arc::new(|name, input| {
            name == "search" && input.pointer("/query") == Some(&json!("hello"))
        });

        let config = RunConfig::new(transport.clone())
            .with_schema(schema.clone())
            .with_predicate(predicate)
            .with_assertions(assertions.clone());

        assert_eq!(config.transport, transport);
        assert_eq!(config.schema, schema);
        assert!(config.predicate.is_some());
        assert_eq!(config.assertions.rules.len(), 1);
        let predicate = config.predicate.as_ref().expect("predicate set");
        assert!(predicate("search", &json!({"query": "hello"})));
        assert!(!predicate("search", &json!({"query": "nope"})));

        let debug = format!("{config:?}");
        assert!(debug.contains("predicate: true"));
    }
}
