//! Public API types for configuring and reporting tooltest runs.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Number, Value as JsonValue};

mod generator;
mod runner;
pub mod schema;
pub mod session;
mod validation;

pub use rmcp::model::{
    CallToolRequestParam, CallToolResult, ErrorCode, ErrorData, JsonObject, Tool,
};
pub use rmcp::service::{ClientInitializeError, ServiceError};
pub use runner::{run_http, run_stdio, run_with_session, RunnerOptions};
pub use schema::{
    parse_call_tool_request, parse_call_tool_result, parse_list_tools, schema_version_label,
    SchemaError,
};
pub use session::{SessionDriver, SessionError};
pub use validation::{
    list_tools_http, list_tools_stdio, validate_tool, validate_tools, BulkToolValidationSummary,
    ToolValidationConfig, ToolValidationDecision, ToolValidationError, ToolValidationFailure,
    ToolValidationFn,
};

#[cfg(test)]
mod tests;

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

/// Generator mode selection for MCP sequence runs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorMode {
    /// Use the legacy proptest-based generator.
    #[default]
    Legacy,
    /// Use the state-machine generator.
    StateMachine,
}

/// Configuration for state-machine generator behavior.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StateMachineConfig {
    /// Seed numbers added to the corpus before generation.
    pub seed_numbers: Vec<Number>,
    /// Seed strings added to the corpus before generation.
    pub seed_strings: Vec<String>,
    /// Mine whitespace-delimited text tokens into the corpus.
    pub mine_text: bool,
    /// Dump the final state-machine corpus after the run completes.
    pub dump_corpus: bool,
    /// Log newly mined corpus values after each tool response.
    pub log_corpus_deltas: bool,
    /// Allow schema-based generation when corpus lacks required values.
    pub lenient_sourcing: bool,
    /// Optional allowlist for coverage warnings and validation.
    pub coverage_allowlist: Option<Vec<String>>,
    /// Optional blocklist for coverage warnings and validation.
    pub coverage_blocklist: Option<Vec<String>>,
    /// Coverage validation rules applied after state-machine runs.
    pub coverage_rules: Vec<CoverageRule>,
}

impl StateMachineConfig {
    /// Sets the seed numbers for the state-machine corpus.
    pub fn with_seed_numbers(mut self, seed_numbers: Vec<Number>) -> Self {
        self.seed_numbers = seed_numbers;
        self
    }

    /// Sets the seed strings for the state-machine corpus.
    pub fn with_seed_strings(mut self, seed_strings: Vec<String>) -> Self {
        self.seed_strings = seed_strings;
        self
    }

    /// Enables mining of whitespace-delimited text tokens into the corpus.
    pub fn with_mine_text(mut self, mine_text: bool) -> Self {
        self.mine_text = mine_text;
        self
    }

    /// Enables dumping the final state-machine corpus after the run completes.
    pub fn with_dump_corpus(mut self, dump_corpus: bool) -> Self {
        self.dump_corpus = dump_corpus;
        self
    }

    /// Enables logging newly mined corpus values after each tool response.
    pub fn with_log_corpus_deltas(mut self, log_corpus_deltas: bool) -> Self {
        self.log_corpus_deltas = log_corpus_deltas;
        self
    }

    /// Enables schema-based generation when corpus lacks required values.
    pub fn with_lenient_sourcing(mut self, lenient_sourcing: bool) -> Self {
        self.lenient_sourcing = lenient_sourcing;
        self
    }

    /// Sets the coverage allowlist for state-machine runs.
    pub fn with_coverage_allowlist(mut self, coverage_allowlist: Vec<String>) -> Self {
        self.coverage_allowlist = Some(coverage_allowlist);
        self
    }

    /// Sets the coverage blocklist for state-machine runs.
    pub fn with_coverage_blocklist(mut self, coverage_blocklist: Vec<String>) -> Self {
        self.coverage_blocklist = Some(coverage_blocklist);
        self
    }

    /// Sets the coverage validation rules for state-machine runs.
    pub fn with_coverage_rules(mut self, coverage_rules: Vec<CoverageRule>) -> Self {
        self.coverage_rules = coverage_rules;
        self
    }
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

/// Predicate callback used to decide whether a tool invocation is eligible.
pub type ToolPredicate = Arc<dyn Fn(&str, &JsonValue) -> bool + Send + Sync>;

/// Declarative JSON assertion DSL container.
///
/// Runs also apply default assertions that fail on tool error responses and
/// validate structured output against declared output schemas.
///
/// Example:
/// ```
/// use serde_json::json;
/// use tooltest_core::{
///     AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, ResponseAssertion,
/// };
///
/// let assertions = AssertionSet {
///     rules: vec![AssertionRule::Response(ResponseAssertion {
///         tool: Some("echo".to_string()),
///         checks: vec![AssertionCheck {
///             target: AssertionTarget::StructuredOutput,
///             pointer: "/status".to_string(),
///             expected: json!("ok"),
///         }],
///     })],
/// };
/// ```
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
    /// Checks applied to the response payloads (input, output, or structured output).
    pub checks: Vec<AssertionCheck>,
}

/// Assertions evaluated against the entire run sequence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceAssertion {
    /// Checks applied to the sequence payload.
    pub checks: Vec<AssertionCheck>,
}

/// A single JSON-pointer based check.
///
/// `pointer` uses RFC 6901 JSON Pointer syntax.
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
    /// The structured tool output object, when present or required by schema.
    StructuredOutput,
    /// The full run sequence payload.
    Sequence,
}

/// Top-level configuration for executing a tooltest run.
#[derive(Clone)]
pub struct RunConfig {
    /// MCP schema configuration.
    pub schema: SchemaConfig,
    /// Optional predicate to filter eligible tools.
    pub predicate: Option<ToolPredicate>,
    /// Assertion rules to evaluate during the run.
    pub assertions: AssertionSet,
    /// Generator mode selection for sequence generation.
    pub generator_mode: GeneratorMode,
    /// State-machine generator configuration.
    pub state_machine: StateMachineConfig,
}

impl RunConfig {
    /// Creates a run configuration with defaults for schema and assertions.
    pub fn new() -> Self {
        Self {
            schema: SchemaConfig::default(),
            predicate: None,
            assertions: AssertionSet::default(),
            generator_mode: GeneratorMode::default(),
            state_machine: StateMachineConfig::default(),
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

    /// Sets the generator mode for the run.
    pub fn with_generator_mode(mut self, generator_mode: GeneratorMode) -> Self {
        self.generator_mode = generator_mode;
        self
    }

    /// Sets the state-machine generator configuration.
    pub fn with_state_machine(mut self, state_machine: StateMachineConfig) -> Self {
        self.state_machine = state_machine;
        self
    }
}

impl Default for RunConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RunConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunConfig")
            .field("schema", &self.schema)
            .field("predicate", &self.predicate.is_some())
            .field("assertions", &self.assertions)
            .field("generator_mode", &self.generator_mode)
            .field("state_machine", &self.state_machine)
            .finish()
    }
}

/// A generated tool invocation.
pub type ToolInvocation = CallToolRequestParam;

/// A trace entry capturing MCP interactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceEntry {
    /// A list-tools request was issued.
    ListTools {
        /// Optional failure detail when list-tools fails.
        #[serde(skip_serializing_if = "Option::is_none")]
        failure_reason: Option<String>,
    },
    /// A tool call, optionally annotated with a response on failure.
    ToolCall {
        /// The invocation that was sent.
        invocation: ToolInvocation,
        /// Optional response payload (omitted in compact traces).
        #[serde(skip_serializing_if = "Option::is_none")]
        response: Option<CallToolResult>,
        /// Optional failure detail when a call fails.
        #[serde(skip_serializing_if = "Option::is_none")]
        failure_reason: Option<String>,
    },
}

impl TraceEntry {
    /// Creates a trace entry for a list-tools call.
    pub fn list_tools() -> Self {
        Self::ListTools {
            failure_reason: None,
        }
    }

    /// Creates a trace entry for a failed list-tools call.
    pub fn list_tools_with_failure(reason: String) -> Self {
        Self::ListTools {
            failure_reason: Some(reason),
        }
    }

    /// Creates a trace entry for a tool call without a response.
    pub fn tool_call(invocation: ToolInvocation) -> Self {
        Self::ToolCall {
            invocation,
            response: None,
            failure_reason: None,
        }
    }

    /// Creates a trace entry for a tool call with a response.
    pub fn tool_call_with_response(invocation: ToolInvocation, response: CallToolResult) -> Self {
        Self::ToolCall {
            invocation,
            response: Some(response),
            failure_reason: None,
        }
    }

    /// Returns the invocation and response when the entry is a tool call.
    pub fn as_tool_call(&self) -> Option<(&ToolInvocation, Option<&CallToolResult>)> {
        match self {
            TraceEntry::ToolCall {
                invocation,
                response,
                ..
            } => Some((invocation, response.as_ref())),
            TraceEntry::ListTools { .. } => None,
        }
    }
}

/// A minimized failing sequence from property-based testing.
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
    /// Optional structured failure code.
    pub code: Option<String>,
    /// Optional structured failure details.
    pub details: Option<JsonValue>,
}

impl RunFailure {
    /// Creates a run failure with only a reason string.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            code: None,
            details: None,
        }
    }
}

/// Warning emitted during a tooltest run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunWarning {
    /// Structured warning code.
    pub code: RunWarningCode,
    /// Human-readable warning message.
    pub message: String,
    /// Optional tool name associated with the warning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

/// Structured warning codes for tooltest runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunWarningCode {
    SchemaUnsupportedKeyword,
}

/// Warning describing a coverage issue in a state-machine run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageWarning {
    /// Tool name that could not be called.
    pub tool: String,
    /// Reason the tool could not be called.
    pub reason: CoverageWarningReason,
}

/// Structured reason codes for coverage warnings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageWarningReason {
    MissingString,
    MissingInteger,
    MissingNumber,
    MissingRequiredValue,
}

/// Coverage report for state-machine runs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Successful tool call counts.
    pub counts: BTreeMap<String, u64>,
    /// Coverage warnings for uncallable tools.
    pub warnings: Vec<CoverageWarning>,
}

/// Snapshot of the state-machine corpus.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorpusReport {
    /// Numbers observed in the corpus.
    pub numbers: Vec<Number>,
    /// Integers observed in the corpus.
    pub integers: Vec<i64>,
    /// Strings observed in the corpus.
    pub strings: Vec<String>,
}

/// Coverage validation rules for state-machine runs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum CoverageRule {
    /// Require a minimum number of successful calls per tool.
    MinCallsPerTool { min: u64 },
    /// Require that all callable tools are called at least once.
    NoUncalledTools,
    /// Require a minimum percentage of callable tools to be called.
    PercentCalled { min_percent: f64 },
}

impl CoverageRule {
    /// Helper to enforce minimum calls per tool.
    pub fn min_calls_per_tool(min: u64) -> Self {
        Self::MinCallsPerTool { min }
    }

    /// Helper to enforce no uncalled tools.
    pub fn no_uncalled_tools() -> Self {
        Self::NoUncalledTools
    }

    /// Helper to enforce minimum percentage of tools called.
    pub fn percent_called(min_percent: f64) -> Self {
        Self::PercentCalled { min_percent }
    }
}

/// Results of a tooltest run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunResult {
    /// Overall run outcome.
    pub outcome: RunOutcome,
    /// Trace of MCP calls (responses are only included on failures).
    pub trace: Vec<TraceEntry>,
    /// Minimized sequence for failures, when available.
    pub minimized: Option<MinimizedSequence>,
    /// Non-fatal warnings collected during the run.
    pub warnings: Vec<RunWarning>,
    /// Coverage report for state-machine runs, when enabled.
    pub coverage: Option<CoverageReport>,
    /// Corpus snapshot for state-machine runs, when enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corpus: Option<CorpusReport>,
}
