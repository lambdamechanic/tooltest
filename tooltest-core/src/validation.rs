//! Helpers for enumerating tools and validating tool behavior.

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::future::Future;
use std::sync::Arc;

use crate::generator::{invocation_strategy, schema_violations};
use crate::{
    HttpConfig, RunConfig, RunFailure, SessionDriver, SessionError, StdioConfig, TraceEntry,
};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use rmcp::model::Tool;

const DEFAULT_CASES_PER_TOOL: usize = 50;
const CASES_PER_TOOL_ENV: &str = "TOOLTEST_CASES_PER_TOOL";

/// Middleware decision returned by a tool validator.
#[derive(Clone, Debug)]
pub enum ToolValidationDecision {
    /// Accept the tool response and stop the validation chain.
    Accept,
    /// Reject the tool response with a failure.
    Reject(RunFailure),
    /// Defer to the next validator in the chain.
    Defer,
}

/// Callable used to validate a tool response.
pub type ToolValidationFn = Arc<dyn Fn(&Tool, &TraceEntry) -> ToolValidationDecision + Send + Sync>;

/// Configuration for bulk tool validation.
#[derive(Clone)]
pub struct ToolValidationConfig {
    /// Run-level configuration and predicates.
    pub run: RunConfig,
    /// Number of cases to exercise per tool.
    pub cases_per_tool: usize,
    /// Validators invoked after each tool call.
    pub validators: Vec<ToolValidationFn>,
}

impl ToolValidationConfig {
    /// Creates a validation configuration with defaults.
    pub fn new() -> Self {
        Self {
            run: RunConfig::new(),
            cases_per_tool: default_cases_per_tool(),
            validators: default_validators(),
        }
    }

    /// Sets the per-tool case count.
    pub fn with_cases_per_tool(mut self, cases_per_tool: usize) -> Self {
        self.cases_per_tool = cases_per_tool.max(1);
        self
    }

    /// Sets the run configuration used for validation.
    pub fn with_run_config(mut self, run: RunConfig) -> Self {
        self.run = run;
        self
    }

    /// Adds a response validator ahead of the defaults.
    pub fn with_validator(mut self, validator: ToolValidationFn) -> Self {
        self.validators.insert(0, validator);
        self
    }
}

impl Default for ToolValidationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of a bulk validation run.
#[derive(Clone, Debug)]
pub struct BulkToolValidationSummary {
    /// Tool names that were validated.
    pub tools: Vec<String>,
    /// Number of cases exercised per tool.
    pub cases_per_tool: usize,
}

/// Failure details for a tool validation run.
#[derive(Clone, Debug)]
pub struct ToolValidationFailure {
    /// The tool that failed validation.
    pub tool: String,
    /// Failure reason.
    pub failure: RunFailure,
    /// Trace entries for the minimized failing case.
    pub trace: Vec<TraceEntry>,
}

/// Errors emitted while validating tools.
#[derive(Debug)]
pub enum ToolValidationError {
    /// Failed to communicate with the MCP endpoint.
    Session(SessionError),
    /// No tools are available for validation.
    NoToolsAvailable,
    /// Requested tool names were not found.
    MissingTools { tools: Vec<String> },
    /// Tool invocation generation failed.
    Generation { tool: String, reason: String },
    /// A tool validation failed.
    ValidationFailed(ToolValidationFailure),
}

impl fmt::Display for ToolValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToolValidationError::Session(error) => write!(f, "session error: {error:?}"),
            ToolValidationError::NoToolsAvailable => write!(f, "no tools available for validation"),
            ToolValidationError::MissingTools { tools } => {
                write!(f, "missing tools: {}", tools.join(", "))
            }
            ToolValidationError::Generation { tool, reason } => {
                write!(f, "failed to generate invocation for '{tool}': {reason}")
            }
            ToolValidationError::ValidationFailed(failure) => write!(
                f,
                "tool '{}' failed validation: {}",
                failure.tool, failure.failure.reason
            ),
        }
    }
}

impl std::error::Error for ToolValidationError {}

impl From<SessionError> for ToolValidationError {
    fn from(error: SessionError) -> Self {
        ToolValidationError::Session(error)
    }
}

/// Lists tools from an HTTP MCP endpoint using the provided configuration.
pub async fn list_tools_http(config: &HttpConfig) -> Result<Vec<Tool>, SessionError> {
    list_tools_with_connector(config.clone(), |config| async move {
        SessionDriver::connect_http(&config).await
    })
    .await
}

/// Lists tools from a stdio MCP endpoint using the provided configuration.
pub async fn list_tools_stdio(config: &StdioConfig) -> Result<Vec<Tool>, SessionError> {
    list_tools_with_connector(config.clone(), |config| async move {
        SessionDriver::connect_stdio(&config).await
    })
    .await
}

async fn list_tools_session(session: &SessionDriver) -> Result<Vec<Tool>, SessionError> {
    session.list_tools().await
}

async fn list_tools_with_connector<T, F, Fut>(
    config: T,
    connector: F,
) -> Result<Vec<Tool>, SessionError>
where
    F: FnOnce(T) -> Fut,
    Fut: Future<Output = Result<SessionDriver, SessionError>>,
{
    let session = connector(config).await?;
    list_tools_session(&session).await
}

/// Validates tools by name, or all tools when no name list is provided.
pub async fn validate_tools(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool_names: Option<&[String]>,
) -> Result<BulkToolValidationSummary, ToolValidationError> {
    let tools = session.list_tools().await?;
    if tools.is_empty() {
        return Err(ToolValidationError::NoToolsAvailable);
    }

    let tools = select_tools(tools, tool_names)?;
    for tool in &tools {
        run_tool_cases(session, config, tool).await?;
    }

    Ok(BulkToolValidationSummary {
        tools: tools.iter().map(|tool| tool.name.to_string()).collect(),
        cases_per_tool: config.cases_per_tool.max(1),
    })
}

/// Validates a single tool definition.
pub async fn validate_tool(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool: &Tool,
) -> Result<(), ToolValidationError> {
    run_tool_cases(session, config, tool).await
}

#[allow(clippy::result_large_err)]
fn select_tools(
    tools: Vec<Tool>,
    tool_names: Option<&[String]>,
) -> Result<Vec<Tool>, ToolValidationError> {
    let Some(tool_names) = tool_names else {
        return Ok(tools);
    };

    let tool_map: HashMap<String, Tool> = tools
        .into_iter()
        .map(|tool| (tool.name.to_string(), tool))
        .collect();

    let mut missing = Vec::new();
    let mut selected = Vec::new();
    for name in tool_names {
        if let Some(tool) = tool_map.get(name) {
            selected.push(tool.clone());
        } else {
            missing.push(name.clone());
        }
    }

    if !missing.is_empty() {
        return Err(ToolValidationError::MissingTools { tools: missing });
    }

    Ok(selected)
}

async fn run_tool_cases(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool: &Tool,
) -> Result<(), ToolValidationError> {
    let strategy = invocation_strategy(std::slice::from_ref(tool), config.run.predicate.as_ref())
        .map_err(|error| ToolValidationError::Generation {
        tool: tool.name.to_string(),
        reason: error.to_string(),
    })?;

    let cases = config.cases_per_tool.max(1);
    let mut runner = TestRunner::default();

    for _ in 0..cases {
        let tree =
            strategy
                .new_tree(&mut runner)
                .map_err(|reason| ToolValidationError::Generation {
                    tool: tool.name.to_string(),
                    reason: reason.to_string(),
                })?;

        if run_invocation(session, config, tool, tree.current())
            .await?
            .is_some()
        {
            let minimized = shrink_failure(session, config, tool, tree).await?;
            return Err(ToolValidationError::ValidationFailed(minimized));
        }
    }

    Ok(())
}

async fn run_invocation(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool: &Tool,
    invocation: crate::ToolInvocation,
) -> Result<Option<ToolValidationFailure>, ToolValidationError> {
    let trace = session.send_tool_call(invocation).await?;
    if let Err(failure) = apply_validators(config, tool, &trace) {
        return Ok(Some(ToolValidationFailure {
            tool: tool.name.to_string(),
            failure,
            trace: vec![trace],
        }));
    }
    Ok(None)
}

async fn shrink_failure<T>(
    session: &SessionDriver,
    config: &ToolValidationConfig,
    tool: &Tool,
    mut tree: T,
) -> Result<ToolValidationFailure, ToolValidationError>
where
    T: ValueTree<Value = crate::ToolInvocation>,
{
    let Some(mut best) = run_invocation(session, config, tool, tree.current()).await? else {
        return Err(ToolValidationError::Generation {
            tool: tool.name.to_string(),
            reason: "expected failing case to shrink".to_string(),
        });
    };

    loop {
        if !tree.simplify() {
            break;
        }

        match run_invocation(session, config, tool, tree.current()).await? {
            Some(failure) => {
                best = failure;
                continue;
            }
            None => {
                let mut restored = false;
                while tree.complicate() {
                    if let Some(failure) =
                        run_invocation(session, config, tool, tree.current()).await?
                    {
                        best = failure;
                        restored = true;
                        break;
                    }
                }
                if !restored {
                    break;
                }
            }
        }
    }

    Ok(best)
}

fn apply_validators(
    config: &ToolValidationConfig,
    tool: &Tool,
    trace: &TraceEntry,
) -> Result<(), RunFailure> {
    for validator in &config.validators {
        match validator(tool, trace) {
            ToolValidationDecision::Accept => return Ok(()),
            ToolValidationDecision::Reject(failure) => return Err(failure),
            ToolValidationDecision::Defer => continue,
        }
    }
    Ok(())
}

fn default_validators() -> Vec<ToolValidationFn> {
    vec![
        Arc::new(output_schema_validator),
        Arc::new(default_validator),
    ]
}

fn output_schema_validator(tool: &Tool, trace: &TraceEntry) -> ToolValidationDecision {
    let Some(schema) = &tool.output_schema else {
        return ToolValidationDecision::Defer;
    };
    if trace.response.is_error == Some(true) {
        return ToolValidationDecision::Defer;
    }
    let Some(structured) = &trace.response.structured_content else {
        return ToolValidationDecision::Reject(RunFailure::new(format!(
            "tool '{}' returned no structured_content for output schema",
            tool.name
        )));
    };
    let violations = schema_violations(schema.as_ref(), structured);
    if violations.is_empty() {
        ToolValidationDecision::Defer
    } else {
        ToolValidationDecision::Reject(RunFailure::new(format!(
            "tool '{}' output schema violations: {violations:?}",
            tool.name
        )))
    }
}

fn default_validator(_tool: &Tool, trace: &TraceEntry) -> ToolValidationDecision {
    if trace.response.is_error == Some(true) {
        return ToolValidationDecision::Reject(RunFailure::new("tool returned error".to_string()));
    }
    ToolValidationDecision::Defer
}

fn default_cases_per_tool() -> usize {
    match env::var(CASES_PER_TOOL_ENV) {
        Ok(value) => value
            .parse::<usize>()
            .ok()
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_CASES_PER_TOOL),
        Err(_) => DEFAULT_CASES_PER_TOOL,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex, OnceLock};

    use proptest::prelude::*;
    use proptest::strategy::NewTree;
    use rmcp::model::{
        CallToolResult, ClientJsonRpcMessage, ClientNotification, ClientRequest, Content,
        InitializeRequest, InitializeRequestParam, InitializedNotification, JsonRpcMessage,
        JsonRpcNotification, JsonRpcResponse, JsonRpcVersion2_0, ListPromptsRequest,
        ListToolsRequest, NumberOrString, PaginatedRequestParam, ServerJsonRpcMessage,
        ServerResult, Tool,
    };
    use rmcp::service::ServiceError;
    use rmcp::transport::Transport;
    use serde_json::json;
    use tokio::sync::mpsc;
    use tokio::sync::Mutex as AsyncMutex;

    use super::*;
    use tooltest_test_support::{
        call_tool_response, init_response, list_tools_response, stub_tool, ListToolsTransport,
    };

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    fn is_session_transport(error: &SessionError) -> bool {
        matches!(error, SessionError::Transport(_))
    }

    fn is_tool_validation_no_tools(error: &ToolValidationError) -> bool {
        matches!(error, ToolValidationError::NoToolsAvailable)
    }

    fn is_tool_validation_session(error: &ToolValidationError) -> bool {
        matches!(error, ToolValidationError::Session(_))
    }

    fn is_tool_validation_missing_tools(error: &ToolValidationError) -> bool {
        matches!(error, ToolValidationError::MissingTools { .. })
    }

    fn is_tool_validation_generation(error: &ToolValidationError) -> bool {
        matches!(error, ToolValidationError::Generation { .. })
    }

    fn is_tool_validation_failed(error: &ToolValidationError) -> bool {
        matches!(error, ToolValidationError::ValidationFailed(_))
    }

    fn is_accept(decision: &ToolValidationDecision) -> bool {
        matches!(decision, ToolValidationDecision::Accept)
    }

    fn is_defer(decision: &ToolValidationDecision) -> bool {
        matches!(decision, ToolValidationDecision::Defer)
    }

    fn is_reject(decision: &ToolValidationDecision) -> bool {
        matches!(decision, ToolValidationDecision::Reject(_))
    }

    fn is_initialize_response(message: &ServerJsonRpcMessage) -> bool {
        matches!(
            message,
            ServerJsonRpcMessage::Response(JsonRpcResponse {
                result: ServerResult::InitializeResult(_),
                ..
            })
        )
    }

    fn is_list_tools_response(message: &ServerJsonRpcMessage) -> bool {
        matches!(
            message,
            ServerJsonRpcMessage::Response(JsonRpcResponse {
                result: ServerResult::ListToolsResult(_),
                ..
            })
        )
    }

    fn missing_tools_list(error: &ToolValidationError) -> Option<Vec<String>> {
        match error {
            ToolValidationError::MissingTools { tools } => Some(tools.clone()),
            _ => None,
        }
    }

    fn sample_service_error() -> SessionError {
        SessionError::Service(Box::new(ServiceError::TransportClosed))
    }

    enum ConnectorOutcome {
        Ok(TestTransport),
        Err,
    }

    fn test_connector(
        outcome: ConnectorOutcome,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SessionDriver, SessionError>> + Send>,
    > {
        Box::pin(async move {
            match outcome {
                ConnectorOutcome::Ok(transport) => {
                    SessionDriver::connect_with_transport(transport).await
                }
                ConnectorOutcome::Err => Err(SessionError::Transport(Box::new(
                    std::io::Error::other("connector"),
                ))),
            }
        })
    }

    async fn http_test_connector(config: HttpConfig) -> Result<SessionDriver, SessionError> {
        if config.url == "fail" {
            Err(SessionError::from(std::io::Error::other("connector")))
        } else {
            let transport = TestTransport::new(vec![test_tool("echo")], []);
            SessionDriver::connect_with_transport(transport).await
        }
    }

    async fn stdio_test_connector(config: StdioConfig) -> Result<SessionDriver, SessionError> {
        if config.command == "fail" {
            Err(SessionError::from(std::io::Error::other("connector")))
        } else {
            let transport = TestTransport::new(vec![test_tool("echo")], []);
            SessionDriver::connect_with_transport(transport).await
        }
    }

    pub(super) struct TestTransport {
        tools: Vec<Tool>,
        error_tools: HashSet<String>,
        responses: Arc<AsyncMutex<mpsc::UnboundedReceiver<ServerJsonRpcMessage>>>,
        response_tx: mpsc::UnboundedSender<ServerJsonRpcMessage>,
    }

    #[derive(Debug)]
    struct TransportError(&'static str);

    impl std::fmt::Display for TransportError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl std::error::Error for TransportError {}

    struct FaultyTransport {
        tools: Vec<Tool>,
        fail_on_list: bool,
        call_fail_after: Option<usize>,
        call_count: usize,
        responses: Arc<AsyncMutex<mpsc::UnboundedReceiver<ServerJsonRpcMessage>>>,
        response_tx: mpsc::UnboundedSender<ServerJsonRpcMessage>,
    }

    impl FaultyTransport {
        fn new(tools: Vec<Tool>, fail_on_list: bool, call_fail_after: Option<usize>) -> Self {
            let (response_tx, response_rx) = mpsc::unbounded_channel();
            Self {
                tools,
                fail_on_list,
                call_fail_after,
                call_count: 0,
                responses: Arc::new(AsyncMutex::new(response_rx)),
                response_tx,
            }
        }
    }

    impl TestTransport {
        pub(super) fn new(tools: Vec<Tool>, error_tools: impl IntoIterator<Item = String>) -> Self {
            let (response_tx, response_rx) = mpsc::unbounded_channel();
            Self {
                tools,
                error_tools: error_tools.into_iter().collect(),
                responses: Arc::new(AsyncMutex::new(response_rx)),
                response_tx,
            }
        }
    }

    impl Transport<rmcp::service::RoleClient> for TestTransport {
        type Error = std::convert::Infallible;

        fn send(
            &mut self,
            item: ClientJsonRpcMessage,
        ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
            let response_tx = self.response_tx.clone();
            let tools = self.tools.clone();
            let error_tools = self.error_tools.clone();
            if let JsonRpcMessage::Request(request) = &item {
                let response = match &request.request {
                    ClientRequest::InitializeRequest(_) => Some(init_response(request.id.clone())),
                    ClientRequest::ListToolsRequest(_) => {
                        Some(list_tools_response(request.id.clone(), tools.clone()))
                    }
                    ClientRequest::CallToolRequest(call_request) => {
                        let tool_name = call_request.params.name.as_ref();
                        let result = if error_tools.contains(tool_name) {
                            CallToolResult::error(vec![Content::text("error")])
                        } else {
                            CallToolResult::success(vec![Content::text("ok")])
                        };
                        Some(call_tool_response(request.id.clone(), result))
                    }
                    _ => None,
                };
                if let Some(response) = response {
                    let _ = response_tx.send(response);
                }
            }
            std::future::ready(Ok(()))
        }

        fn receive(&mut self) -> impl std::future::Future<Output = Option<ServerJsonRpcMessage>> {
            let responses = Arc::clone(&self.responses);
            async move {
                let mut receiver = responses.lock().await;
                receiver.recv().await
            }
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl Transport<rmcp::service::RoleClient> for FaultyTransport {
        type Error = TransportError;

        fn send(
            &mut self,
            item: ClientJsonRpcMessage,
        ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
            let response_tx = self.response_tx.clone();
            let tools = self.tools.clone();
            let fail_on_list = self.fail_on_list;
            let call_fail_after = self.call_fail_after;
            let call_count = &mut self.call_count;
            if let JsonRpcMessage::Request(request) = &item {
                match &request.request {
                    ClientRequest::InitializeRequest(_) => {
                        let _ = response_tx.send(init_response(request.id.clone()));
                    }
                    ClientRequest::ListToolsRequest(_) => {
                        if fail_on_list {
                            return std::future::ready(Err(TransportError("list tools")));
                        }
                        let _ = response_tx
                            .send(list_tools_response(request.id.clone(), tools.clone()));
                    }
                    ClientRequest::CallToolRequest(_) => {
                        if let Some(fail_after) = call_fail_after {
                            if *call_count >= fail_after {
                                return std::future::ready(Err(TransportError("call tool")));
                            }
                        }
                        *call_count += 1;
                        let result = CallToolResult::success(vec![Content::text("ok")]);
                        let _ = response_tx.send(call_tool_response(request.id.clone(), result));
                    }
                    _ => {}
                }
            }
            std::future::ready(Ok(()))
        }

        fn receive(&mut self) -> impl std::future::Future<Output = Option<ServerJsonRpcMessage>> {
            let responses = Arc::clone(&self.responses);
            async move {
                let mut receiver = responses.lock().await;
                receiver.recv().await
            }
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn tool_validation_config_builders_set_fields() {
        let _guard = env_lock();
        env::remove_var(CASES_PER_TOOL_ENV);

        let _default = ToolValidationConfig::default();
        let predicate: crate::ToolPredicate = Arc::new(|_, _| true);
        let run = RunConfig::new().with_predicate(predicate);
        let validator: ToolValidationFn = Arc::new(|_, _| ToolValidationDecision::Accept);

        let config = ToolValidationConfig::new()
            .with_cases_per_tool(0)
            .with_run_config(run)
            .with_validator(validator.clone());

        assert_eq!(config.cases_per_tool, 1);
        assert!(config.run.predicate.is_some());
        assert_eq!(config.validators.len(), 3);
        assert!(Arc::ptr_eq(&config.validators[0], &validator));

        let trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "noop".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::success(vec![Content::text("ok")]),
        };
        let tool = test_tool("noop");
        let decision = (config.validators[0])(&tool, &trace);
        assert!(is_accept(&decision));
    }

    #[test]
    fn tool_validation_config_reads_env_override() {
        let _guard = env_lock();
        env::set_var(CASES_PER_TOOL_ENV, "123");
        let config = ToolValidationConfig::new();
        env::remove_var(CASES_PER_TOOL_ENV);

        assert_eq!(config.cases_per_tool, 123);
    }

    #[test]
    fn tool_validation_error_displays_variants() {
        let error = ToolValidationError::NoToolsAvailable;
        assert!(error.to_string().contains("no tools"));

        let error = ToolValidationError::MissingTools {
            tools: vec!["missing".to_string()],
        };
        assert!(error.to_string().contains("missing"));

        let error = ToolValidationError::Generation {
            tool: "tool".to_string(),
            reason: "bad".to_string(),
        };
        assert!(error.to_string().contains("failed to generate"));

        let error = ToolValidationError::ValidationFailed(ToolValidationFailure {
            tool: "tool".to_string(),
            failure: RunFailure::new("nope".to_string()),
            trace: Vec::new(),
        });
        assert!(error.to_string().contains("failed validation"));

        let error = ToolValidationError::from(SessionError::Transport(Box::new(
            std::io::Error::other("transport"),
        )));
        assert!(error.to_string().contains("session error"));
    }

    #[test]
    fn decision_helpers_cover_true_and_false() {
        let accept = ToolValidationDecision::Accept;
        let defer = ToolValidationDecision::Defer;
        let reject = ToolValidationDecision::Reject(RunFailure::new("nope".to_string()));

        assert!(is_accept(&accept));
        assert!(!is_accept(&defer));

        assert!(is_defer(&defer));
        assert!(!is_defer(&accept));

        assert!(is_reject(&reject));
        assert!(!is_reject(&accept));
    }

    #[tokio::test]
    async fn list_tools_helpers_report_errors_in_tests() {
        let http = HttpConfig {
            url: "http://127.0.0.1:0/mcp".to_string(),
            auth_token: None,
        };
        let _error = list_tools_http(&http).await.expect_err("http error");

        let stdio = StdioConfig::new("fail");
        let error = list_tools_stdio(&stdio).await.expect_err("stdio error");
        assert!(is_session_transport(&error));
    }

    #[tokio::test]
    async fn list_tools_stub_ignores_other_requests() {
        let mut transport = ListToolsTransport::new(vec![stub_tool("echo")]);
        let request = ClientJsonRpcMessage::request(
            ClientRequest::ListPromptsRequest(ListPromptsRequest {
                method: Default::default(),
                params: Some(PaginatedRequestParam { cursor: None }),
                extensions: Default::default(),
            }),
            NumberOrString::Number(10),
        );
        let _ = transport.send(request).await;

        let notification = ClientJsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: JsonRpcVersion2_0,
            notification: ClientNotification::InitializedNotification(
                InitializedNotification::default(),
            ),
        });
        let _ = transport.send(notification).await;
    }

    #[tokio::test]
    async fn list_tools_stub_handles_initialize_and_list_tools() {
        let tools = vec![stub_tool("echo")];
        let mut transport = ListToolsTransport::new(tools.clone());

        let init = ClientJsonRpcMessage::request(
            ClientRequest::InitializeRequest(InitializeRequest::new(
                InitializeRequestParam::default(),
            )),
            NumberOrString::Number(1),
        );
        let _ = transport.send(init).await;
        let response = transport.receive().await.expect("init response");
        assert!(is_initialize_response(&response));
        assert!(!is_list_tools_response(&response));

        let list = ClientJsonRpcMessage::request(
            ClientRequest::ListToolsRequest(ListToolsRequest {
                method: Default::default(),
                params: Some(PaginatedRequestParam { cursor: None }),
                extensions: Default::default(),
            }),
            NumberOrString::Number(2),
        );
        let _ = transport.send(list).await;
        let response = transport.receive().await.expect("list response");
        assert!(is_list_tools_response(&response));
        assert!(!is_initialize_response(&response));
        transport.close().await.expect("close");
    }

    #[test]
    fn apply_validators_accepts_first_validator() {
        let validator: ToolValidationFn = Arc::new(|_, _| ToolValidationDecision::Accept);
        let config = ToolValidationConfig {
            run: RunConfig::new(),
            cases_per_tool: 1,
            validators: vec![validator],
        };
        let trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "noop".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::success(vec![Content::text("ok")]),
        };
        let tool = test_tool("noop");

        assert!(apply_validators(&config, &tool, &trace).is_ok());
    }

    #[test]
    fn apply_validators_rejects_validator() {
        let validator: ToolValidationFn =
            Arc::new(|_, _| ToolValidationDecision::Reject(RunFailure::new("nope".to_string())));
        let config = ToolValidationConfig {
            run: RunConfig::new(),
            cases_per_tool: 1,
            validators: vec![validator],
        };
        let trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "noop".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::success(vec![Content::text("ok")]),
        };
        let tool = test_tool("noop");

        let error = apply_validators(&config, &tool, &trace).expect_err("reject");
        assert_eq!(error.reason, "nope");
    }

    #[test]
    fn output_schema_validator_defers_on_error_response() {
        let tool = tool_with_output_schema("noop", json!({ "type": "object" }));
        let trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "noop".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::error(vec![Content::text("error")]),
        };

        let decision = output_schema_validator(&tool, &trace);
        assert!(is_defer(&decision));
    }

    #[test]
    fn output_schema_validator_defers_without_schema() {
        let tool = test_tool("noop");
        let trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "noop".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::structured(json!({})),
        };

        let decision = output_schema_validator(&tool, &trace);
        assert!(is_defer(&decision));
    }

    #[test]
    fn output_schema_validator_rejects_missing_structured_content() {
        let tool = tool_with_output_schema("noop", json!({ "type": "object" }));
        let trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "noop".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::success(vec![Content::text("ok")]),
        };

        let decision = output_schema_validator(&tool, &trace);
        assert!(is_reject(&decision));
    }

    #[test]
    fn output_schema_validator_defers_on_matching_structured_content() {
        let tool = tool_with_output_schema(
            "noop",
            json!({
                "type": "object",
                "properties": { "value": { "type": "string" } }
            }),
        );
        let trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "noop".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::structured(json!({ "value": "ok" })),
        };

        let decision = output_schema_validator(&tool, &trace);
        assert!(is_defer(&decision));
    }

    #[test]
    fn output_schema_validator_rejects_schema_violations() {
        let tool = tool_with_output_schema(
            "noop",
            json!({
                "type": "object",
                "required": ["value"],
                "properties": { "value": { "type": "string" } }
            }),
        );
        let trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "noop".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::structured(json!({})),
        };

        let decision = output_schema_validator(&tool, &trace);
        assert!(is_reject(&decision));
    }

    #[test]
    fn default_validator_rejects_error_response() {
        let tool = test_tool("noop");
        let trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "noop".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::error(vec![Content::text("error")]),
        };

        let decision = default_validator(&tool, &trace);
        assert!(is_reject(&decision));
    }

    #[tokio::test]
    async fn list_tools_session_uses_driver() {
        let tool = test_tool("echo");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");

        let tools = list_tools_session(&driver).await.expect("tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name.as_ref(), "echo");
    }

    #[tokio::test]
    async fn list_tools_with_connector_uses_session() {
        let transport = TestTransport::new(vec![test_tool("echo")], []);
        let tools = list_tools_with_connector(ConnectorOutcome::Ok(transport), test_connector)
            .await
            .expect("tools");
        assert_eq!(tools.len(), 1);
    }

    #[tokio::test]
    async fn list_tools_with_connector_accepts_http_config() {
        let ok_config = HttpConfig {
            url: "http://localhost:8080/mcp".to_string(),
            auth_token: None,
        };

        let tools = list_tools_with_connector(ok_config, http_test_connector)
            .await
            .expect("tools");
        assert_eq!(tools.len(), 1);

        let error_config = HttpConfig {
            url: "fail".to_string(),
            auth_token: None,
        };
        let error = list_tools_with_connector(error_config, http_test_connector)
            .await
            .expect_err("error");
        assert!(is_session_transport(&error));
    }

    #[tokio::test]
    async fn list_tools_with_connector_accepts_stdio_config() {
        let ok_config = StdioConfig::new("mcp-server");

        let tools = list_tools_with_connector(ok_config, stdio_test_connector)
            .await
            .expect("tools");
        assert_eq!(tools.len(), 1);

        let error_config = StdioConfig::new("fail");
        let error = list_tools_with_connector(error_config, stdio_test_connector)
            .await
            .expect_err("error");
        assert!(is_session_transport(&error));
    }

    #[tokio::test]
    async fn list_tools_with_connector_reports_error() {
        let error = list_tools_with_connector(ConnectorOutcome::Err, test_connector)
            .await
            .expect_err("error");
        assert!(is_session_transport(&error));
    }

    #[tokio::test]
    async fn validate_tool_runs_cases() {
        let transport = TestTransport::new(vec![test_tool("echo")], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let config = ToolValidationConfig::new().with_cases_per_tool(1);
        let tool = test_tool("echo");

        validate_tool(&driver, &config, &tool)
            .await
            .expect("validate tool");
    }

    #[cfg(coverage)]
    #[tokio::test]
    async fn list_tools_http_reports_error_for_unreachable_endpoint() {
        let http = HttpConfig {
            url: "http://127.0.0.1:0/mcp".to_string(),
            auth_token: None,
        };

        assert!(list_tools_http(&http).await.is_err());
    }

    #[cfg(coverage)]
    #[tokio::test]
    async fn list_tools_stdio_reports_error_in_coverage() {
        let stdio = StdioConfig::new("mcp-server");
        assert!(list_tools_stdio(&stdio).await.is_err());
    }

    #[tokio::test]
    async fn validate_tools_reports_no_tools() {
        let transport = TestTransport::new(Vec::new(), []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let config = ToolValidationConfig::new().with_cases_per_tool(1);

        let error = validate_tools(&driver, &config, None)
            .await
            .expect_err("no tools");
        assert!(is_tool_validation_no_tools(&error));
    }

    #[tokio::test]
    async fn validate_tools_reports_list_tools_error() {
        let transport = FaultyTransport::new(vec![test_tool("echo")], true, None);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let config = ToolValidationConfig::new().with_cases_per_tool(1);

        let error = validate_tools(&driver, &config, None)
            .await
            .expect_err("list tools error");
        assert!(is_tool_validation_session(&error));
    }

    #[tokio::test]
    async fn validate_tools_selects_requested_names() {
        let tools = vec![test_tool("alpha"), test_tool("beta")];
        let transport = TestTransport::new(tools, []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let config = ToolValidationConfig::new().with_cases_per_tool(1);
        let tool_names = vec!["beta".to_string()];

        let summary = validate_tools(&driver, &config, Some(&tool_names))
            .await
            .expect("summary");

        assert_eq!(summary.tools, tool_names);
    }

    #[tokio::test]
    async fn validate_tools_reports_missing_names() {
        let tools = vec![test_tool("alpha")];
        let transport = TestTransport::new(tools, []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let config = ToolValidationConfig::new().with_cases_per_tool(1);
        let missing = vec!["missing".to_string()];

        let error = validate_tools(&driver, &config, Some(&missing))
            .await
            .expect_err("missing");
        assert!(is_tool_validation_missing_tools(&error));
    }

    #[tokio::test]
    async fn validate_tools_reports_generation_error() {
        let tool = Tool::new(
            "bad".to_string(),
            "bad tool",
            json!({ "type": "string" }).as_object().cloned().unwrap(),
        );
        let transport = TestTransport::new(vec![tool], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let config = ToolValidationConfig::new().with_cases_per_tool(1);

        let error = validate_tools(&driver, &config, None)
            .await
            .expect_err("generation error");
        assert!(is_tool_validation_generation(&error));
    }

    #[tokio::test]
    async fn validate_tools_reports_generation_error_on_rejection() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        let predicate: crate::ToolPredicate = Arc::new(move |_, _| {
            let seen = counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            seen == 0
        });

        let run = RunConfig::new().with_predicate(predicate);
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_run_config(run);
        let transport = TestTransport::new(vec![test_tool("echo")], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");

        let error = validate_tools(&driver, &config, None)
            .await
            .expect_err("generation error");
        assert!(is_tool_validation_generation(&error));
    }

    #[tokio::test]
    async fn validate_tools_reports_call_error() {
        let transport = FaultyTransport::new(vec![test_tool("echo")], false, Some(0));
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let config = ToolValidationConfig::new().with_cases_per_tool(1);

        let error = validate_tools(&driver, &config, None)
            .await
            .expect_err("call error");
        assert!(is_tool_validation_session(&error));
    }

    #[tokio::test]
    async fn run_tool_cases_reports_validation_failure() {
        let transport = TestTransport::new(vec![test_tool("echo")], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn =
            Arc::new(|_, _| ToolValidationDecision::Reject(RunFailure::new("always".to_string())));
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);
        let tool = test_tool("echo");

        let error = run_tool_cases(&driver, &config, &tool)
            .await
            .expect_err("validation failed");
        assert!(is_tool_validation_failed(&error));
    }

    #[tokio::test]
    async fn validate_tools_reports_shrink_failure_error() {
        let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_clone = Arc::clone(&seen);
        let validator: ToolValidationFn = Arc::new(move |_, _| {
            if seen_clone.swap(true, std::sync::atomic::Ordering::SeqCst) {
                ToolValidationDecision::Defer
            } else {
                ToolValidationDecision::Reject(RunFailure::new("first".to_string()))
            }
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);
        let transport = TestTransport::new(vec![test_tool("echo")], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");

        let error = validate_tools(&driver, &config, None)
            .await
            .expect_err("shrink failure");
        assert!(is_tool_validation_generation(&error));
    }

    #[tokio::test]
    async fn shrink_failure_reports_error_without_failure() {
        let tool = test_tool("echo");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");

        let config = ToolValidationConfig::new().with_cases_per_tool(1);
        let strategy = tool_invocation_strategy("echo");
        let mut runner = TestRunner::default();
        let tree = strategy.new_tree(&mut runner).unwrap();

        let error = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect_err("expected shrink error");
        assert!(is_tool_validation_generation(&error));
    }

    #[tokio::test]
    async fn shrink_failure_breaks_when_simplified_case_passes() {
        let tool = test_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn = Arc::new(|_, trace| {
            let value = trace
                .invocation
                .arguments
                .as_ref()
                .and_then(|args| args.get("value"))
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            if value == 0 {
                ToolValidationDecision::Defer
            } else {
                ToolValidationDecision::Reject(RunFailure::new("non-zero".to_string()))
            }
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);

        let tree = SequenceTree::new(
            invocation_with_value("num", 1),
            Some(invocation_with_value("num", 0)),
            Vec::new(),
        );

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "non-zero");
    }

    #[tokio::test]
    async fn shrink_failure_reports_generation_error_for_sequence_tree() {
        let tool = test_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn = Arc::new(|_, _| ToolValidationDecision::Defer);
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);

        let tree = SequenceTree::new(invocation_with_value("num", 0), None, Vec::new());

        let error = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect_err("expected shrink error");
        assert!(is_tool_validation_generation(&error));
    }

    #[tokio::test]
    async fn shrink_failure_sequence_tree_handles_failure_after_simplify() {
        let tool = test_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn = Arc::new(|_, _| {
            ToolValidationDecision::Reject(RunFailure::new("non-zero".to_string()))
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);

        let tree = SequenceTree::new(
            invocation_with_value("num", 1),
            Some(invocation_with_value("num", 2)),
            Vec::new(),
        );

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "non-zero");
    }

    #[tokio::test]
    async fn shrink_failure_breaks_when_complicate_cases_pass_for_sequence_tree() {
        let tool = test_value_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn = Arc::new(|_, trace| {
            let value = trace
                .invocation
                .arguments
                .as_ref()
                .and_then(|args| args.get("value"))
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            if value == 1 {
                ToolValidationDecision::Reject(RunFailure::new("non-zero".to_string()))
            } else {
                ToolValidationDecision::Defer
            }
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);

        let tree = SequenceTree::new(
            invocation_with_value("num", 1),
            Some(invocation_with_value("num", 0)),
            vec![invocation_with_value("num", 0)],
        );

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "non-zero");
    }

    #[tokio::test]
    async fn shrink_failure_handles_failure_for_boxed_tree() {
        let tool = test_value_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn =
            Arc::new(|_, _| ToolValidationDecision::Reject(RunFailure::new("always".to_string())));
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);
        let strategy = SequenceStrategy::new(
            invocation_with_value("num", 1),
            Some(invocation_with_value("num", 2)),
            Vec::new(),
        )
        .boxed();

        let mut runner = TestRunner::default();
        let tree = strategy.new_tree(&mut runner).expect("tree");

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "always");
    }

    #[tokio::test]
    async fn shrink_failure_breaks_when_complicate_cases_pass_for_boxed_tree() {
        let tool = test_value_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn = Arc::new(|_, trace| {
            let value = trace
                .invocation
                .arguments
                .as_ref()
                .and_then(|args| args.get("value"))
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            if value == 1 {
                ToolValidationDecision::Reject(RunFailure::new("non-zero".to_string()))
            } else {
                ToolValidationDecision::Defer
            }
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);
        let strategy = SequenceStrategy::new(
            invocation_with_value("num", 1),
            Some(invocation_with_value("num", 0)),
            vec![invocation_with_value("num", 0)],
        )
        .boxed();

        let mut runner = TestRunner::default();
        let tree = strategy.new_tree(&mut runner).expect("tree");

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "non-zero");
    }

    #[tokio::test]
    async fn shrink_failure_handles_restore_for_boxed_tree() {
        let tool = test_value_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let outcomes = Arc::new(Mutex::new(vec![
            Err(RunFailure::new("first".to_string())),
            Ok(()),
            Err(RunFailure::new("restored".to_string())),
        ]));
        let outcomes_clone = Arc::clone(&outcomes);
        let validator: ToolValidationFn = Arc::new(move |_, _| {
            outcomes_clone
                .lock()
                .expect("outcomes")
                .pop()
                .unwrap_or(Ok(()))
                .map_or_else(ToolValidationDecision::Reject, |_| {
                    ToolValidationDecision::Defer
                })
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);
        let strategy = SequenceStrategy::new(
            invocation_with_value("num", 1),
            Some(invocation_with_value("num", 0)),
            vec![invocation_with_value("num", 2)],
        )
        .boxed();

        let mut runner = TestRunner::default();
        let tree = strategy.new_tree(&mut runner).expect("tree");

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "first");
    }

    #[tokio::test]
    async fn shrink_failure_restores_after_complicate_failure() {
        let tool = test_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn = Arc::new(|_, trace| {
            let value = trace
                .invocation
                .arguments
                .as_ref()
                .and_then(|args| args.get("value"))
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            if value == 0 {
                ToolValidationDecision::Defer
            } else {
                ToolValidationDecision::Reject(RunFailure::new("non-zero".to_string()))
            }
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);

        let tree = SequenceTree::new(
            invocation_with_value("num", 1),
            Some(invocation_with_value("num", 0)),
            vec![invocation_with_value("num", 2)],
        );

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "non-zero");
    }

    #[tokio::test]
    async fn shrink_failure_maintains_failure_when_always_invalid() {
        let tool = test_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn =
            Arc::new(|_, _| ToolValidationDecision::Reject(RunFailure::new("always".to_string())));
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);

        let strategy = tool_invocation_strategy("num");
        let mut runner = TestRunner::default();
        let tree = strategy.new_tree(&mut runner).unwrap();

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "always");
    }

    #[tokio::test]
    async fn shrink_failure_restores_after_passing_case() {
        let tool = test_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn = Arc::new(|_, trace| {
            let value = trace
                .invocation
                .arguments
                .as_ref()
                .and_then(|args| args.get("value"))
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            if value == 0 {
                ToolValidationDecision::Defer
            } else {
                ToolValidationDecision::Reject(RunFailure::new("non-zero".to_string()))
            }
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);
        let strategy = tool_invocation_strategy("num");
        let mut runner = TestRunner::default();
        let mut tree = strategy.new_tree(&mut runner).unwrap();
        let mut forced = false;

        for _ in 0..10 {
            let value = tree
                .current()
                .arguments
                .as_ref()
                .and_then(|args| args.get("value"))
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            if value != 0 && forced {
                break;
            }
            forced = true;
            tree = strategy.new_tree(&mut runner).unwrap();
        }

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "non-zero");
    }

    #[tokio::test]
    async fn shrink_failure_breaks_when_restore_missing() {
        let tool = test_tool("num");
        let transport = TestTransport::new(vec![tool.clone()], []);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");

        let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_clone = Arc::clone(&seen);
        let validator: ToolValidationFn = Arc::new(move |_, _| {
            if seen_clone.swap(true, std::sync::atomic::Ordering::SeqCst) {
                ToolValidationDecision::Defer
            } else {
                ToolValidationDecision::Reject(RunFailure::new("first".to_string()))
            }
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);

        let strategy = tool_invocation_strategy("num");
        let mut runner = TestRunner::default();
        let tree = strategy.new_tree(&mut runner).unwrap();

        let failure = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect("failure");
        assert_eq!(failure.failure.reason, "first");
    }

    #[tokio::test]
    async fn shrink_failure_reports_session_error_on_initial_call() {
        let tool = test_tool("num");
        let transport = FaultyTransport::new(vec![tool.clone()], false, Some(0));
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let config = ToolValidationConfig::new().with_cases_per_tool(1);

        let strategy = tool_invocation_strategy("num");
        let mut runner = TestRunner::default();
        let tree = strategy.new_tree(&mut runner).unwrap();

        let error = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect_err("session error");
        assert!(is_tool_validation_session(&error));
    }

    #[tokio::test]
    async fn shrink_failure_reports_session_error_in_loop() {
        let tool = test_tool("num");
        let transport = FaultyTransport::new(vec![tool.clone()], false, Some(1));
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let validator: ToolValidationFn =
            Arc::new(|_, _| ToolValidationDecision::Reject(RunFailure::new("always".to_string())));
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);

        let strategy = tool_invocation_strategy("num");
        let mut runner = TestRunner::default();
        let tree = strategy.new_tree(&mut runner).unwrap();

        let error = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect_err("session error");
        assert!(is_tool_validation_session(&error));
    }

    #[tokio::test]
    async fn shrink_failure_reports_session_error_in_complicate() {
        let tool = test_tool("num");
        let transport = FaultyTransport::new(vec![tool.clone()], false, Some(2));
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_clone = Arc::clone(&seen);
        let validator: ToolValidationFn = Arc::new(move |_, _| {
            if seen_clone.swap(true, std::sync::atomic::Ordering::SeqCst) {
                ToolValidationDecision::Defer
            } else {
                ToolValidationDecision::Reject(RunFailure::new("first".to_string()))
            }
        });
        let config = ToolValidationConfig::new()
            .with_cases_per_tool(1)
            .with_validator(validator);

        let strategy = tool_invocation_strategy("num");
        let mut runner = TestRunner::default();
        let tree = strategy.new_tree(&mut runner).unwrap();

        let error = shrink_failure(&driver, &config, &tool, tree)
            .await
            .expect_err("session error");
        assert!(is_tool_validation_session(&error));
    }

    #[tokio::test]
    async fn transport_handles_error_tools_and_close() {
        let transport = TestTransport::new(vec![test_tool("boom")], ["boom".to_string()]);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let invocation = crate::ToolInvocation {
            name: "boom".into(),
            arguments: Some(json!({}).as_object().cloned().unwrap()),
        };
        let trace = driver.send_tool_call(invocation).await.expect("trace");
        assert_eq!(trace.response.is_error, Some(true));
    }

    #[tokio::test]
    async fn transport_ignores_unhandled_request_and_closes() {
        let mut transport = TestTransport::new(vec![test_tool("echo")], []);
        let request = ClientJsonRpcMessage::request(
            ClientRequest::ListPromptsRequest(ListPromptsRequest {
                method: Default::default(),
                params: Some(PaginatedRequestParam { cursor: None }),
                extensions: Default::default(),
            }),
            NumberOrString::Number(7),
        );
        let _ = transport.send(request).await;
        transport.close().await.expect("close");
    }

    #[test]
    fn transport_error_formats_message() {
        let error = TransportError("boom");
        assert_eq!(error.to_string(), "boom");
    }

    #[test]
    fn match_helpers_cover_both_paths() {
        let transport_error = SessionError::Transport(Box::new(std::io::Error::other("oops")));
        let service_error = sample_service_error();
        assert!(is_session_transport(&transport_error));
        assert!(!is_session_transport(&service_error));

        let no_tools = ToolValidationError::NoToolsAvailable;
        let missing = ToolValidationError::MissingTools {
            tools: vec!["missing".to_string()],
        };
        assert!(is_tool_validation_no_tools(&no_tools));
        assert!(!is_tool_validation_no_tools(&missing));

        let session_error = ToolValidationError::Session(sample_service_error());
        let generation_error = ToolValidationError::Generation {
            tool: "tool".to_string(),
            reason: "bad".to_string(),
        };
        assert!(is_tool_validation_session(&session_error));
        assert!(!is_tool_validation_session(&generation_error));

        assert!(is_tool_validation_generation(&generation_error));
        assert!(!is_tool_validation_generation(&session_error));

        let missing_error = ToolValidationError::MissingTools {
            tools: vec!["missing".to_string()],
        };
        assert!(is_tool_validation_missing_tools(&missing_error));
        assert!(!is_tool_validation_missing_tools(&generation_error));
        assert_eq!(missing_tools_list(&generation_error), None);

        let failed_error = ToolValidationError::ValidationFailed(ToolValidationFailure {
            tool: "tool".to_string(),
            failure: RunFailure::new("nope".to_string()),
            trace: Vec::new(),
        });
        assert!(is_tool_validation_failed(&failed_error));
        assert!(!is_tool_validation_failed(&generation_error));
    }

    #[test]
    fn coverage_smoke_for_validation_helpers() {
        let _guard = env_lock();
        let tools = vec![test_tool("alpha"), test_tool("beta")];

        let all_tools = select_tools(tools.clone(), None).expect("all tools");
        assert_eq!(all_tools.len(), 2);

        let missing = vec!["missing".to_string()];
        let missing_error = select_tools(tools.clone(), Some(&missing)).expect_err("missing tools");
        assert!(is_tool_validation_missing_tools(&missing_error));
        assert_eq!(missing_tools_list(&missing_error), Some(missing.clone()));

        let selected = select_tools(tools, Some(&["beta".to_string()])).expect("selected tools");
        assert_eq!(selected.len(), 1);

        let ok_trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "ok".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::success(vec![Content::text("ok")]),
        };
        let tool = test_tool("ok");
        let ok_decision = default_validator(&tool, &ok_trace);
        assert!(is_defer(&ok_decision));

        let err_trace = TraceEntry {
            invocation: crate::ToolInvocation {
                name: "err".into(),
                arguments: Some(json!({}).as_object().cloned().unwrap()),
            },
            response: CallToolResult::error(vec![Content::text("bad")]),
        };
        let err_decision = default_validator(&tool, &err_trace);
        assert!(is_reject(&err_decision));

        env::set_var(CASES_PER_TOOL_ENV, "0");
        assert_eq!(default_cases_per_tool(), DEFAULT_CASES_PER_TOOL);

        env::set_var(CASES_PER_TOOL_ENV, "nope");
        assert_eq!(default_cases_per_tool(), DEFAULT_CASES_PER_TOOL);

        env::set_var(CASES_PER_TOOL_ENV, "7");
        assert_eq!(default_cases_per_tool(), 7);

        env::remove_var(CASES_PER_TOOL_ENV);
    }

    #[tokio::test]
    async fn faulty_transport_handles_unhandled_request_and_closes() {
        let mut transport = FaultyTransport::new(vec![test_tool("echo")], false, None);
        let request = ClientJsonRpcMessage::request(
            ClientRequest::ListPromptsRequest(ListPromptsRequest {
                method: Default::default(),
                params: Some(PaginatedRequestParam { cursor: None }),
                extensions: Default::default(),
            }),
            NumberOrString::Number(8),
        );
        let _ = transport.send(request).await;
        transport.close().await.expect("close");
    }

    #[tokio::test]
    async fn faulty_transport_allows_call_before_failure() {
        let transport = FaultyTransport::new(vec![test_tool("echo")], false, Some(2));
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let invocation = crate::ToolInvocation {
            name: "echo".into(),
            arguments: Some(json!({}).as_object().cloned().unwrap()),
        };
        let trace = driver.send_tool_call(invocation).await.expect("trace");
        assert_eq!(trace.response.is_error, Some(false));
    }

    #[tokio::test]
    async fn faulty_transport_allows_call_without_failure() {
        let transport = FaultyTransport::new(vec![test_tool("echo")], false, None);
        let driver = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");
        let invocation = crate::ToolInvocation {
            name: "echo".into(),
            arguments: Some(json!({}).as_object().cloned().unwrap()),
        };
        let trace = driver.send_tool_call(invocation).await.expect("trace");
        assert_eq!(trace.response.is_error, Some(false));
    }

    fn tool_with_output_schema(name: &str, output_schema: serde_json::Value) -> Tool {
        Tool {
            name: name.to_string().into(),
            title: None,
            description: None,
            input_schema: Arc::new(json!({ "type": "object" }).as_object().cloned().unwrap()),
            output_schema: Some(Arc::new(
                output_schema
                    .as_object()
                    .cloned()
                    .expect("output schema object"),
            )),
            annotations: None,
            icons: None,
            meta: None,
        }
    }

    pub(super) fn test_tool(name: &str) -> Tool {
        Tool::new(
            name.to_string(),
            "test tool",
            json!({ "type": "object" }).as_object().cloned().unwrap(),
        )
    }

    fn test_value_tool(name: &str) -> Tool {
        Tool::new(
            name.to_string(),
            "test tool",
            json!({
                "type": "object",
                "properties": {
                    "value": { "type": "integer" }
                },
                "required": ["value"]
            })
            .as_object()
            .cloned()
            .unwrap(),
        )
    }

    fn tool_invocation_strategy(name: &str) -> impl Strategy<Value = crate::ToolInvocation> {
        let name = name.to_string();
        any::<i64>().prop_map(move |value| crate::ToolInvocation {
            name: name.clone().into(),
            arguments: Some(json!({ "value": value }).as_object().cloned().unwrap()),
        })
    }

    fn invocation_with_value(name: &str, value: i64) -> crate::ToolInvocation {
        crate::ToolInvocation {
            name: name.to_string().into(),
            arguments: Some(json!({ "value": value }).as_object().cloned().unwrap()),
        }
    }

    struct SequenceTree {
        current: crate::ToolInvocation,
        simplified: Option<crate::ToolInvocation>,
        complicate_steps: Vec<crate::ToolInvocation>,
        complicate_index: usize,
    }

    impl SequenceTree {
        fn new(
            current: crate::ToolInvocation,
            simplified: Option<crate::ToolInvocation>,
            complicate_steps: Vec<crate::ToolInvocation>,
        ) -> Self {
            Self {
                current,
                simplified,
                complicate_steps,
                complicate_index: 0,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct SequenceStrategy {
        current: crate::ToolInvocation,
        simplified: Option<crate::ToolInvocation>,
        complicate_steps: Vec<crate::ToolInvocation>,
    }

    impl SequenceStrategy {
        fn new(
            current: crate::ToolInvocation,
            simplified: Option<crate::ToolInvocation>,
            complicate_steps: Vec<crate::ToolInvocation>,
        ) -> Self {
            Self {
                current,
                simplified,
                complicate_steps,
            }
        }
    }

    impl Strategy for SequenceStrategy {
        type Tree = SequenceTree;
        type Value = crate::ToolInvocation;

        fn new_tree(&self, _: &mut TestRunner) -> NewTree<Self> {
            Ok(SequenceTree::new(
                self.current.clone(),
                self.simplified.clone(),
                self.complicate_steps.clone(),
            ))
        }
    }

    impl ValueTree for SequenceTree {
        type Value = crate::ToolInvocation;

        fn current(&self) -> Self::Value {
            self.current.clone()
        }

        fn simplify(&mut self) -> bool {
            if let Some(next) = self.simplified.take() {
                self.current = next;
                true
            } else {
                false
            }
        }

        fn complicate(&mut self) -> bool {
            if let Some(next) = self.complicate_steps.get(self.complicate_index) {
                self.current = next.clone();
                self.complicate_index += 1;
                true
            } else {
                false
            }
        }
    }
}
