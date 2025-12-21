use serde_json::{json, Value as JsonValue};

use rmcp::model::{ErrorData, JsonRpcRequest, JsonRpcVersion2_0, NumberOrString, Request};

use crate::{ToolInvocation, TraceEntry};

/// Transport abstraction for MCP request/response exchange.
pub trait Transport {
    /// Sends a JSON-RPC request and returns the raw JSON response.
    fn send(&mut self, request: JsonValue) -> Result<JsonValue, TransportError>;
}

/// Transport error category to aid recovery decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    /// Errors caused by IO, networking, or process failures.
    Io,
    /// Errors caused by protocol or framing mismatches.
    Protocol,
    /// Errors that do not fit a more specific category.
    Other,
}

/// Transport-level error surfaced by the session driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError {
    /// Human-readable error description.
    pub message: String,
    /// Classification for the underlying transport error.
    pub kind: TransportErrorKind,
    /// Optional source string for debugging.
    pub source: Option<String>,
}

impl TransportError {
    /// Creates a new transport error from a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: TransportErrorKind::Other,
            source: None,
        }
    }

    /// Creates a new transport error with an explicit kind.
    pub fn with_kind(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind,
            source: None,
        }
    }

    /// Creates a new transport error with a source description.
    pub fn with_source(
        kind: TransportErrorKind,
        message: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            message: message.into(),
            kind,
            source: Some(source.into()),
        }
    }
}

/// Errors emitted by the session driver.
#[derive(Clone, Debug, PartialEq)]
pub enum SessionError {
    /// Transport-level failure.
    Transport(TransportError),
    /// Initialization failed with a reason.
    InitializationFailed { error: Box<ErrorData> },
    /// Tool call failed with a reason.
    ToolCallFailed { tool: String, error: Box<ErrorData> },
}

impl From<TransportError> for SessionError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// Stateful MCP session driver that enforces initialization ordering.
pub struct SessionDriver<T: Transport> {
    transport: T,
    initialized: bool,
    next_id: u64,
}

impl<T: Transport> SessionDriver<T> {
    /// Creates a new session driver for the provided transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            initialized: false,
            next_id: 1,
        }
    }

    /// Returns whether initialization has completed.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Resets initialization state and request id counter.
    pub fn reset(&mut self) {
        self.initialized = false;
        self.next_id = 1;
    }

    /// Performs MCP initialization with empty parameters.
    pub fn initialize(&mut self) -> Result<JsonValue, SessionError> {
        self.initialize_with_params(json!({}))
    }

    /// Performs MCP initialization with caller-supplied parameters.
    pub fn initialize_with_params(&mut self, params: JsonValue) -> Result<JsonValue, SessionError> {
        let response = self.send_request("initialize", params)?;
        if let Some(error) = extract_error(&response) {
            return Err(SessionError::InitializationFailed {
                error: Box::new(error),
            });
        }
        self.initialized = true;
        Ok(response)
    }

    /// Sends a tool invocation, ensuring initialization runs first.
    pub fn send_tool_call(
        &mut self,
        invocation: ToolInvocation,
    ) -> Result<TraceEntry, SessionError> {
        self.ensure_initialized()?;
        let tool_name = invocation.name.clone();
        let arguments = invocation.arguments.clone();
        let params = json!({
            "name": tool_name.clone(),
            "arguments": arguments,
        });
        let response = self.send_request("tools/call", params)?;
        if let Some(error) = extract_error(&response) {
            return Err(SessionError::ToolCallFailed {
                tool: tool_name,
                error: Box::new(error),
            });
        }
        Ok(TraceEntry {
            invocation,
            response,
        })
    }

    /// Drives a sequence of tool invocations, enforcing initialization ordering.
    pub fn run_invocations<I>(&mut self, invocations: I) -> Result<Vec<TraceEntry>, SessionError>
    where
        I: IntoIterator<Item = ToolInvocation>,
    {
        self.ensure_initialized()?;
        let mut trace = Vec::new();
        for invocation in invocations {
            trace.push(self.send_tool_call(invocation)?);
        }
        Ok(trace)
    }

    fn ensure_initialized(&mut self) -> Result<(), SessionError> {
        if !self.initialized {
            self.initialize()?;
        }
        Ok(())
    }

    fn send_request(&mut self, method: &str, params: JsonValue) -> Result<JsonValue, SessionError> {
        let request = Request {
            method: method.to_string(),
            params,
            extensions: Default::default(),
        };
        let id = i64::try_from(self.next_id).unwrap_or(i64::MAX);
        let request = JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: NumberOrString::Number(id),
            request,
        };
        let request = serde_json::to_value(request).expect("rmcp request should serialize");
        // Saturate instead of wrapping to avoid repeating request ids in long runs.
        self.next_id = self.next_id.saturating_add(1);
        self.transport.send(request).map_err(SessionError::from)
    }
}

fn extract_error(response: &JsonValue) -> Option<ErrorData> {
    response.get("error").map(|error| {
        serde_json::from_value(error.clone()).unwrap_or_else(|parse_error| {
            ErrorData::internal_error(
                "invalid error payload",
                Some(json!({
                    "raw": error,
                    "parse_error": parse_error.to_string()
                })),
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use rmcp::model::ErrorCode;
    use serde_json::json;

    struct RecordingTransport {
        requests: Vec<JsonValue>,
        responses: VecDeque<JsonValue>,
    }

    impl RecordingTransport {
        fn new(responses: Vec<JsonValue>) -> Self {
            Self {
                requests: Vec::new(),
                responses: VecDeque::from(responses),
            }
        }
    }

    impl Transport for RecordingTransport {
        fn send(&mut self, request: JsonValue) -> Result<JsonValue, TransportError> {
            self.requests.push(request);
            self.responses
                .pop_front()
                .ok_or_else(|| TransportError::new("missing response"))
        }
    }

    struct QueueTransport {
        responses: VecDeque<Result<JsonValue, TransportError>>,
    }

    impl QueueTransport {
        fn new(responses: Vec<Result<JsonValue, TransportError>>) -> Self {
            Self {
                responses: VecDeque::from(responses),
            }
        }
    }

    impl Transport for QueueTransport {
        fn send(&mut self, _request: JsonValue) -> Result<JsonValue, TransportError> {
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err(TransportError::new("missing response")))
        }
    }

    #[test]
    fn send_tool_call_initializes_first() {
        let responses = vec![
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
        ];
        let transport = RecordingTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        let invocation = ToolInvocation {
            name: "search".to_string(),
            arguments: json!({"query": "hello"}),
        };
        let trace = driver.send_tool_call(invocation).expect("tool call");

        assert_eq!(trace.invocation.name, "search");
        assert_eq!(driver.transport.requests.len(), 2);
        assert_eq!(
            driver.transport.requests[0]
                .get("method")
                .and_then(|value| value.as_str()),
            Some("initialize")
        );
        assert_eq!(
            driver.transport.requests[1]
                .get("method")
                .and_then(|value| value.as_str()),
            Some("tools/call")
        );
    }

    #[test]
    fn initialization_error_surfaces_as_failure() {
        let responses = vec![json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32603, "message": "nope"}
        })];
        let transport = RecordingTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        let error = driver.initialize().expect_err("expected init failure");
        assert_eq!(
            error,
            SessionError::InitializationFailed {
                error: Box::new(ErrorData::new(ErrorCode::INTERNAL_ERROR, "nope", None))
            }
        );
    }

    #[test]
    fn initialize_propagates_transport_error() {
        let transport = QueueTransport::new(vec![Err(TransportError::new("wire down"))]);
        let mut driver = SessionDriver::new(transport);

        let error = driver.initialize().expect_err("transport failure");
        assert_eq!(
            error,
            SessionError::Transport(TransportError::new("wire down"))
        );
    }

    #[test]
    fn transport_error_helpers_capture_message() {
        let error = TransportError::new("transport down");
        assert_eq!(error.message, "transport down");
        assert_eq!(error.kind, TransportErrorKind::Other);
        assert!(error.source.is_none());
        assert_eq!(
            SessionError::from(error.clone()),
            SessionError::Transport(error)
        );

        let error = TransportError::with_kind(TransportErrorKind::Io, "lost");
        assert_eq!(error.kind, TransportErrorKind::Io);
        assert!(error.source.is_none());

        let error = TransportError::with_source(TransportErrorKind::Protocol, "bad", "codec");
        assert_eq!(error.kind, TransportErrorKind::Protocol);
        assert_eq!(error.source, Some("codec".to_string()));
    }

    #[test]
    fn recording_transport_missing_response_reports_error() {
        let mut transport = RecordingTransport::new(Vec::new());
        let error = transport
            .send(json!({}))
            .expect_err("expected missing response");
        assert_eq!(error, TransportError::new("missing response"));
    }

    #[test]
    fn queue_transport_missing_response_reports_error() {
        let mut transport = QueueTransport::new(Vec::new());
        let error = transport
            .send(json!({}))
            .expect_err("expected missing response");
        assert_eq!(error, TransportError::new("missing response"));
    }

    #[test]
    fn initialize_sets_initialized_flag() {
        let responses = vec![json!({"jsonrpc": "2.0", "id": 1, "result": {}})];
        let transport = RecordingTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        assert!(!driver.is_initialized());
        driver.initialize().expect("init");
        assert!(driver.is_initialized());
    }

    #[test]
    fn tool_call_error_surfaces_as_failure() {
        let responses = vec![
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 2, "error": {"code": -32603, "message": "bad"}}),
        ];
        let transport = RecordingTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        let invocation = ToolInvocation {
            name: "bad_tool".to_string(),
            arguments: json!({}),
        };
        let error = driver.send_tool_call(invocation).expect_err("tool failure");
        assert_eq!(
            error,
            SessionError::ToolCallFailed {
                tool: "bad_tool".to_string(),
                error: Box::new(ErrorData::new(ErrorCode::INTERNAL_ERROR, "bad", None))
            }
        );
    }

    #[test]
    fn tool_call_propagates_init_failure() {
        let responses = vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32603, "message": "init blocked"}
        }))];
        let transport = QueueTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        let invocation = ToolInvocation {
            name: "guarded".to_string(),
            arguments: json!({}),
        };
        let error = driver.send_tool_call(invocation).expect_err("init failure");
        assert_eq!(
            error,
            SessionError::InitializationFailed {
                error: Box::new(ErrorData::new(
                    ErrorCode::INTERNAL_ERROR,
                    "init blocked",
                    None
                ))
            }
        );
    }

    #[test]
    fn tool_call_propagates_transport_error() {
        let responses = vec![
            Ok(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
            Err(TransportError::new("link down")),
        ];
        let transport = QueueTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        let invocation = ToolInvocation {
            name: "unstable".to_string(),
            arguments: json!({}),
        };
        let error = driver
            .send_tool_call(invocation)
            .expect_err("transport error");
        assert_eq!(
            error,
            SessionError::Transport(TransportError::new("link down"))
        );
    }

    #[test]
    fn run_invocations_reuses_initialization() {
        let responses = vec![
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 3, "result": {}}),
        ];
        let transport = RecordingTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        driver.initialize().expect("init");
        let invocations = vec![
            ToolInvocation {
                name: "one".to_string(),
                arguments: json!({"a": 1}),
            },
            ToolInvocation {
                name: "two".to_string(),
                arguments: json!({"b": 2}),
            },
        ];
        let trace = driver.run_invocations(invocations).expect("trace");

        assert_eq!(trace.len(), 2);
        assert_eq!(driver.transport.requests.len(), 3);
        assert_eq!(
            driver.transport.requests[0]
                .get("method")
                .and_then(|value| value.as_str()),
            Some("initialize")
        );
    }

    #[test]
    fn run_invocations_propagates_init_failure() {
        let responses = vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32603, "message": "no init"}
        }))];
        let transport = QueueTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        let invocations = vec![ToolInvocation {
            name: "blocked".to_string(),
            arguments: json!({}),
        }];
        let error = driver
            .run_invocations(invocations)
            .expect_err("init failure");
        assert_eq!(
            error,
            SessionError::InitializationFailed {
                error: Box::new(ErrorData::new(ErrorCode::INTERNAL_ERROR, "no init", None))
            }
        );
    }

    #[test]
    fn run_invocations_propagates_tool_failure() {
        let responses = vec![
            Ok(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
            Ok(json!({"jsonrpc": "2.0", "id": 2, "error": {"code": -32603, "message": "nope"}})),
        ];
        let transport = QueueTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        let invocations = vec![ToolInvocation {
            name: "fail".to_string(),
            arguments: json!({}),
        }];
        let error = driver
            .run_invocations(invocations)
            .expect_err("tool failure");
        assert_eq!(
            error,
            SessionError::ToolCallFailed {
                tool: "fail".to_string(),
                error: Box::new(ErrorData::new(ErrorCode::INTERNAL_ERROR, "nope", None))
            }
        );
    }

    #[test]
    fn rpc_error_preserves_fields() {
        let error = ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            "oops",
            Some(json!({"info": "detail"})),
        );
        assert_eq!(error.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(error.message.as_ref(), "oops");
        assert_eq!(error.data, Some(json!({"info": "detail"})));
    }

    #[test]
    fn invalid_error_payload_yields_internal_error() {
        let error = extract_error(&json!({"error": {"message": "oops"}})).expect("error");
        assert_eq!(error.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(error.message.as_ref(), "invalid error payload");
        let data = error.data.expect("data");
        assert_eq!(data["raw"], json!({"message": "oops"}));
        assert!(data["parse_error"].as_str().is_some());
    }

    #[test]
    fn reset_clears_initialization_state() {
        let responses = vec![
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 1, "result": {}}),
        ];
        let transport = RecordingTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        driver.initialize().expect("init");
        assert!(driver.is_initialized());
        driver.reset();
        assert!(!driver.is_initialized());

        driver.initialize().expect("init again");
        assert_eq!(driver.transport.requests.len(), 2);
        assert_eq!(
            driver.transport.requests[0]
                .get("id")
                .and_then(|value| value.as_i64()),
            Some(1)
        );
        assert_eq!(
            driver.transport.requests[1]
                .get("id")
                .and_then(|value| value.as_i64()),
            Some(1)
        );
    }
}
