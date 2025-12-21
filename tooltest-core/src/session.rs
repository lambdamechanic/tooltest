use serde_json::{json, Value as JsonValue};

use crate::{ToolInvocation, TraceEntry};

/// Transport abstraction for MCP request/response exchange.
pub trait Transport {
    /// Sends a JSON-RPC request and returns the raw JSON response.
    fn send(&mut self, request: JsonValue) -> Result<JsonValue, TransportError>;
}

/// Transport-level error surfaced by the session driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError {
    /// Human-readable error description.
    pub message: String,
}

impl TransportError {
    /// Creates a new transport error from a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Errors emitted by the session driver.
#[derive(Clone, Debug, PartialEq)]
pub enum SessionError {
    /// Transport-level failure.
    Transport(TransportError),
    /// Initialization failed with a reason.
    InitializationFailed { reason: String },
    /// Tool call failed with a reason.
    ToolCallFailed { tool: String, reason: String },
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

    /// Performs MCP initialization with empty parameters.
    pub fn initialize(&mut self) -> Result<JsonValue, SessionError> {
        self.initialize_with_params(json!({}))
    }

    /// Performs MCP initialization with caller-supplied parameters.
    pub fn initialize_with_params(&mut self, params: JsonValue) -> Result<JsonValue, SessionError> {
        let response = self.send_request("initialize", params)?;
        if let Some(reason) = extract_error(&response) {
            return Err(SessionError::InitializationFailed { reason });
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
        if let Some(reason) = extract_error(&response) {
            return Err(SessionError::ToolCallFailed {
                tool: tool_name,
                reason,
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
        let request = json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params,
        });
        self.next_id = self.next_id.saturating_add(1);
        self.transport.send(request).map_err(SessionError::from)
    }
}

fn extract_error(response: &JsonValue) -> Option<String> {
    response.get("error").map(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
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
            "error": {"message": "nope"}
        })];
        let transport = RecordingTransport::new(responses);
        let mut driver = SessionDriver::new(transport);

        let error = driver.initialize().expect_err("expected init failure");
        assert_eq!(
            error,
            SessionError::InitializationFailed {
                reason: "{\"message\":\"nope\"}".to_string()
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
        assert_eq!(
            SessionError::from(error.clone()),
            SessionError::Transport(error)
        );
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
            json!({"jsonrpc": "2.0", "id": 2, "error": {"message": "bad"}}),
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
                reason: "{\"message\":\"bad\"}".to_string()
            }
        );
    }

    #[test]
    fn tool_call_propagates_init_failure() {
        let responses = vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"message": "init blocked"}
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
                reason: "{\"message\":\"init blocked\"}".to_string()
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
            "error": {"message": "no init"}
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
                reason: "{\"message\":\"no init\"}".to_string()
            }
        );
    }

    #[test]
    fn run_invocations_propagates_tool_failure() {
        let responses = vec![
            Ok(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
            Ok(json!({"jsonrpc": "2.0", "id": 2, "error": {"message": "nope"}})),
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
                reason: "{\"message\":\"nope\"}".to_string()
            }
        );
    }
}
