use axum::Router;
use rmcp::handler::server::{
    router::tool::ToolRouter,
    wrapper::{Json, Parameters},
};
use rmcp::model::{CallToolResult, Content, ErrorData};
use rmcp::transport::{
    streamable_http_server::session::local::LocalSessionManager, StreamableHttpServerConfig,
    StreamableHttpService,
};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Number};
use tooltest_core::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CoverageRule,
    CoverageWarningReason, ErrorCode, HttpConfig, ResponseAssertion, RunConfig, RunOutcome,
    RunnerOptions, SequenceAssertion, SessionDriver, StateMachineConfig, StdioConfig, TraceEntry,
};

use tooltest_test_support::{tool_with_schemas, RunnerTransport};

async fn connect_runner_transport(
    transport: RunnerTransport,
) -> Result<SessionDriver, tooltest_core::SessionError> {
    SessionDriver::connect_with_transport::<
        RunnerTransport,
        std::convert::Infallible,
        rmcp::transport::TransportAdapterIdentity,
    >(transport)
    .await
}

#[derive(Clone)]
struct HttpTestServer {
    tool_router: ToolRouter<Self>,
}

impl HttpTestServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for HttpTestServer {}

#[derive(Deserialize, Serialize, JsonSchema)]
struct EchoInput {
    value: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct EchoOutput {
    status: String,
}

#[tool_router]
impl HttpTestServer {
    #[tool(name = "echo", description = "Echo input for test coverage")]
    async fn echo(&self, _params: Parameters<EchoInput>) -> Json<EchoOutput> {
        Json(EchoOutput {
            status: "ok".to_string(),
        })
    }
}

fn stdio_server_config() -> Option<StdioConfig> {
    option_env!("CARGO_BIN_EXE_stdio_test_server").map(StdioConfig::new)
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_returns_minimized_failure() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": {
                "flag": { "type": "boolean", "const": true }
            },
            "required": ["flag"]
        }),
        Some(json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "const": "ok" }
            },
            "required": ["status"]
        })),
    );
    let response = CallToolResult::structured(json!({ "status": "bad" }));
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let config = RunConfig::new();
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };
    let result = tooltest_core::run_with_session(&driver, &config, options).await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    assert!(result.minimized.is_some());
    assert_eq!(result.trace.len(), 2);
    assert!(matches!(
        result.trace.as_slice(),
        [
            TraceEntry::ListTools { .. },
            TraceEntry::ToolCall {
                response: Some(_),
                failure_reason: Some(_),
                ..
            }
        ]
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_accepts_json_dsl_assertions() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": {
                "flag": { "type": "boolean", "const": true }
            },
            "required": ["flag"]
        }),
        Some(json!({
            "type": "object",
            "properties": {
                "status": { "type": "string" }
            },
            "required": ["status"]
        })),
    );
    let response = CallToolResult::structured(json!({ "status": "ok" }));
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let assertions = AssertionSet {
        rules: vec![
            AssertionRule::Response(ResponseAssertion {
                tool: Some("echo".to_string()),
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/flag".to_string(),
                    expected: json!(true),
                }],
            }),
            AssertionRule::Response(ResponseAssertion {
                tool: Some("echo".to_string()),
                checks: vec![AssertionCheck {
                    target: AssertionTarget::StructuredOutput,
                    pointer: "/status".to_string(),
                    expected: json!("ok"),
                }],
            }),
            AssertionRule::Sequence(SequenceAssertion {
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Sequence,
                    pointer: "/0/invocation/name".to_string(),
                    expected: json!("echo"),
                }],
            }),
        ],
    };

    let config = RunConfig::new().with_assertions(assertions);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };
    let result = tooltest_core::run_with_session(&driver, &config, options).await;

    assert!(matches!(result.outcome, RunOutcome::Success));
    assert!(result.trace.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn run_with_session_rejects_current_thread_runtime() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 0..=0,
        },
    )
    .await;

    match result.outcome {
        RunOutcome::Failure(failure) => {
            assert!(failure.reason.contains("multi-thread Tokio runtime"));
        }
        _ => panic!("expected failure"),
    }
}

#[test]
fn runner_options_default_matches_expected_values() {
    let options = RunnerOptions::default();
    assert_eq!(options.cases, 32);
    assert_eq!(options.sequence_len, 1..=3);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_supports_state_machine_generator() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            },
            "required": ["count"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let state_machine = StateMachineConfig::default().with_seed_numbers(vec![Number::from(5)]);
    let config = RunConfig::new().with_state_machine(state_machine);
    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Success));
    assert!(result.trace.is_empty());
    let coverage = result.coverage.expect("coverage");
    assert_eq!(coverage.counts.get("echo").copied(), Some(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_emits_uncallable_tool_warning() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": {
                "text": { "type": "string" }
            },
            "required": ["text"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let config = RunConfig::new();
    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    let coverage = result.coverage.expect("coverage");
    assert_eq!(coverage.warnings.len(), 1);
    assert_eq!(coverage.warnings[0].tool, "echo");
    assert_eq!(
        coverage.warnings[0].reason,
        CoverageWarningReason::MissingString
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_honors_coverage_allowlist_and_blocklist() {
    let alpha = tool_with_schemas(
        "alpha",
        json!({
            "type": "object",
            "properties": {
                "text": { "type": "string" }
            },
            "required": ["text"]
        }),
        None,
    );
    let beta = tool_with_schemas(
        "beta",
        json!({
            "type": "object",
            "properties": {
                "text": { "type": "string" }
            },
            "required": ["text"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new_with_tools(vec![alpha, beta], response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let state_machine = StateMachineConfig::default()
        .with_coverage_allowlist(vec!["alpha".to_string()])
        .with_coverage_blocklist(vec!["beta".to_string()]);
    let config = RunConfig::new().with_state_machine(state_machine);

    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    let coverage = result.coverage.expect("coverage");
    assert_eq!(coverage.warnings.len(), 1);
    assert_eq!(coverage.warnings[0].tool, "alpha");
    assert_eq!(
        coverage.warnings[0].reason,
        CoverageWarningReason::MissingString
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_executes_allowlist_and_blocklist_filters() {
    let alpha = tool_with_schemas("alpha", json!({ "type": "object" }), None);
    let beta = tool_with_schemas("beta", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new_with_tools(vec![alpha, beta], response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let state_machine = StateMachineConfig::default()
        .with_coverage_allowlist(vec!["alpha".to_string()])
        .with_coverage_blocklist(vec!["alpha".to_string()])
        .with_coverage_rules(vec![CoverageRule::percent_called(0.0)]);
    let config = RunConfig::new().with_state_machine(state_machine);

    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Success));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_fails_on_coverage_validation_rule() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            },
            "required": ["count"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let state_machine = StateMachineConfig::default()
        .with_seed_numbers(vec![Number::from(1)])
        .with_coverage_rules(vec![CoverageRule::min_calls_per_tool(2)]);
    let config = RunConfig::new().with_state_machine(state_machine);

    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    match result.outcome {
        RunOutcome::Failure(failure) => {
            assert_eq!(failure.code.as_deref(), Some("coverage_validation_failed"));
            assert!(failure.details.is_some());
        }
        _ => panic!("expected failure"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_coverage_failure_includes_corpus_dump() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": {
                "text": { "type": "string" }
            },
            "required": ["text"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let state_machine = StateMachineConfig::default()
        .with_seed_strings(vec!["alpha".to_string()])
        .with_dump_corpus(true)
        .with_coverage_rules(vec![CoverageRule::min_calls_per_tool(2)]);
    let config = RunConfig::new().with_state_machine(state_machine);

    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    assert!(result.corpus.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_percent_called_excludes_uncallable_tools() {
    let callable = tool_with_schemas(
        "callable",
        json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            },
            "required": ["count"]
        }),
        None,
    );
    let uncallable = tool_with_schemas(
        "uncallable",
        json!({
            "type": "object",
            "properties": {
                "text": { "type": "string" }
            },
            "required": ["text"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new_with_tools(vec![callable, uncallable], response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let state_machine = StateMachineConfig::default()
        .with_seed_numbers(vec![Number::from(1)])
        .with_coverage_rules(vec![CoverageRule::percent_called(100.0)]);
    let config = RunConfig::new().with_state_machine(state_machine);

    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Success));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_excludes_error_responses_from_coverage() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            },
            "required": ["count"]
        }),
        None,
    );
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let state_machine = StateMachineConfig::default().with_seed_numbers(vec![Number::from(3)]);
    let config = RunConfig::new().with_state_machine(state_machine);

    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    let coverage = result.coverage.expect("coverage");
    assert_eq!(coverage.counts.get("echo").copied(), Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_session_error() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response).with_call_tool_error(ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        "call failed",
        None,
    ));
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    match result.outcome {
        RunOutcome::Failure(failure) => {
            assert!(failure.reason.contains("session error"));
        }
        _ => panic!("expected failure"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_list_tools_error() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response).with_list_tools_error(ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        "list failed",
        None,
    ));
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    assert!(matches!(
        result.trace.as_slice(),
        [TraceEntry::ListTools {
            failure_reason: Some(_),
            ..
        }]
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_invalid_tool_schema() {
    let tool = tool_with_schemas("bad", json!({ "type": "string" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_invalid_input_schema() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object", "properties": { "bad": { "type": 5 } } }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    let RunOutcome::Failure(failure) = &result.outcome else {
        panic!("expected failure");
    };
    assert!(failure.reason.contains("unsupported schema for tool"));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_invalid_output_schema() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({
            "type": "object",
            "properties": { "status": 5 }
        })),
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_uncompilable_output_schema() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({
            "type": "object",
            "properties": { "status": { "type": "string", "pattern": "(" } }
        })),
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    assert!(matches!(
        result.trace.as_slice(),
        [TraceEntry::ListTools { .. }]
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_no_eligible_tools() {
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new_with_tools(Vec::new(), response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_tool_error_response() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_call_tool_error() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response).with_call_tool_error(ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        "call failed",
        None,
    ));
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    assert!(matches!(
        result.trace.as_slice(),
        [
            TraceEntry::ListTools { .. },
            TraceEntry::ToolCall {
                response: None,
                failure_reason: Some(_),
                ..
            }
        ]
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_succeeds_with_default_assertions() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = tooltest_core::run_with_session(
        &driver,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Success));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_response_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let assertions = AssertionSet {
        rules: vec![AssertionRule::Response(ResponseAssertion {
            tool: Some("echo".to_string()),
            checks: vec![AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/flag".to_string(),
                expected: json!(true),
            }],
        })],
    };

    let config = RunConfig::new().with_assertions(assertions);
    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_sequence_assertion_failure() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let assertions = AssertionSet {
        rules: vec![AssertionRule::Sequence(SequenceAssertion {
            checks: vec![AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/missing".to_string(),
                expected: json!(true),
            }],
        })],
    };

    let config = RunConfig::new().with_assertions(assertions);
    let result = tooltest_core::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_http_succeeds_with_streamable_server() {
    let mut http_config = StreamableHttpServerConfig::default();
    http_config.stateful_mode = true;
    http_config.sse_keep_alive = None;
    let service: StreamableHttpService<HttpTestServer, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(HttpTestServer::new()),
            Default::default(),
            http_config,
        );
    let app = Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let config = HttpConfig {
        url: format!("http://{addr}/mcp"),
        auth_token: None,
    };
    let state_machine = StateMachineConfig::default().with_lenient_sourcing(true);
    let result = tooltest_core::run_http(
        &config,
        &RunConfig::new().with_state_machine(state_machine),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    let _ = shutdown_tx.send(());
    let _ = server.await;

    assert!(matches!(result.outcome, RunOutcome::Success));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_http_reports_transport_error() {
    let config = HttpConfig {
        url: "http://localhost:1234/mcp".to_string(),
        auth_token: None,
    };
    let result =
        tooltest_core::run_http(&config, &RunConfig::new(), RunnerOptions::default()).await;
    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_stdio_reports_transport_error() {
    let config = StdioConfig::new("mcp-server");
    let result =
        tooltest_core::run_stdio(&config, &RunConfig::new(), RunnerOptions::default()).await;
    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_stdio_succeeds_with_real_transport() {
    let Some(config) = stdio_server_config() else {
        return;
    };
    if !std::path::Path::new(&config.command).exists() {
        return;
    }
    let result = tooltest_core::run_stdio(
        &config,
        &RunConfig::new(),
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;
    assert!(matches!(result.outcome, RunOutcome::Success));
}
