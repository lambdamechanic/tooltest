use rmcp::model::{CallToolResult, Content, ErrorData};
use serde_json::json;
use tooltest_core::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, ErrorCode, HttpConfig,
    ResponseAssertion, RunConfig, RunOutcome, RunnerOptions, SequenceAssertion, SessionDriver,
    StdioConfig,
};

mod support;

use support::{tool_with_schemas, RunnerTransport};

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

fn stdio_server_config() -> StdioConfig {
    StdioConfig::new(env!("CARGO_BIN_EXE_stdio_test_server"))
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
    assert_eq!(result.trace.len(), 1);
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
    assert_eq!(result.trace.len(), 1);
}

#[test]
fn runner_options_default_matches_expected_values() {
    let options = RunnerOptions::default();
    assert_eq!(options.cases, 32);
    assert_eq!(options.sequence_len, 1..=3);
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
    assert!(result.trace.is_empty());
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
    assert!(result.trace.is_empty());
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
    let config = stdio_server_config();
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
