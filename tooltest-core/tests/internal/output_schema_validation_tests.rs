use crate::{
    list_tools_with_session, validate_tool, RunConfig, RunOutcome, RunnerOptions, SchemaConfig,
    SessionDriver, ToolValidationConfig, ToolValidationError,
};
use rmcp::model::CallToolResult;
use serde_json::json;
use tooltest_test_support::{tool_with_schemas, ListToolsTransport, RunnerTransport};

async fn connect_runner_transport(
    transport: RunnerTransport,
) -> Result<SessionDriver, crate::SessionError> {
    SessionDriver::connect_with_transport::<
        RunnerTransport,
        std::convert::Infallible,
        rmcp::transport::TransportAdapterIdentity,
    >(transport)
    .await
}

async fn connect_list_tools_transport(
    transport: ListToolsTransport,
) -> Result<SessionDriver, crate::SessionError> {
    SessionDriver::connect_with_transport::<
        ListToolsTransport,
        std::convert::Infallible,
        rmcp::transport::TransportAdapterIdentity,
    >(transport)
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn run_rejects_unknown_output_schema_version() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({
            "$schema": "https://example.com/unknown",
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

    let result = crate::run_with_session(
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
            assert!(failure.reason.contains("unknown output schema version"));
        }
        RunOutcome::Success => panic!("expected failure"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tool_validation_rejects_unknown_output_schema_version() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
        Some(json!({
            "$schema": "https://example.com/unknown",
            "type": "object",
            "properties": {
                "status": { "type": "string" }
            },
            "required": ["status"]
        })),
    );
    let response = CallToolResult::structured(json!({ "status": "ok" }));
    let transport = RunnerTransport::new(tool.clone(), response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let config = ToolValidationConfig::new().with_cases_per_tool(1);
    let result = validate_tool(&driver, &config, &tool).await;

    match result {
        Err(ToolValidationError::ValidationFailed(failure)) => {
            assert!(failure
                .failure
                .reason
                .contains("unknown output schema version"));
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn list_tools_session_validates_schema() {
    let tool = tool_with_schemas(
        "echo",
        json!({
            "type": 5,
            "properties": {
                "value": { "type": "string" }
            }
        }),
        None,
    );
    let transport = ListToolsTransport::new(vec![tool]);
    let driver = connect_list_tools_transport(transport)
        .await
        .expect("connect");

    let result = list_tools_with_session(&driver, &SchemaConfig::default()).await;
    assert!(result.is_err());
}
