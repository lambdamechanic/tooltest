use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CoverageRule,
    CoverageWarningReason, ErrorCode, HttpConfig, PreRunHook, ResponseAssertion, RunConfig,
    RunOutcome, RunnerOptions, SequenceAssertion, StateMachineConfig, StdioConfig, TraceEntry,
};
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
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::test_support::connect_runner_transport;
use tooltest_test_support::{tool_with_schemas, RunnerTransport};

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
    option_env!("CARGO_BIN_EXE_stdio_test_server").map(|server| {
        let mut config = StdioConfig::new(server);
        config
            .env
            .insert("LLVM_PROFILE_FILE".to_string(), "/dev/null".to_string());
        config
    })
}

fn temp_hook_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    path.push(format!("tooltest-pre-run-{tag}-{pid}-{nanos}-{counter}"));
    path
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

    let config = RunConfig::new().with_state_machine(
        StateMachineConfig::default().with_coverage_rules(vec![CoverageRule::percent_called(0.0)]),
    );
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };
    let result = crate::run_with_session(&driver, &config, options).await;

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
async fn run_with_session_executes_pre_run_hook_per_case() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let path = temp_hook_path("per-case");
    let hook = PreRunHook::new(format!("printf 'hook\\n' >> {}", path.display()));
    let config = RunConfig::new().with_pre_run_hook(hook).with_state_machine(
        StateMachineConfig::default().with_coverage_rules(vec![CoverageRule::percent_called(0.0)]),
    );
    let options = RunnerOptions {
        cases: 2,
        sequence_len: 1..=1,
    };

    let result = crate::run_with_session(&driver, &config, options).await;

    assert!(matches!(result.outcome, RunOutcome::Success));
    let contents = fs::read_to_string(&path).expect("read hook log");
    assert_eq!(contents.lines().count(), 3);
    let _ = fs::remove_file(&path);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_executes_pre_run_hook_for_zero_case_runs() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let path = temp_hook_path("zero-case");
    let hook = PreRunHook::new(format!("printf 'hook\\n' >> {}", path.display()));
    let config = RunConfig::new().with_pre_run_hook(hook).with_state_machine(
        StateMachineConfig::default().with_coverage_rules(vec![CoverageRule::percent_called(0.0)]),
    );
    let options = RunnerOptions {
        cases: 0,
        sequence_len: 1..=1,
    };

    let result = crate::run_with_session(&driver, &config, options).await;

    assert!(matches!(result.outcome, RunOutcome::Success));
    let contents = fs::read_to_string(&path).expect("read hook log");
    assert_eq!(contents.lines().count(), 2);
    let _ = fs::remove_file(&path);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_pre_run_hook_failure_details() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let hook = PreRunHook::new("echo hook-out; echo hook-err 1>&2; exit 7");
    let config = RunConfig::new().with_pre_run_hook(hook);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = crate::run_with_session(&driver, &config, options).await;

    match result.outcome {
        RunOutcome::Failure(failure) => {
            assert_eq!(failure.code.as_deref(), Some("pre_run_hook_failed"));
            let details = failure.details.expect("details");
            assert_eq!(
                details.get("exit_code").and_then(|value| value.as_i64()),
                Some(7)
            );
            let stdout = details
                .get("stdout")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let stderr = details
                .get("stderr")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            assert!(stdout.contains("hook-out"));
            assert!(stderr.contains("hook-err"));
        }
        _ => panic!("expected failure"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_pre_run_hook_start_error() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let missing_cwd = temp_hook_path("missing-hook-cwd");
    let mut hook = PreRunHook::new("echo ok");
    hook.cwd = Some(missing_cwd.to_string_lossy().into_owned());
    let config = RunConfig::new().with_pre_run_hook(hook);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = crate::run_with_session(&driver, &config, options).await;

    match result.outcome {
        RunOutcome::Failure(failure) => {
            assert_eq!(failure.code.as_deref(), Some("pre_run_hook_failed"));
            assert!(failure.reason.contains("failed to start"));
            let details = failure.details.expect("details");
            let stderr = details
                .get("stderr")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            assert!(!stderr.is_empty());
        }
        _ => panic!("expected failure"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_pre_run_hook_failure_for_zero_case_runs() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let marker = temp_hook_path("zero-case-fail");
    let hook = PreRunHook::new(format!(
        "if [ -f \"{marker}\" ]; then exit 3; else printf 'hook' > \"{marker}\"; fi",
        marker = marker.display()
    ));
    let config = RunConfig::new().with_pre_run_hook(hook);
    let options = RunnerOptions {
        cases: 0,
        sequence_len: 1..=1,
    };

    let result = crate::run_with_session(&driver, &config, options).await;

    match result.outcome {
        RunOutcome::Failure(failure) => {
            assert_eq!(failure.code.as_deref(), Some("pre_run_hook_failed"));
            let details = failure.details.expect("details");
            assert_eq!(
                details.get("exit_code").and_then(|value| value.as_i64()),
                Some(3)
            );
        }
        _ => panic!("expected failure"),
    }
    let _ = fs::remove_file(marker);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_reports_pre_run_hook_signal_exit() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let hook = PreRunHook::new("kill -9 $$");
    let config = RunConfig::new().with_pre_run_hook(hook);
    let options = RunnerOptions {
        cases: 1,
        sequence_len: 1..=1,
    };

    let result = crate::run_with_session(&driver, &config, options).await;

    match result.outcome {
        RunOutcome::Failure(failure) => {
            assert_eq!(failure.code.as_deref(), Some("pre_run_hook_failed"));
            assert_eq!(failure.reason, "pre-run hook failed");
            let details = failure.details.expect("details");
            assert!(details
                .get("signal")
                .and_then(|value| value.as_i64())
                .is_some());
        }
        _ => panic!("expected failure"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_session_zero_cases_without_pre_run_hook_succeeds() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let config = RunConfig::new().with_state_machine(
        StateMachineConfig::default().with_coverage_rules(vec![CoverageRule::percent_called(0.0)]),
    );
    let options = RunnerOptions {
        cases: 0,
        sequence_len: 1..=1,
    };

    let result = crate::run_with_session(&driver, &config, options).await;

    assert!(matches!(result.outcome, RunOutcome::Success));
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
    let result = crate::run_with_session(&driver, &config, options).await;

    assert!(matches!(result.outcome, RunOutcome::Success));
    assert!(result.trace.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn run_with_session_rejects_current_thread_runtime() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let result = crate::run_with_session(
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
    assert_eq!(options.sequence_len, 1..=20);
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
    let result = crate::run_with_session(
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
async fn run_with_session_generates_all_enum_values() {
    let tool = tool_with_schemas(
        "automation_script",
        json!({
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "enum": ["shell", "ruby", "powershell", "batch"]
                }
            },
            "required": ["language"]
        }),
        None,
    );
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let assertions = AssertionSet {
        rules: vec![AssertionRule::Sequence(SequenceAssertion {
            checks: vec![AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/force_failure".to_string(),
                expected: json!(true),
            }],
        })],
    };
    let config = RunConfig::new().with_assertions(assertions);
    let result = crate::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 20..=20,
        },
    )
    .await;
    assert!(matches!(result.outcome, RunOutcome::Failure(_)));

    let mut seen = HashSet::new();
    let tool_calls: Vec<_> = result
        .trace
        .iter()
        .filter_map(|entry| entry.as_tool_call().map(|(invocation, _)| invocation))
        .collect();
    assert_eq!(tool_calls.len(), 20);
    for invocation in tool_calls {
        let args = invocation.arguments.as_ref().expect("arguments");
        let language = args
            .get("language")
            .and_then(|value| value.as_str())
            .expect("language");
        seen.insert(language.to_string());
    }

    let allowed: std::collections::HashSet<String> = ["shell", "ruby", "powershell", "batch"]
        .into_iter()
        .map(|value| value.to_string())
        .collect();
    assert!(!seen.is_empty());
    assert!(seen.is_subset(&allowed), "unexpected language in {seen:?}");
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
    let result = crate::run_with_session(
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

    let result = crate::run_with_session(
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

    let result = crate::run_with_session(
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
async fn run_with_session_defaults_to_percent_called_rule() {
    let alpha = tool_with_schemas("alpha", json!({ "type": "object" }), None);
    let beta = tool_with_schemas("beta", json!({ "type": "object" }), None);
    let response = CallToolResult::success(vec![Content::text("ok")]);
    let transport = RunnerTransport::new_with_tools(vec![alpha, beta], response);
    let driver = connect_runner_transport(transport).await.expect("connect");

    let config = RunConfig::new().with_state_machine(StateMachineConfig::default());

    let result = crate::run_with_session(
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
        }
        _ => panic!("expected failure"),
    }
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

    let result = crate::run_with_session(
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
    assert!(result.coverage.is_some());
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

    let result = crate::run_with_session(
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
async fn run_with_session_suppresses_coverage_on_positive_error() {
    let tool = tool_with_schemas(
        "echo",
        json!({ "type": "object" }),
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

    let config = RunConfig::new().with_state_machine(StateMachineConfig::default());

    let result = crate::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    assert!(result.coverage.is_none());
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

    let result = crate::run_with_session(
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
async fn run_with_session_allows_error_responses_and_excludes_from_coverage_by_default() {
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

    let state_machine = StateMachineConfig::default()
        .with_seed_numbers(vec![Number::from(3)])
        .with_coverage_rules(vec![CoverageRule::percent_called(0.0)]);
    let config = RunConfig::new().with_state_machine(state_machine);

    let result = crate::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Success));
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

    let result = crate::run_with_session(
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

    let result = crate::run_with_session(
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

    let result = crate::run_with_session(
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

    let result = crate::run_with_session(
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

    let result = crate::run_with_session(
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

    let result = crate::run_with_session(
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
async fn run_with_session_reports_tool_error_response_when_forbidden() {
    let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
    let response = CallToolResult::error(vec![Content::text("boom")]);
    let transport = RunnerTransport::new(tool, response);
    let driver = connect_runner_transport(transport).await.expect("connect");
    let config = RunConfig::new().with_in_band_error_forbidden(true);

    let result = crate::run_with_session(
        &driver,
        &config,
        RunnerOptions {
            cases: 1,
            sequence_len: 1..=1,
        },
    )
    .await;

    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    assert!(result.coverage.is_none(), "coverage: {:?}", result.coverage);
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

    let result = crate::run_with_session(
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

    let result = crate::run_with_session(
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
    let result = crate::run_with_session(
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
    let result = crate::run_with_session(
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
    let http_config = StreamableHttpServerConfig {
        stateful_mode: true,
        sse_keep_alive: None,
        ..Default::default()
    };
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
    let result = crate::run_http(
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
    let result = crate::run_http(&config, &RunConfig::new(), RunnerOptions::default()).await;
    assert!(matches!(result.outcome, RunOutcome::Failure(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn run_stdio_reports_transport_error() {
    let config = StdioConfig::new("mcp-server");
    let result = crate::run_stdio(&config, &RunConfig::new(), RunnerOptions::default()).await;
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
    let result = crate::run_stdio(
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
