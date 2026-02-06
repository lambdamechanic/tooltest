use futures::{stream::Stream, FutureExt};
use rmcp::handler::server::common::schema_for_type;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    AnnotateAble, CallToolRequestParam, CallToolResult, ClientJsonRpcMessage, ClientNotification,
    ClientRequest, GetPromptRequestParam, GetPromptResult, InitializeRequest,
    InitializeRequestParam, InitializedNotification, JsonObject, ListPromptsResult,
    ListResourcesResult, ListToolsResult, NumberOrString, PaginatedRequestParam, Prompt,
    PromptMessage, PromptMessageContent, PromptMessageRole, RawResource, ReadResourceRequestParam,
    ReadResourceResult, Resource, ResourceContents, Tool,
};
use rmcp::transport::stdio;
use rmcp::{ErrorData, RoleServer, ServiceExt};
use schemars::{generate::SchemaSettings, transform::AddNullable, JsonSchema};
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use tooltest_core::{
    RunFailure, RunOutcome, RunResult, TooltestInput, TooltestRunConfig, TooltestStdioTarget,
    TooltestTarget, TooltestTargetConfig, TooltestTargetStdio,
};

const TOOLTEST_TOOL_NAME: &str = "tooltest";
const TOOLTEST_TOOL_DESCRIPTION: &str =
    "Run tooltest against an MCP server using the shared tooltest input.";
const TOOLTEST_FIX_LOOP_PROMPT_NAME: &str = "tooltest-fix-loop";
const TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION: &str =
    "Guidance for iterating on tooltest failures in MCP servers.";
const TOOLTEST_FIX_LOOP_RESOURCE_URI: &str = "tooltest://guides/fix-loop";
const TOOLTEST_FIX_LOOP_RESOURCE_NAME: &str = "tooltest-fix-loop";
const TOOLTEST_FIX_LOOP_RESOURCE_DESCRIPTION: &str =
    "Step-by-step guidance for running tooltest to fix MCP issues.";
const TOOLTEST_FIX_LOOP_PROMPT: &str = r#"You have access to this repository and can run commands.
Goal: make the repository's MCP server(s) conform to the MCP spec as exercised by tooltest.

Figure out how to start the MCP server from this repo (stdio or streamable HTTP).

Select a small, related subset of tools intended to be used together. Default to testing at most 50 tools at a time, and strongly prefer a smaller group. Use `--tool-allowlist` (or `tool_allowlist` in MCP input) to enforce this.

Run tooltest against it and fix failures until it exits 0.

If you see "state-machine generator failed to reach minimum sequence length", re-run with `--lenient-sourcing` or seed values in `--state-machine-config`.

CLI usage (preferred when you can run commands):
- Use CLI-only flags for debugging, e.g. `--trace-all /tmp/tooltest-traces.jsonl`.
- Examples:
  CLI stdio (allowlist example): tooltest stdio --command "<command that starts the repo's MCP server>" --tool-allowlist foo --tool-allowlist bar
  CLI http (allowlist example): tooltest http --url "http://127.0.0.1:9000/mcp" --tool-allowlist foo --tool-allowlist bar

MCP tool usage (when you must call via MCP):
- Call the `tooltest` tool with the shared input schema.
- Only fields in the MCP input schema are accepted (CLI-only flags like `--json` and `--trace-all` are not supported).
- Example (allowlist):
{
  "target": { "stdio": { "command": "<command that starts the repo's MCP server>" } },
  "tool_allowlist": ["foo", "bar"]
}

Don't rename tools or change schemas unless required; prefer backward-compatible fixes.

Add/adjust tests if needed.

Return a short summary of what you changed and why, plus the final passing tooltest output snippet.
"#;

fn exit_immediately() -> bool {
    std::env::var_os("TOOLTEST_MCP_EXIT_IMMEDIATELY").is_some()
}

fn use_test_transport() -> bool {
    std::env::var_os("TOOLTEST_MCP_TEST_TRANSPORT").is_some()
}

struct TooltestWork {
    input: TooltestInput,
    respond_to: tokio::sync::oneshot::Sender<Result<tooltest_core::RunResult, ErrorData>>,
}

struct TooltestWorker {
    sender: tokio::sync::mpsc::UnboundedSender<TooltestWork>,
    #[cfg(test)]
    done: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

type TooltestExecuteFuture = Pin<
    Box<dyn std::future::Future<Output = Result<tooltest_core::RunResult, ErrorData>> + 'static>,
>;
type TooltestExecuteFn = fn(TooltestInput) -> TooltestExecuteFuture;

fn build_worker_runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
}

fn execute_tooltest_boxed(input: TooltestInput) -> TooltestExecuteFuture {
    Box::pin(execute_tooltest(input))
}

impl TooltestWorker {
    fn new() -> Result<Self, String> {
        Self::new_with_parts(build_worker_runtime, false, execute_tooltest_boxed)
    }

    fn new_with_parts(
        build_runtime: fn() -> Result<tokio::runtime::Runtime, std::io::Error>,
        skip_ready: bool,
        execute: TooltestExecuteFn,
    ) -> Result<Self, String> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<TooltestWork>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        #[cfg(test)]
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if skip_ready {
                return;
            }

            let runtime_result = build_runtime().map_err(|error| error.to_string());
            let runtime = match runtime_result {
                Ok(runtime) => {
                    let _ = ready_tx.send(Ok(()));
                    runtime
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                    return;
                }
            };
            runtime.block_on(async move {
                while let Some(work) = receiver.recv().await {
                    let result = std::panic::AssertUnwindSafe(execute(work.input))
                        .catch_unwind()
                        .await;
                    let result = match result {
                        Ok(result) => result,
                        Err(_) => Err(ErrorData::internal_error("tooltest tool panicked", None)),
                    };
                    let _ = work.respond_to.send(result);
                }
            });
            #[cfg(test)]
            let _ = done_tx.send(());
        });
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                sender,
                #[cfg(test)]
                done: std::sync::Mutex::new(done_rx),
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("tooltest runtime thread failed to start".to_string()),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum WorkerReadyMode {
    Send,
    Skip,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct TooltestWorkerConfig {
    ready_mode: WorkerReadyMode,
    build_runtime: fn() -> Result<tokio::runtime::Runtime, std::io::Error>,
}

#[cfg(test)]
impl Default for TooltestWorkerConfig {
    fn default() -> Self {
        Self {
            ready_mode: WorkerReadyMode::Send,
            build_runtime: build_worker_runtime,
        }
    }
}

#[cfg(test)]
impl TooltestWorker {
    fn new_with_config(
        config: TooltestWorkerConfig,
        execute: TooltestExecuteFn,
    ) -> Result<Self, String> {
        let skip_ready = matches!(config.ready_mode, WorkerReadyMode::Skip);
        Self::new_with_parts(config.build_runtime, skip_ready, execute)
    }
}

fn tooltest_worker_inner(
    worker: &OnceLock<Result<TooltestWorker, String>>,
) -> Result<&TooltestWorker, ErrorData> {
    let worker = worker.get_or_init(TooltestWorker::new);
    match worker.as_ref() {
        Ok(worker) => Ok(worker),
        Err(error) => Err(ErrorData::internal_error(
            format!("failed to start tooltest runtime: {error}"),
            None,
        )),
    }
}

fn tooltest_worker() -> Result<&'static TooltestWorker, ErrorData> {
    static WORKER: OnceLock<Result<TooltestWorker, String>> = OnceLock::new();
    tooltest_worker_inner(&WORKER)
}

struct NoopSink;

impl futures::Sink<rmcp::service::TxJsonRpcMessage<RoleServer>> for NoopSink {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: Pin<&mut Self>,
        _item: rmcp::service::TxJsonRpcMessage<RoleServer>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

type TestStream = rmcp::service::RxJsonRpcMessage<RoleServer>;

struct TestStreamState {
    messages: VecDeque<TestStream>,
    panic_on_empty: bool,
}

impl TestStreamState {
    fn new(messages: Vec<TestStream>, panic_on_empty: bool) -> Self {
        Self {
            messages: VecDeque::from(messages),
            panic_on_empty,
        }
    }
}

impl Stream for TestStreamState {
    type Item = TestStream;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(message) = self.messages.pop_front() {
            return Poll::Ready(Some(message));
        }
        if self.panic_on_empty {
            panic!("test transport exhausted");
        }
        Poll::Ready(None)
    }
}

fn stdio_test_transport() -> (NoopSink, TestStreamState) {
    let init = ClientJsonRpcMessage::request(
        ClientRequest::InitializeRequest(InitializeRequest::new(InitializeRequestParam::default())),
        NumberOrString::Number(1),
    );
    let initialized = ClientJsonRpcMessage::notification(
        ClientNotification::InitializedNotification(InitializedNotification::default()),
    );
    (
        NoopSink,
        TestStreamState::new(vec![init, initialized], false),
    )
}

fn stdio_bad_transport() -> (NoopSink, TestStreamState) {
    (NoopSink, TestStreamState::new(Vec::new(), false))
}

fn stdio_panic_transport() -> (NoopSink, TestStreamState) {
    let init = ClientJsonRpcMessage::request(
        ClientRequest::InitializeRequest(InitializeRequest::new(InitializeRequestParam::default())),
        NumberOrString::Number(1),
    );
    let initialized = ClientJsonRpcMessage::notification(
        ClientNotification::InitializedNotification(InitializedNotification::default()),
    );
    (
        NoopSink,
        TestStreamState::new(vec![init, initialized], true),
    )
}

#[derive(Clone, Default)]
pub struct McpServer;

impl McpServer {
    pub fn new() -> Self {
        Self
    }
}

async fn run_tooltest_call(
    worker: Result<&TooltestWorker, ErrorData>,
    input: TooltestInput,
) -> Result<CallToolResult, ErrorData> {
    let worker = worker?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    worker
        .sender
        .send(TooltestWork {
            input,
            respond_to: sender,
        })
        .map_err(|_| ErrorData::internal_error("tooltest tool execution failed", None))?;
    let result = receiver
        .await
        .map_err(|_| ErrorData::internal_error("tooltest tool execution failed", None))??;
    run_result_to_call_tool(&result)
}

impl ServerHandler for McpServer {
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListToolsResult {
            tools: vec![tooltest_tool()],
            ..Default::default()
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_
    {
        let name = request.name;
        let arguments = request.arguments;
        async move {
            if name.as_ref() != TOOLTEST_TOOL_NAME {
                return Err(ErrorData::invalid_params(
                    format!("tool '{name}' not found"),
                    Some(json!({ "available_tools": [TOOLTEST_TOOL_NAME] })),
                ));
            }
            let input = parse_tooltest_input(arguments)?;
            run_tooltest_call(tooltest_worker(), input).await
        }
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListPromptsResult {
            prompts: vec![fix_loop_prompt()],
            ..Default::default()
        }))
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetPromptResult, rmcp::ErrorData>> + Send + '_
    {
        let name = request.name;
        std::future::ready(if name == TOOLTEST_FIX_LOOP_PROMPT_NAME {
            Ok(fix_loop_prompt_result())
        } else {
            Err(prompt_not_found_error(&name))
        })
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListResourcesResult {
            resources: vec![fix_loop_resource()],
            ..Default::default()
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, rmcp::ErrorData>> + Send + '_
    {
        let uri = request.uri;
        std::future::ready(if uri == TOOLTEST_FIX_LOOP_RESOURCE_URI {
            Ok(ReadResourceResult {
                contents: vec![fix_loop_resource_contents()],
            })
        } else {
            Err(ErrorData::resource_not_found(
                format!("resource '{uri}' not found"),
                None,
            ))
        })
    }
}

fn tooltest_tool() -> Tool {
    Tool {
        name: TOOLTEST_TOOL_NAME.into(),
        title: None,
        description: Some(TOOLTEST_TOOL_DESCRIPTION.into()),
        input_schema: tooltest_input_schema(),
        output_schema: Some(schema_for_type::<tooltest_core::RunResult>()),
        annotations: None,
        icons: None,
        meta: None,
    }
}

fn tooltest_input_schema() -> Arc<JsonObject> {
    default_tooltest_input_schema()
}

fn default_tooltest_input_schema() -> Arc<JsonObject> {
    static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
    SCHEMA
        .get_or_init(inline_schema_for_type::<TooltestInput>)
        .clone()
}

fn inline_schema_for_type<T: JsonSchema>() -> Arc<JsonObject> {
    let mut settings = SchemaSettings::draft2020_12();
    settings.inline_subschemas = true;
    settings.transforms = vec![Box::new(AddNullable::default())];
    let generator = settings.into_generator();
    let schema = generator.into_root_schema_for::<T>();
    let value = serde_json::to_value(schema).expect("failed to serialize schema");
    let object: JsonObject =
        serde_json::from_value(value).expect("schema serialization produced non-object value");
    Arc::new(object)
}

fn fix_loop_prompt() -> Prompt {
    Prompt::new(
        TOOLTEST_FIX_LOOP_PROMPT_NAME,
        Some(TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION),
        None,
    )
}

fn fix_loop_prompt_result() -> GetPromptResult {
    GetPromptResult {
        description: Some(TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION.to_string()),
        messages: vec![PromptMessage {
            role: PromptMessageRole::User,
            content: PromptMessageContent::Text {
                text: TOOLTEST_FIX_LOOP_PROMPT.to_string(),
            },
        }],
    }
}

fn prompt_not_found_error(name: &str) -> ErrorData {
    ErrorData::invalid_params(
        format!("prompt '{name}' not found"),
        Some(json!({ "available_prompts": [TOOLTEST_FIX_LOOP_PROMPT_NAME] })),
    )
}

fn fix_loop_resource() -> Resource {
    RawResource {
        uri: TOOLTEST_FIX_LOOP_RESOURCE_URI.to_string(),
        name: TOOLTEST_FIX_LOOP_RESOURCE_NAME.to_string(),
        title: None,
        description: Some(TOOLTEST_FIX_LOOP_RESOURCE_DESCRIPTION.to_string()),
        mime_type: Some("text/plain".to_string()),
        size: None,
        icons: None,
        meta: None,
    }
    .no_annotation()
}

fn fix_loop_resource_contents() -> ResourceContents {
    ResourceContents::TextResourceContents {
        uri: TOOLTEST_FIX_LOOP_RESOURCE_URI.to_string(),
        mime_type: Some("text/plain".to_string()),
        text: TOOLTEST_FIX_LOOP_PROMPT.to_string(),
        meta: None,
    }
}

fn parse_tooltest_input(arguments: Option<JsonObject>) -> Result<TooltestInput, ErrorData> {
    let arguments =
        arguments.ok_or_else(|| ErrorData::invalid_params("tooltest input is required", None))?;
    serde_json::from_value(JsonValue::Object(arguments)).map_err(|error| {
        ErrorData::invalid_params(format!("invalid tooltest input: {error}"), None)
    })
}

async fn execute_tooltest(input: TooltestInput) -> Result<tooltest_core::RunResult, ErrorData> {
    let mut input = input;
    if let Ok(command) = std::env::var("TOOLTEST_MCP_DOGFOOD_COMMAND") {
        input.target = TooltestTarget::Stdio(TooltestTargetStdio {
            stdio: TooltestStdioTarget {
                command,
                args: Vec::new(),
                env: BTreeMap::new(),
                cwd: None,
            },
        });
        input.cases = 30;
        input.min_sequence_len = 1;
        input.max_sequence_len = 1;
        input.lenient_sourcing = true;
        input.no_lenient_sourcing = false;
        input.tool_allowlist.clear();
        input.tool_blocklist.clear();
        input.in_band_error_forbidden = false;
        input.pre_run_hook = None;
        input.state_machine_config = None;
        input.mine_text = false;
        input.dump_corpus = false;
        input.log_corpus_deltas = false;
        input.full_trace = false;
        input.show_uncallable = false;
        input.uncallable_limit = 1;
    }
    let TooltestRunConfig {
        target,
        run_config,
        runner_options,
    } = match input.to_configs() {
        Ok(configs) => configs,
        Err(error) => return Ok(run_result_from_input_error(error)),
    };

    let result = match target {
        TooltestTargetConfig::Stdio(config) => {
            tooltest_core::run_stdio(&config, &run_config, runner_options).await
        }
        TooltestTargetConfig::Http(config) => {
            tooltest_core::run_http(&config, &run_config, runner_options).await
        }
    };
    Ok(result)
}

fn run_result_from_input_error(message: String) -> RunResult {
    RunResult {
        outcome: RunOutcome::Failure(RunFailure::new(message)),
        trace: Vec::new(),
        minimized: None,
        warnings: Vec::new(),
        coverage: None,
        corpus: None,
    }
}

fn run_result_to_call_tool(result: &tooltest_core::RunResult) -> Result<CallToolResult, ErrorData> {
    run_result_to_call_tool_inner(result, serialize_value)
}

fn run_result_to_call_tool_inner<T: Serialize>(
    value: &T,
    serialize: fn(&T) -> Result<JsonValue, ErrorData>,
) -> Result<CallToolResult, ErrorData> {
    let value = serialize(value)?;
    Ok(CallToolResult::structured(value))
}

fn serialize_value<T: Serialize>(value: &T) -> Result<JsonValue, ErrorData> {
    serde_json::to_value(value).map_err(|error| {
        ErrorData::internal_error(format!("failed to serialize run result: {error}"), None)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        execute_tooltest, execute_tooltest_boxed, run_result_to_call_tool_inner, run_tooltest_call,
        serialize_value, tooltest_input_schema, tooltest_worker_inner, McpServer, NoopSink,
        TooltestWorker, TooltestWorkerConfig, WorkerReadyMode, TOOLTEST_FIX_LOOP_PROMPT,
        TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION, TOOLTEST_FIX_LOOP_PROMPT_NAME,
        TOOLTEST_FIX_LOOP_RESOURCE_URI, TOOLTEST_TOOL_DESCRIPTION, TOOLTEST_TOOL_NAME,
    };
    use axum::Router;
    use futures::SinkExt;
    use rmcp::model::AnnotateAble;
    use rmcp::model::{
        CallToolRequest, CallToolRequestParam, CallToolResult, ClientJsonRpcMessage, ClientRequest,
        EmptyResult, ErrorCode, GetPromptRequest, GetPromptRequestParam, JsonObject,
        ListPromptsRequest, ListResourcesRequest, ListToolsRequest, ListToolsResult,
        NumberOrString, PaginatedRequestParam, ReadResourceRequest, ReadResourceRequestParam,
        ServerJsonRpcMessage, ServerResult,
    };
    use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
    use rmcp::transport::Transport;
    use rmcp::transport::{
        streamable_http_server::session::local::LocalSessionManager, StreamableHttpServerConfig,
        StreamableHttpService,
    };
    use rmcp::ErrorData;
    use rmcp::RoleServer;
    use rmcp::ServerHandler;
    use serde::Serialize;
    use serde_json::{json, Value as JsonValue};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::sync::OnceLock;
    use tokio::sync::mpsc;
    use tooltest_core::{
        RunFailure, RunOutcome, RunResult, TooltestInput, TooltestStdioTarget, TooltestTarget,
        TooltestTargetStdio,
    };
    use tooltest_test_support::tool_with_schemas;

    struct TestTransport {
        incoming: mpsc::UnboundedReceiver<RxJsonRpcMessage<RoleServer>>,
        outgoing: mpsc::UnboundedSender<TxJsonRpcMessage<RoleServer>>,
    }

    impl Transport<RoleServer> for TestTransport {
        type Error = std::convert::Infallible;

        fn send(
            &mut self,
            item: TxJsonRpcMessage<RoleServer>,
        ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
            let _ = self.outgoing.send(item);
            std::future::ready(Ok(()))
        }

        fn receive(
            &mut self,
        ) -> impl std::future::Future<Output = Option<RxJsonRpcMessage<RoleServer>>> + Send
        {
            self.incoming.recv()
        }

        fn close(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
            std::future::ready(Ok(()))
        }
    }

    fn test_transport() -> (
        TestTransport,
        mpsc::UnboundedSender<RxJsonRpcMessage<RoleServer>>,
        mpsc::UnboundedReceiver<TxJsonRpcMessage<RoleServer>>,
    ) {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        (
            TestTransport {
                incoming: incoming_rx,
                outgoing: outgoing_tx,
            },
            incoming_tx,
            outgoing_rx,
        )
    }

    async fn send_request(request: ClientRequest) -> ServerJsonRpcMessage {
        let (transport, incoming_tx, mut outgoing_rx) = test_transport();
        let running = rmcp::service::serve_directly(McpServer::new(), transport, None);
        let message = ClientJsonRpcMessage::request(request, NumberOrString::Number(1));
        incoming_tx.send(message).expect("send");
        let response = outgoing_rx.recv().await.expect("response");
        let _ = running.cancel().await;
        drop(incoming_tx);
        response
    }

    fn list_tools_from_response(response: ServerJsonRpcMessage) -> Option<Vec<rmcp::model::Tool>> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::ListToolsResult(result) => Some(result.tools),
                _ => None,
            },
            _ => None,
        }
    }

    fn list_prompts_from_response(
        response: ServerJsonRpcMessage,
    ) -> Option<Vec<rmcp::model::Prompt>> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::ListPromptsResult(result) => Some(result.prompts),
                _ => None,
            },
            _ => None,
        }
    }

    fn get_prompt_from_response(
        response: ServerJsonRpcMessage,
    ) -> Option<rmcp::model::GetPromptResult> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::GetPromptResult(result) => Some(result),
                _ => None,
            },
            _ => None,
        }
    }

    fn list_resources_from_response(
        response: ServerJsonRpcMessage,
    ) -> Option<Vec<rmcp::model::Resource>> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::ListResourcesResult(result) => Some(result.resources),
                _ => None,
            },
            _ => None,
        }
    }

    fn read_resource_from_response(
        response: ServerJsonRpcMessage,
    ) -> Option<rmcp::model::ReadResourceResult> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::ReadResourceResult(result) => Some(result),
                _ => None,
            },
            _ => None,
        }
    }

    fn prompt_text_from_message(message: &rmcp::model::PromptMessage) -> Option<&str> {
        match &message.content {
            rmcp::model::PromptMessageContent::Text { text } => Some(text.as_str()),
            _ => None,
        }
    }

    fn resource_text_from_content(
        content: &rmcp::model::ResourceContents,
    ) -> Option<(&str, Option<&str>)> {
        match content {
            rmcp::model::ResourceContents::TextResourceContents {
                text, mime_type, ..
            } => Some((text.as_str(), mime_type.as_deref())),
            _ => None,
        }
    }

    fn schema_has_properties(schema: &JsonValue, keys: &[&str]) -> bool {
        if let Some(properties) = schema.get("properties").and_then(|value| value.as_object()) {
            return keys.iter().all(|key| properties.contains_key(*key));
        }
        for keyword in ["anyOf", "oneOf", "allOf"] {
            if let Some(items) = schema.get(keyword).and_then(|value| value.as_array()) {
                if items.iter().any(|item| schema_has_properties(item, keys)) {
                    return true;
                }
            }
        }
        false
    }

    #[tokio::test]
    async fn noop_sink_close_completes() {
        let mut sink = NoopSink;
        sink.close().await.expect("close");
    }

    #[tokio::test]
    async fn list_tools_includes_tooltest() {
        let response = send_request(ClientRequest::ListToolsRequest(ListToolsRequest {
            method: Default::default(),
            params: None,
            extensions: Default::default(),
        }))
        .await;
        let tools = list_tools_from_response(response).expect("list tools response");
        let tool = tools
            .iter()
            .find(|tool| tool.name.as_ref() == TOOLTEST_TOOL_NAME)
            .expect("tooltest tool");
        assert_eq!(tool.description.as_deref(), Some(TOOLTEST_TOOL_DESCRIPTION));
        assert!(!tool.input_schema.is_empty());
        let output_schema = tool.output_schema.as_ref().expect("output schema");
        assert!(!output_schema.is_empty());
    }

    #[tokio::test]
    async fn list_prompts_includes_fix_loop() {
        let response = send_request(ClientRequest::ListPromptsRequest(ListPromptsRequest {
            method: Default::default(),
            params: Some(PaginatedRequestParam { cursor: None }),
            extensions: Default::default(),
        }))
        .await;
        let prompts = list_prompts_from_response(response).expect("list prompts response");
        let prompt = prompts
            .iter()
            .find(|prompt| prompt.name == TOOLTEST_FIX_LOOP_PROMPT_NAME)
            .expect("prompt");
        assert_eq!(
            prompt.description.as_deref(),
            Some(TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION)
        );
    }

    #[tokio::test]
    async fn get_prompt_returns_fix_loop_literal() {
        let response = send_request(ClientRequest::GetPromptRequest(GetPromptRequest {
            method: Default::default(),
            params: GetPromptRequestParam {
                name: TOOLTEST_FIX_LOOP_PROMPT_NAME.to_string(),
                arguments: None,
            },
            extensions: Default::default(),
        }))
        .await;
        let result = get_prompt_from_response(response).expect("get prompt response");
        let message = result.messages.first().expect("prompt message");
        let text = prompt_text_from_message(message).expect("text prompt content");
        assert_eq!(text, TOOLTEST_FIX_LOOP_PROMPT);
    }

    #[tokio::test]
    async fn list_resources_includes_fix_loop() {
        let response = send_request(ClientRequest::ListResourcesRequest(ListResourcesRequest {
            method: Default::default(),
            params: Some(PaginatedRequestParam { cursor: None }),
            extensions: Default::default(),
        }))
        .await;
        let resources = list_resources_from_response(response).expect("list resources response");
        let resource = resources
            .iter()
            .find(|resource| resource.uri == TOOLTEST_FIX_LOOP_RESOURCE_URI)
            .expect("resource");
        assert_eq!(resource.mime_type.as_deref(), Some("text/plain"));
    }

    #[tokio::test]
    async fn read_resource_returns_fix_loop_text() {
        let response = send_request(ClientRequest::ReadResourceRequest(ReadResourceRequest {
            method: Default::default(),
            params: ReadResourceRequestParam {
                uri: TOOLTEST_FIX_LOOP_RESOURCE_URI.to_string(),
            },
            extensions: Default::default(),
        }))
        .await;
        let result = read_resource_from_response(response).expect("read resource response");
        let content = result.contents.first().expect("resource content");
        let (text, mime_type) = resource_text_from_content(content).expect("text content");
        assert_eq!(mime_type, Some("text/plain"));
        assert_eq!(text, TOOLTEST_FIX_LOOP_PROMPT);
    }

    #[tokio::test]
    async fn get_prompt_unknown_returns_error() {
        let response = send_request(ClientRequest::GetPromptRequest(GetPromptRequest {
            method: Default::default(),
            params: GetPromptRequestParam {
                name: "unknown".to_string(),
                arguments: None,
            },
            extensions: Default::default(),
        }))
        .await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn read_resource_unknown_returns_error() {
        let response = send_request(ClientRequest::ReadResourceRequest(ReadResourceRequest {
            method: Default::default(),
            params: ReadResourceRequestParam {
                uri: "tooltest://guides/unknown".to_string(),
            },
            extensions: Default::default(),
        }))
        .await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::RESOURCE_NOT_FOUND);
    }

    #[tokio::test]
    async fn response_helpers_return_none_for_errors() {
        let response = ServerJsonRpcMessage::error(
            rmcp::ErrorData::invalid_params("boom", None),
            NumberOrString::Number(1),
        );
        assert!(list_tools_from_response(response.clone()).is_none());
        assert!(list_prompts_from_response(response.clone()).is_none());
        assert!(get_prompt_from_response(response.clone()).is_none());
        assert!(list_resources_from_response(response.clone()).is_none());
        assert!(read_resource_from_response(response).is_none());
    }

    #[tokio::test]
    async fn response_helpers_return_none_for_unexpected_results() {
        let response = ServerJsonRpcMessage::response(
            ServerResult::EmptyResult(EmptyResult {}),
            NumberOrString::Number(2),
        );
        assert!(list_tools_from_response(response.clone()).is_none());
        assert!(list_prompts_from_response(response.clone()).is_none());
        assert!(get_prompt_from_response(response.clone()).is_none());
        assert!(list_resources_from_response(response.clone()).is_none());
        assert!(read_resource_from_response(response).is_none());
    }

    #[test]
    fn prompt_text_from_message_returns_none_for_non_text() {
        let resource =
            rmcp::model::RawResource::new("tooltest://example", "example").no_annotation();
        let message = rmcp::model::PromptMessage {
            role: rmcp::model::PromptMessageRole::User,
            content: rmcp::model::PromptMessageContent::ResourceLink { link: resource },
        };
        assert!(prompt_text_from_message(&message).is_none());
    }

    #[test]
    fn resource_text_from_content_returns_none_for_blob() {
        let content = rmcp::model::ResourceContents::BlobResourceContents {
            uri: "tooltest://example".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            blob: "deadbeef".to_string(),
            meta: None,
        };
        assert!(resource_text_from_content(&content).is_none());
    }

    fn tooltest_server_env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn tooltest_server_command_locked() -> String {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_tooltest_test_server") {
            return path;
        }
        #[cfg(windows)]
        let exe_name = "tooltest_test_server.exe";
        #[cfg(not(windows))]
        let exe_name = "tooltest_test_server";
        let current = std::env::current_exe().expect("current exe");
        let dir = current
            .parent()
            .and_then(|parent| parent.parent())
            .expect("test binary directory");
        let candidate = dir.join(exe_name);
        std::fs::metadata(&candidate).expect("tooltest_test_server missing");
        candidate.to_string_lossy().to_string()
    }

    fn tooltest_server_command() -> String {
        let _guard = tooltest_server_env_lock().lock().expect("server env lock");
        tooltest_server_command_locked()
    }

    struct EnvVarGuard {
        key: &'static str,
        value: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self {
                key,
                value: previous,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.value {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn stdio_env() -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("LLVM_PROFILE_FILE".to_string(), "/dev/null".to_string());
        env.insert(
            "TOOLTEST_TEST_SERVER_ALLOW_STDIN".to_string(),
            "1".to_string(),
        );
        env
    }

    fn env_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn minimal_tooltest_input() -> TooltestInput {
        let stdio = TooltestStdioTarget {
            command: "noop".to_string(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
        };
        let target = TooltestTarget::Stdio(TooltestTargetStdio { stdio });
        TooltestInput {
            target,
            cases: 1,
            min_sequence_len: 1,
            max_sequence_len: 1,
            lenient_sourcing: false,
            mine_text: false,
            dump_corpus: false,
            log_corpus_deltas: false,
            no_lenient_sourcing: false,
            state_machine_config: None,
            tool_allowlist: Vec::new(),
            tool_blocklist: Vec::new(),
            in_band_error_forbidden: false,
            pre_run_hook: None,
            full_trace: false,
            show_uncallable: false,
            uncallable_limit: 1,
        }
    }

    async fn send_call_tool_request_with_name_unlocked(
        name: &str,
        arguments: Option<JsonObject>,
    ) -> ServerJsonRpcMessage {
        let (transport, incoming_tx, mut outgoing_rx) = test_transport();
        let running = rmcp::service::serve_directly(McpServer::new(), transport, None);
        let message = ClientJsonRpcMessage::request(
            ClientRequest::CallToolRequest(CallToolRequest {
                method: Default::default(),
                params: CallToolRequestParam {
                    name: name.to_string().into(),
                    arguments,
                },
                extensions: Default::default(),
            }),
            NumberOrString::Number(1),
        );
        incoming_tx.send(message).expect("send");
        let response = outgoing_rx.recv().await.expect("response");
        let _ = running.cancel().await;
        drop(incoming_tx);
        response
    }

    async fn send_call_tool_request_with_name(
        name: &str,
        arguments: Option<JsonObject>,
    ) -> ServerJsonRpcMessage {
        let _guard = env_lock().lock().await;
        send_call_tool_request_with_name_unlocked(name, arguments).await
    }

    async fn send_call_tool_request(arguments: Option<JsonObject>) -> ServerJsonRpcMessage {
        send_call_tool_request_with_name(TOOLTEST_TOOL_NAME, arguments).await
    }

    async fn send_http_test_server_call(name: &str) -> ServerJsonRpcMessage {
        let (transport, incoming_tx, mut outgoing_rx) = test_transport();
        let running = rmcp::service::serve_directly(HttpTestServer::new(), transport, None);
        let message = ClientJsonRpcMessage::request(
            ClientRequest::CallToolRequest(CallToolRequest {
                method: Default::default(),
                params: CallToolRequestParam {
                    name: name.to_string().into(),
                    arguments: None,
                },
                extensions: Default::default(),
            }),
            NumberOrString::Number(1),
        );
        incoming_tx.send(message).expect("send");
        let response = outgoing_rx.recv().await.expect("response");
        let _ = running.cancel().await;
        drop(incoming_tx);
        response
    }

    fn call_tool_result_from_response(response: ServerJsonRpcMessage) -> Option<CallToolResult> {
        match response {
            ServerJsonRpcMessage::Response(response) => match response.result {
                ServerResult::CallToolResult(result) => Some(result),
                _ => None,
            },
            _ => None,
        }
    }

    fn run_result_from_tool_result(result: CallToolResult) -> RunResult {
        let structured = result.structured_content.expect("structured content");
        serde_json::from_value(structured).expect("run result")
    }

    fn outcome_is_failure(outcome: &RunOutcome) -> bool {
        matches!(outcome, RunOutcome::Failure(_))
    }

    fn expect_failure(outcome: RunOutcome) -> RunFailure {
        match outcome {
            RunOutcome::Failure(failure) => failure,
            RunOutcome::Success => panic!("expected failure outcome"),
        }
    }

    struct BrokenSerialize;

    impl Serialize for BrokenSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("boom"))
        }
    }

    #[tokio::test]
    async fn run_tooltest_call_reports_worker_error() {
        let input = minimal_tooltest_input();
        let error = run_tooltest_call(Err(ErrorData::internal_error("boom", None)), input)
            .await
            .expect_err("expected error");
        assert_eq!(error.code, ErrorCode::INTERNAL_ERROR);
        assert!(error.message.contains("boom"));
    }

    #[tokio::test]
    async fn run_tooltest_call_reports_send_error() {
        let (sender, receiver) = mpsc::unbounded_channel();
        drop(receiver);
        let (_done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = TooltestWorker {
            sender,
            done: std::sync::Mutex::new(done_rx),
        };
        let input = minimal_tooltest_input();
        let error = run_tooltest_call(Ok(&worker), input)
            .await
            .expect_err("expected error");
        assert_eq!(error.code, ErrorCode::INTERNAL_ERROR);
        assert!(error.message.contains("tooltest tool execution failed"));
    }

    #[tokio::test]
    async fn run_tooltest_call_reports_response_canceled() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let (_done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = TooltestWorker {
            sender,
            done: std::sync::Mutex::new(done_rx),
        };
        let input = minimal_tooltest_input();
        let handle = tokio::spawn(async move {
            let work = receiver.recv().await.expect("work");
            drop(work);
        });
        let error = run_tooltest_call(Ok(&worker), input)
            .await
            .expect_err("expected error");
        handle.await.expect("worker task");
        assert_eq!(error.code, ErrorCode::INTERNAL_ERROR);
        assert!(error.message.contains("tooltest tool execution failed"));
    }

    #[tokio::test]
    async fn run_tooltest_call_reports_response_error() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let (_done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = TooltestWorker {
            sender,
            done: std::sync::Mutex::new(done_rx),
        };
        let input = minimal_tooltest_input();
        let handle = tokio::spawn(async move {
            let work = receiver.recv().await.expect("work");
            let _ = work
                .respond_to
                .send(Err(ErrorData::internal_error("boom", None)));
        });
        let error = run_tooltest_call(Ok(&worker), input)
            .await
            .expect_err("expected error");
        handle.await.expect("worker task");
        assert_eq!(error.code, ErrorCode::INTERNAL_ERROR);
        assert!(error.message.contains("boom"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn call_tool_runs_stdio_smoke() {
        let server = tooltest_server_command();
        let args = json!({
            "target": { "stdio": { "command": server, "env": stdio_env() } },
            "cases": 50,
            "min_sequence_len": 1,
            "max_sequence_len": 1,
            "no_lenient_sourcing": true
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let result = call_tool_result_from_response(response).expect("call tool result");
        assert_eq!(result.is_error, Some(false));
        let run_result = run_result_from_tool_result(result);
        assert!(!outcome_is_failure(&run_result.outcome));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn call_tool_runs_http_target() {
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

        let args = json!({
            "target": { "http": { "url": format!("http://{addr}/mcp") } },
            "cases": 1,
            "min_sequence_len": 1,
            "max_sequence_len": 1,
            "lenient_sourcing": true
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let result = call_tool_result_from_response(response).expect("call tool result");
        assert_eq!(result.is_error, Some(false));
        let run_result = run_result_from_tool_result(result);

        let _ = shutdown_tx.send(());
        let _ = server.await;

        let _ = run_result.outcome;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn call_tool_returns_failure_outcome_on_tool_error() {
        let server = tooltest_server_command();
        let mut env = stdio_env();
        env.insert(
            "TOOLTEST_TEST_SERVER_CALL_ERROR".to_string(),
            "1".to_string(),
        );
        let args = json!({
            "target": { "stdio": { "command": server, "env": env } },
            "cases": 1,
            "min_sequence_len": 1,
            "max_sequence_len": 1,
            "in_band_error_forbidden": true
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let result = call_tool_result_from_response(response).expect("call tool result");
        let run_result = run_result_from_tool_result(result);
        assert!(outcome_is_failure(&run_result.outcome));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn call_tool_returns_failure_outcome_on_connection_error() {
        let args = json!({
            "target": { "http": { "url": "http://127.0.0.1:0/mcp" } },
            "cases": 1,
            "min_sequence_len": 1,
            "max_sequence_len": 1
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let result = call_tool_result_from_response(response).expect("call tool result");
        let run_result = run_result_from_tool_result(result);
        assert!(outcome_is_failure(&run_result.outcome));
    }

    #[tokio::test]
    async fn call_tool_invalid_input_missing_target_is_error() {
        let args = json!({
            "cases": 1
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn call_tool_invalid_input_top_level_stdio_is_error() {
        let args = json!({
            "stdio": { "command": "server" }
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn call_tool_invalid_input_cli_only_field_is_error() {
        let args = json!({
            "target": { "http": { "url": "http://127.0.0.1:0/mcp" } },
            "json": true
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn call_tool_invalid_input_trace_all_field_is_error() {
        let args = json!({
            "target": { "http": { "url": "http://127.0.0.1:0/mcp" } },
            "trace_all": "/tmp/tooltest-traces.jsonl"
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn call_tool_missing_arguments_is_error() {
        let response = send_call_tool_request(None).await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn call_tool_unknown_name_is_error() {
        let response = send_call_tool_request_with_name("unknown", None).await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn call_tool_returns_structured_content_and_json_content() {
        let args = json!({
            "target": { "http": { "url": "http://127.0.0.1:0/mcp" } },
            "cases": 1,
            "min_sequence_len": 1,
            "max_sequence_len": 1
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let result = call_tool_result_from_response(response).expect("call tool result");
        let structured = result.structured_content.expect("structured content");
        let content = result.content.first().expect("content");
        let text = content.as_text().expect("text content").text.as_str();
        let text_value: JsonValue = serde_json::from_str(text).expect("json content");
        assert_eq!(structured, text_value);
        assert_eq!(result.is_error, Some(false));
    }

    #[tokio::test]
    async fn run_tooltest_call_tool_panic_is_internal_error() {
        let _lock = env_lock().lock().await;
        fn panic_execute(_input: TooltestInput) -> super::TooltestExecuteFuture {
            Box::pin(async move {
                panic!("boom");
            })
        }

        let worker =
            TooltestWorker::new_with_config(TooltestWorkerConfig::default(), panic_execute)
                .expect("worker");
        let error = run_tooltest_call(Ok(&worker), minimal_tooltest_input())
            .await
            .expect_err("expected error");
        assert_eq!(error.code, ErrorCode::INTERNAL_ERROR);
        assert!(error.message.contains("tooltest tool panicked"));
    }

    #[tokio::test]
    async fn call_tool_invalid_config_returns_error() {
        let args = json!({
            "target": { "http": { "url": "http://127.0.0.1:0/mcp" } },
            "uncallable_limit": 0
        });
        let response =
            send_call_tool_request(Some(args.as_object().cloned().expect("args object"))).await;
        let result = call_tool_result_from_response(response).expect("call tool result");
        let run_result = run_result_from_tool_result(result);
        assert!(outcome_is_failure(&run_result.outcome));
    }

    #[test]
    fn call_tool_result_from_response_returns_none_for_unexpected() {
        let response = ServerJsonRpcMessage::response(
            ServerResult::EmptyResult(EmptyResult {}),
            NumberOrString::Number(3),
        );
        assert!(call_tool_result_from_response(response).is_none());
        let error = ServerJsonRpcMessage::error(
            rmcp::ErrorData::invalid_params("boom", None),
            NumberOrString::Number(4),
        );
        assert!(call_tool_result_from_response(error).is_none());
    }

    #[test]
    fn env_var_guard_restores_existing_value() {
        let key = "TOOLTEST_MCP_ENV_GUARD";
        std::env::set_var(key, "before");
        {
            let _guard = EnvVarGuard::set(key, "after");
        }
        assert_eq!(std::env::var(key).ok().as_deref(), Some("before"));
        std::env::remove_var(key);
    }

    #[tokio::test]
    async fn tooltest_worker_reports_forced_runtime_error() {
        let _lock = env_lock().lock().await;
        fn forced_runtime_error() -> Result<tokio::runtime::Runtime, std::io::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "forced runtime error",
            ))
        }
        let config = TooltestWorkerConfig {
            ready_mode: WorkerReadyMode::Send,
            build_runtime: forced_runtime_error,
        };
        let error = TooltestWorker::new_with_config(config, execute_tooltest_boxed)
            .err()
            .expect("expected error");
        assert!(error.contains("forced runtime error"));
    }

    #[tokio::test]
    async fn tooltest_worker_reports_ready_channel_failure() {
        let _lock = env_lock().lock().await;
        let config = TooltestWorkerConfig {
            ready_mode: WorkerReadyMode::Skip,
            ..TooltestWorkerConfig::default()
        };
        let error = TooltestWorker::new_with_config(config, execute_tooltest_boxed)
            .err()
            .expect("expected error");
        assert!(error.contains("failed to start"));
    }

    #[test]
    fn tooltest_worker_inner_reports_cached_error() {
        let worker = OnceLock::new();
        let _ = worker.get_or_init(|| Err("boom".to_string()));
        let error = tooltest_worker_inner(&worker)
            .err()
            .expect("expected error");
        assert!(error.message.contains("failed to start tooltest runtime"));
    }

    #[tokio::test]
    async fn tooltest_worker_thread_exits_when_sender_dropped() {
        let _lock = env_lock().lock().await;
        let TooltestWorker { sender, done } = TooltestWorker::new().expect("worker");
        drop(sender);
        tokio::task::spawn_blocking(move || {
            done.lock().expect("lock").recv().expect("done");
        })
        .await
        .expect("join");
    }

    #[test]
    fn tooltest_server_command_prefers_env_var() {
        let _lock = tooltest_server_env_lock().lock().expect("server env lock");
        let _guard = EnvVarGuard::set("CARGO_BIN_EXE_tooltest_test_server", "/tmp/override");
        let command = tooltest_server_command_locked();
        assert_eq!(command, "/tmp/override");
    }

    fn assert_target_branches(has_stdio: bool, has_http: bool) {
        assert!(has_stdio, "target anyOf missing stdio branch");
        assert!(has_http, "target anyOf missing http branch");
    }

    #[test]
    fn tooltest_input_schema_inlines_nested_types() {
        let _lock = tooltest_server_env_lock().lock().expect("server env lock");
        std::env::remove_var("TOOLTEST_MCP_DOGFOOD_COMMAND");
        let schema = tooltest_input_schema();
        let schema_value = JsonValue::Object(schema.as_ref().clone());
        let target = &schema_value["properties"]["target"];
        let any_of = target
            .get("anyOf")
            .and_then(|value| value.as_array())
            .expect("target anyOf");
        let mut has_stdio = false;
        let mut has_http = false;
        for branch in any_of {
            if schema_has_properties(branch, &["stdio"]) {
                has_stdio = true;
            }
            if schema_has_properties(branch, &["http"]) {
                has_http = true;
            }
        }
        assert_target_branches(has_stdio, has_http);
        let state_machine = &schema_value["properties"]["state_machine_config"];
        assert!(schema_has_properties(
            state_machine,
            &["seed_numbers", "seed_strings"]
        ));
    }

    #[test]
    #[should_panic(expected = "target anyOf missing stdio branch")]
    fn assert_target_branches_panics_on_missing_stdio() {
        assert_target_branches(false, true);
    }

    #[test]
    #[should_panic(expected = "target anyOf missing http branch")]
    fn assert_target_branches_panics_on_missing_http() {
        assert_target_branches(true, false);
    }

    #[test]
    fn schema_has_properties_traverses_unions() {
        let schema = json!({
            "anyOf": [
                { "type": "object", "properties": { "alpha": { "type": "string" } } },
                { "type": "object", "properties": { "bravo": { "type": "string" } } }
            ]
        });
        assert!(schema_has_properties(&schema, &["bravo"]));
        assert!(!schema_has_properties(&schema, &["charlie"]));
    }

    #[tokio::test]
    async fn execute_tooltest_applies_dogfood_overrides() {
        let _lock = env_lock().lock().await;
        let _guard = EnvVarGuard::set("TOOLTEST_MCP_DOGFOOD_COMMAND", "");
        let input = minimal_tooltest_input();
        let result = execute_tooltest(input).await.expect("run result");
        assert!(outcome_is_failure(&result.outcome));
        let failure = expect_failure(result.outcome);
        assert!(failure.reason.contains("stdio command"));
    }

    #[test]
    #[should_panic(expected = "expected failure outcome")]
    fn expect_failure_panics_on_success() {
        let _ = expect_failure(RunOutcome::Success);
    }

    #[test]
    fn serialize_value_reports_error_for_failing_serializer() {
        let error = serialize_value(&BrokenSerialize).expect_err("serialize error");
        assert_eq!(error.code, ErrorCode::INTERNAL_ERROR);
    }

    #[test]
    fn outcome_helpers_cover_both_paths() {
        let success = std::hint::black_box(RunOutcome::Success);
        let failure = std::hint::black_box(RunOutcome::Failure(RunFailure::new("boom")));
        assert!(!outcome_is_failure(&success));
        assert!(outcome_is_failure(&failure));
    }

    #[tokio::test]
    async fn run_result_to_call_tool_propagates_serialize_error() {
        let run_result = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
            corpus: None,
        };
        let error = run_result_to_call_tool_inner(&run_result, |_| {
            Err(ErrorData::internal_error("forced serialize error", None))
        })
        .expect_err("serialize error");
        assert_eq!(error.code, ErrorCode::INTERNAL_ERROR);
        assert!(error.message.contains("forced serialize error"));
    }

    #[tokio::test]
    async fn http_test_server_rejects_unknown_tool() {
        let response = send_http_test_server_call("unknown").await;
        let (error, _) = response.into_error().expect("error response");
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn http_test_server_accepts_echo_tool() {
        let response = send_http_test_server_call("echo").await;
        let result = call_tool_result_from_response(response).expect("call tool result");
        assert_eq!(result.is_error, Some(false));
    }

    #[derive(Clone)]
    struct HttpTestServer {
        tool: rmcp::model::Tool,
    }

    impl HttpTestServer {
        fn new() -> Self {
            let input_schema = json!({
                "type": "object",
                "properties": {
                    "value": { "type": "string" }
                },
                "required": ["value"]
            });
            let output_schema = json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string", "const": "ok" }
                },
                "required": ["status"]
            });
            Self {
                tool: tool_with_schemas("echo", input_schema, Some(output_schema)),
            }
        }
    }

    impl ServerHandler for HttpTestServer {
        fn list_tools(
            &self,
            _request: Option<PaginatedRequestParam>,
            _context: rmcp::service::RequestContext<RoleServer>,
        ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_
        {
            std::future::ready(Ok(ListToolsResult {
                tools: vec![self.tool.clone()],
                ..Default::default()
            }))
        }

        fn call_tool(
            &self,
            request: CallToolRequestParam,
            _context: rmcp::service::RequestContext<RoleServer>,
        ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_
        {
            let name = request.name;
            std::future::ready(if name.as_ref() == "echo" {
                Ok(CallToolResult::structured(json!({ "status": "ok" })))
            } else {
                Err(rmcp::ErrorData::invalid_params(
                    format!("tool '{name}' not found"),
                    None,
                ))
            })
        }
    }
}

pub async fn run_stdio() -> Result<(), String> {
    let exit_immediately = exit_immediately();
    let service = if use_test_transport() {
        let transport = if std::env::var_os("TOOLTEST_MCP_BAD_TRANSPORT").is_some() {
            stdio_bad_transport()
        } else if std::env::var_os("TOOLTEST_MCP_PANIC_TRANSPORT").is_some() {
            stdio_panic_transport()
        } else {
            stdio_test_transport()
        };
        McpServer::new()
            .serve(transport)
            .await
            .map_err(|error| format!("failed to start MCP stdio server: {error}"))?
    } else {
        McpServer::new()
            .serve(stdio())
            .await
            .map_err(|error| format!("failed to start MCP stdio server: {error}"))?
    };
    if exit_immediately {
        if std::env::var_os("TOOLTEST_MCP_PANIC_TRANSPORT").is_some() {
            tokio::task::yield_now().await;
        }
        service
            .cancel()
            .await
            .map_err(|error| format!("MCP stdio server failed: {error}"))?;
        return Ok(());
    }
    service
        .waiting()
        .await
        .map_err(|error| format!("MCP stdio server failed: {error}"))?;
    Ok(())
}

// HTTP transport for tooltest MCP server intentionally removed; use stdio only.
