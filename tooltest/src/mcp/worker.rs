use futures::FutureExt;
use rmcp::model::CallToolResult;
use rmcp::ErrorData;
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::OnceLock;
use tooltest_core::{
    RunFailure, RunOutcome, RunResult, TooltestInput, TooltestRunConfig, TooltestStdioTarget,
    TooltestTarget, TooltestTargetConfig, TooltestTargetStdio,
};

pub(super) struct TooltestWork {
    input: TooltestInput,
    pub(super) respond_to:
        tokio::sync::oneshot::Sender<Result<tooltest_core::RunResult, ErrorData>>,
}

pub(super) struct TooltestWorker {
    pub(super) sender: tokio::sync::mpsc::UnboundedSender<TooltestWork>,
    #[cfg(test)]
    pub(super) done: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

pub(super) type TooltestExecuteFuture = Pin<
    Box<dyn std::future::Future<Output = Result<tooltest_core::RunResult, ErrorData>> + 'static>,
>;
pub(super) type TooltestExecuteFn = fn(TooltestInput) -> TooltestExecuteFuture;

fn build_worker_runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
}

pub(super) fn execute_tooltest_boxed(input: TooltestInput) -> TooltestExecuteFuture {
    Box::pin(execute_tooltest(input))
}

impl TooltestWorker {
    pub(super) fn new() -> Result<Self, String> {
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
pub(super) enum WorkerReadyMode {
    Send,
    Skip,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct TooltestWorkerConfig {
    pub(super) ready_mode: WorkerReadyMode,
    pub(super) build_runtime: fn() -> Result<tokio::runtime::Runtime, std::io::Error>,
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
    pub(super) fn new_with_config(
        config: TooltestWorkerConfig,
        execute: TooltestExecuteFn,
    ) -> Result<Self, String> {
        let skip_ready = matches!(config.ready_mode, WorkerReadyMode::Skip);
        Self::new_with_parts(config.build_runtime, skip_ready, execute)
    }
}

pub(super) fn tooltest_worker_inner(
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

static WORKER: OnceLock<Result<TooltestWorker, String>> = OnceLock::new();

pub(super) async fn tooltest_worker() -> Result<&'static TooltestWorker, ErrorData> {
    if WORKER.get().is_none() {
        tokio::task::spawn_blocking(|| {
            let _ = tooltest_worker_inner(&WORKER);
        })
        .await
        .expect("tooltest worker init task panicked");
    }

    tooltest_worker_inner(&WORKER)
}

pub(super) async fn run_tooltest_call(
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

pub(super) fn run_result_to_call_tool_inner<T: Serialize>(
    value: &T,
    serialize: fn(&T) -> Result<JsonValue, ErrorData>,
) -> Result<CallToolResult, ErrorData> {
    let value = serialize(value)?;
    Ok(CallToolResult::structured(value))
}

pub(super) fn serialize_value<T: Serialize>(value: &T) -> Result<JsonValue, ErrorData> {
    serde_json::to_value(value).map_err(|error| {
        ErrorData::internal_error(format!("failed to serialize run result: {error}"), None)
    })
}

pub(super) async fn execute_tooltest(
    input: TooltestInput,
) -> Result<tooltest_core::RunResult, ErrorData> {
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
