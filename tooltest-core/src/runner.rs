//! MCP sequence runner with default and declarative assertions.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::rc::Rc;

use jsonschema::{draft201909, draft202012, draft4, draft6, draft7, Validator};
use proptest::test_runner::{Config as ProptestConfig, TestCaseError, TestError, TestRunner};
use rmcp::model::{CallToolResult, ListToolsResult, Tool};
use serde_json::{json, Number, Value as JsonValue};

use crate::generator::{
    invocation_from_seed, invocation_sequence_strategy, state_machine_sequence_strategy,
    uncallable_reason, StateMachineSeed, UncallableReason, ValueCorpus,
};
use crate::schema::parse_list_tools;
use crate::{
    AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CorpusReport, CoverageReport,
    CoverageRule, CoverageWarning, CoverageWarningReason, GeneratorMode, HttpConfig, JsonObject,
    MinimizedSequence, RunConfig, RunFailure, RunOutcome, RunResult, RunWarning, RunWarningCode,
    SessionDriver, StdioConfig, ToolInvocation, TraceEntry,
};

/// Configuration for proptest-driven run behavior.
#[derive(Clone, Debug)]
pub struct RunnerOptions {
    /// Number of proptest cases to execute.
    pub cases: u32,
    /// Range of invocation counts per generated sequence.
    pub sequence_len: RangeInclusive<usize>,
}

impl Default for RunnerOptions {
    fn default() -> Self {
        Self {
            cases: 32,
            sequence_len: 1..=3,
        }
    }
}

/// Execute a tooltest run using a pre-initialized session.
///
/// Runs apply default assertions that fail on error responses and validate
/// structured output against declared output schemas, plus any user-supplied
/// assertion rules.
///
/// Requires a multi-thread Tokio runtime; current-thread runtimes are rejected.
pub async fn run_with_session(
    session: &SessionDriver,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    let prelude_trace = Rc::new(vec![TraceEntry::list_tools()]);
    let tools = match session.list_tools().await {
        Ok(tools) => tools,
        Err(error) => {
            let reason = format!("failed to list tools: {error:?}");
            return failure_result(
                RunFailure::new(reason.clone()),
                vec![TraceEntry::list_tools_with_failure(reason)],
                None,
                Vec::new(),
                None,
                None,
            );
        }
    };

    let tools = match validate_tools(tools, &config.schema) {
        Ok(tools) => tools,
        Err(reason) => {
            return failure_result(
                RunFailure::new(reason),
                prelude_trace.as_ref().clone(),
                None,
                Vec::new(),
                None,
                None,
            )
        }
    };
    let warnings = collect_schema_warnings(&tools);

    let output_validators = match build_output_validators(&tools) {
        Ok(validators) => validators,
        Err(reason) => {
            return failure_result(
                RunFailure::new(reason),
                prelude_trace.as_ref().clone(),
                None,
                warnings,
                None,
                None,
            )
        }
    };
    let input_validators = match build_input_validators(&tools) {
        Ok(validators) => validators,
        Err(reason) => {
            return failure_result(
                RunFailure::new(reason),
                prelude_trace.as_ref().clone(),
                None,
                warnings,
                None,
                None,
            )
        }
    };

    let assertions = config.assertions.clone();
    let aggregate_tools = tools.clone();
    let aggregate_tracker: Rc<RefCell<CoverageTracker<'_>>> = Rc::new(RefCell::new(
        CoverageTracker::new(&aggregate_tools, &config.state_machine),
    ));
    let last_trace: Rc<RefCell<Vec<TraceEntry>>> = Rc::new(RefCell::new(Vec::new()));
    last_trace.replace(prelude_trace.as_ref().clone());
    let last_coverage: Rc<RefCell<Option<CoverageReport>>> = Rc::new(RefCell::new(None));
    let last_corpus: Rc<RefCell<Option<CorpusReport>>> = Rc::new(RefCell::new(None));
    let last_failure = Rc::new(RefCell::new(FailureContext {
        failure: RunFailure::new(String::new()),
        trace: Vec::new(),
        invocations: Vec::new(),
        coverage: None,
        corpus: None,
    }));
    let handle = tokio::runtime::Handle::current();
    if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
        return failure_result(
            RunFailure::new("run_with_session requires a multi-thread Tokio runtime".to_string()),
            Vec::new(),
            None,
            warnings.clone(),
            None,
            None,
        );
    }
    let warnings = Rc::new(warnings);
    let output_validators = Rc::new(output_validators);
    let input_validators = Rc::new(input_validators);

    let mut runner = TestRunner::new(ProptestConfig {
        cases: options.cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    });

    let run_result = match config.generator_mode {
        GeneratorMode::Legacy => {
            let strategy = match invocation_sequence_strategy(
                &tools,
                config.predicate.as_ref(),
                options.sequence_len.clone(),
            ) {
                Ok(strategy) => strategy,
                Err(error) => {
                    return failure_result(
                        RunFailure::new(error.to_string()),
                        prelude_trace.as_ref().clone(),
                        None,
                        warnings.as_ref().clone(),
                        None,
                        None,
                    )
                }
            };
            let run_result = runner.run(&strategy, {
                let assertions = assertions.clone();
                let last_trace = last_trace.clone();
                let last_coverage = last_coverage.clone();
                let last_corpus = last_corpus.clone();
                let last_failure = last_failure.clone();
                let output_validators = output_validators.clone();
                let input_validators = input_validators.clone();
                let aggregate_tracker = aggregate_tracker.clone();
                move |sequence| {
                    let execution: Result<Vec<TraceEntry>, FailureContext> =
                        tokio::task::block_in_place(|| {
                            let last_coverage = last_coverage.clone();
                            let last_corpus = last_corpus.clone();
                            handle.block_on(async {
                                let mut tracker =
                                    CoverageTracker::new(&tools, &config.state_machine);
                                let result = execute_sequence_with_coverage(
                                    session,
                                    &input_validators,
                                    &output_validators,
                                    &assertions,
                                    &sequence,
                                    &mut tracker,
                                )
                                .await;
                                let (report, corpus_report) = {
                                    let mut aggregate = aggregate_tracker.borrow_mut();
                                    aggregate.merge_from(&tracker);
                                    let report = aggregate.report();
                                    let corpus_report = if config.state_machine.dump_corpus {
                                        Some(aggregate.corpus_report())
                                    } else {
                                        None
                                    };
                                    (report, corpus_report)
                                };
                                last_coverage.replace(Some(report.clone()));
                                last_corpus.replace(corpus_report.clone());
                                match result {
                                    Ok(trace) => Ok(trace),
                                    Err(mut failure) => {
                                        failure.coverage = Some(report);
                                        failure.corpus = corpus_report;
                                        Err(failure)
                                    }
                                }
                            })
                        });
                    match execution {
                        Ok(trace) => {
                            let mut full_trace = prelude_trace.as_ref().clone();
                            full_trace.extend(trace);
                            last_trace.replace(full_trace);
                            Ok(())
                        }
                        Err(mut failure) => {
                            let mut full_trace = prelude_trace.as_ref().clone();
                            full_trace.extend(failure.trace);
                            failure.trace = full_trace;
                            last_failure.replace(failure.clone());
                            Err(TestCaseError::fail(failure.failure.reason.clone()))
                        }
                    }
                }
            });
            finalize_run_result(
                run_result,
                &last_trace,
                &last_failure,
                &last_coverage,
                &last_corpus,
                warnings.as_ref(),
            )
        }
        GeneratorMode::StateMachine => {
            let strategy = match state_machine_sequence_strategy(
                &tools,
                config.predicate.as_ref(),
                &config.state_machine,
                options.sequence_len.clone(),
            ) {
                Ok(strategy) => strategy,
                Err(error) => {
                    return failure_result(
                        RunFailure::new(error.to_string()),
                        prelude_trace.as_ref().clone(),
                        None,
                        warnings.as_ref().clone(),
                        None,
                        None,
                    )
                }
            };
            let run_result = runner.run(&strategy, {
                let assertions = assertions.clone();
                let last_trace = last_trace.clone();
                let last_coverage = last_coverage.clone();
                let last_corpus = last_corpus.clone();
                let last_failure = last_failure.clone();
                let output_validators = output_validators.clone();
                let input_validators = input_validators.clone();
                let predicate = config.predicate.clone();
                let min_len = *options.sequence_len.start();
                let aggregate_tracker = aggregate_tracker.clone();
                move |seeds| {
                    let execution: Result<StateMachineExecution, FailureContext> =
                        tokio::task::block_in_place(|| {
                            let last_coverage = last_coverage.clone();
                            let last_corpus = last_corpus.clone();
                            handle.block_on(async {
                                let mut tracker =
                                    CoverageTracker::new(&tools, &config.state_machine);
                                let result = execute_state_machine_sequence_with_coverage(
                                    session,
                                    &input_validators,
                                    &output_validators,
                                    &assertions,
                                    &seeds,
                                    &tools,
                                    predicate.as_ref(),
                                    &mut tracker,
                                    config.state_machine.lenient_sourcing,
                                    min_len,
                                )
                                .await;
                                let (report, corpus_report) = {
                                    let mut aggregate = aggregate_tracker.borrow_mut();
                                    aggregate.merge_from(&tracker);
                                    let report = aggregate.report();
                                    let corpus_report = if config.state_machine.dump_corpus {
                                        Some(aggregate.corpus_report())
                                    } else {
                                        None
                                    };
                                    (report, corpus_report)
                                };
                                last_coverage.replace(Some(report.clone()));
                                last_corpus.replace(corpus_report.clone());
                                match result {
                                    Ok(execution) => Ok(execution),
                                    Err(mut failure) => {
                                        failure.coverage = Some(report);
                                        failure.corpus = corpus_report;
                                        Err(failure)
                                    }
                                }
                            })
                        });
                    match execution {
                        Ok(execution) => {
                            let mut full_trace = prelude_trace.as_ref().clone();
                            full_trace.extend(execution.trace);
                            last_trace.replace(full_trace);
                            Ok(())
                        }
                        Err(mut failure) => {
                            let mut full_trace = prelude_trace.as_ref().clone();
                            full_trace.extend(failure.trace);
                            failure.trace = full_trace;
                            last_failure.replace(failure.clone());
                            Err(TestCaseError::fail(failure.failure.reason.clone()))
                        }
                    }
                }
            });
            finalize_run_result(
                run_result,
                &last_trace,
                &last_failure,
                &last_coverage,
                &last_corpus,
                warnings.as_ref(),
            )
        }
    };
    if matches!(run_result.outcome, RunOutcome::Success) {
        if let Err(failure) = aggregate_tracker
            .borrow()
            .validate(&config.state_machine.coverage_rules)
        {
            let mut trace = last_trace.borrow().clone();
            attach_failure_reason(&mut trace, "coverage validation failed".to_string());
            let report = aggregate_tracker.borrow().report();
            let corpus_report = if config.state_machine.dump_corpus {
                Some(aggregate_tracker.borrow().corpus_report())
            } else {
                None
            };
            return failure_result(
                coverage_failure(failure),
                trace,
                None,
                warnings.as_ref().clone(),
                Some(report),
                corpus_report,
            );
        }
    }
    run_result
}

/// Execute a tooltest run against a stdio MCP endpoint.
///
/// Uses the same default and declarative assertions as [`run_with_session`].
pub async fn run_stdio(
    endpoint: &StdioConfig,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    run_with_transport(
        Box::pin(SessionDriver::connect_stdio(endpoint)),
        "stdio",
        config,
        options,
    )
    .await
}

/// Execute a tooltest run against an HTTP MCP endpoint.
///
/// Uses the same default and declarative assertions as [`run_with_session`].
pub async fn run_http(
    endpoint: &HttpConfig,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    run_with_transport(
        Box::pin(SessionDriver::connect_http(endpoint)),
        "http",
        config,
        options,
    )
    .await
}

#[derive(Clone, Debug)]
struct FailureContext {
    failure: RunFailure,
    trace: Vec<TraceEntry>,
    invocations: Vec<ToolInvocation>,
    coverage: Option<CoverageReport>,
    corpus: Option<CorpusReport>,
}

#[cfg_attr(not(test), allow(dead_code))]
async fn execute_sequence(
    session: &SessionDriver,
    input_validators: &BTreeMap<String, jsonschema::Validator>,
    output_validators: &BTreeMap<String, jsonschema::Validator>,
    assertions: &AssertionSet,
    sequence: &[ToolInvocation],
) -> Result<Vec<TraceEntry>, FailureContext> {
    let mut trace = Vec::new();
    let mut full_trace = Vec::new();
    let invocations = sequence.to_vec();
    for invocation in sequence {
        validate_invocation_inputs(invocation, input_validators);
        trace.push(TraceEntry::tool_call(invocation.clone()));
        let entry = match session.send_tool_call(invocation.clone()).await {
            Ok(entry) => entry,
            Err(error) => {
                attach_failure_reason(&mut trace, format!("session error: {error:?}"));
                return Err(FailureContext {
                    failure: RunFailure::new(format!("session error: {error:?}")),
                    trace,
                    invocations,
                    coverage: None,
                    corpus: None,
                });
            }
        };
        let (invocation, response) = entry.as_tool_call().expect("tool call trace entry");
        let invocation = invocation.clone();
        let response = response.expect("tool call response").clone();
        full_trace.push(entry);

        if let Some(reason) = apply_default_assertions(&invocation, &response, output_validators) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                invocations,
                coverage: None,
                corpus: None,
            });
        }

        if let Some(reason) = apply_response_assertions(assertions, &invocation, &response) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                invocations,
                coverage: None,
                corpus: None,
            });
        }
    }

    if let Some(reason) = apply_sequence_assertions(assertions, &full_trace) {
        attach_failure_reason(&mut trace, reason.clone());
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace,
            invocations,
            coverage: None,
            corpus: None,
        });
    }

    Ok(trace)
}

struct CoverageTracker<'a> {
    tools: &'a [Tool],
    corpus: ValueCorpus,
    counts: BTreeMap<String, u64>,
    allowlist: Option<Vec<String>>,
    blocklist: Option<Vec<String>>,
    lenient_sourcing: bool,
    mine_text: bool,
    log_corpus_deltas: bool,
}

struct CorpusSnapshot {
    numbers_len: usize,
    integers_len: usize,
    strings_len: usize,
}

struct CorpusDelta {
    numbers: Vec<Number>,
    integers: Vec<i64>,
    strings: Vec<String>,
}

impl CorpusSnapshot {
    fn new(corpus: &ValueCorpus) -> Self {
        Self {
            numbers_len: corpus.numbers().len(),
            integers_len: corpus.integers().len(),
            strings_len: corpus.strings().len(),
        }
    }

    fn delta(&self, corpus: &ValueCorpus) -> CorpusDelta {
        CorpusDelta {
            numbers: corpus.numbers()[self.numbers_len..].to_vec(),
            integers: corpus.integers()[self.integers_len..].to_vec(),
            strings: corpus.strings()[self.strings_len..].to_vec(),
        }
    }
}

const LIST_TOOLS_COUNT_LABEL: &str = "tools/list";

#[derive(Clone, Debug)]
struct CoverageValidationFailure {
    details: JsonValue,
}

impl<'a> CoverageTracker<'a> {
    fn new(tools: &'a [Tool], config: &crate::StateMachineConfig) -> Self {
        let mut corpus = ValueCorpus::default();
        corpus.seed_numbers(config.seed_numbers.clone());
        corpus.seed_strings(config.seed_strings.clone());
        Self {
            tools,
            corpus,
            counts: BTreeMap::new(),
            allowlist: config.coverage_allowlist.clone(),
            blocklist: config.coverage_blocklist.clone(),
            lenient_sourcing: config.lenient_sourcing,
            mine_text: config.mine_text,
            log_corpus_deltas: config.log_corpus_deltas,
        }
    }

    fn corpus(&self) -> &ValueCorpus {
        &self.corpus
    }

    fn merge_from(&mut self, other: &CoverageTracker<'_>) {
        for (tool, count) in &other.counts {
            *self.counts.entry(tool.clone()).or_insert(0) += count;
        }
        self.corpus.merge_from(other.corpus());
    }

    fn report(&self) -> CoverageReport {
        let mut counts = self.counts.clone();
        for tool in self.tools {
            counts.entry(tool.name.to_string()).or_insert(0);
        }
        counts.insert(LIST_TOOLS_COUNT_LABEL.to_string(), 1);
        CoverageReport {
            counts,
            warnings: self.build_warnings(),
        }
    }

    fn corpus_report(&self) -> CorpusReport {
        CorpusReport {
            numbers: self.corpus.numbers().to_vec(),
            integers: self.corpus.integers().to_vec(),
            strings: self.corpus.strings().to_vec(),
        }
    }

    fn record_success(&mut self, tool: &str) {
        *self.counts.entry(tool.to_string()).or_insert(0) += 1;
    }

    fn mine_response(&mut self, tool: &str, response: &CallToolResult) {
        if response.is_error.unwrap_or(false) {
            return;
        }
        let snapshot = CorpusSnapshot::new(self.corpus());
        if let Some(structured) = response.structured_content.as_ref() {
            self.corpus.mine_structured_content(structured);
            if self.mine_text {
                self.corpus.mine_text_from_value(structured);
            }
        }
        if self.mine_text {
            for content in &response.content {
                if let Some(text) = content.as_text() {
                    self.corpus.mine_text(&text.text);
                }
                if let Some(resource) = content.as_resource() {
                    match &resource.resource {
                        rmcp::model::ResourceContents::TextResourceContents { text, .. } => {
                            self.corpus.mine_text(text);
                        }
                        rmcp::model::ResourceContents::BlobResourceContents { .. } => {}
                    }
                }
            }
        }
        if self.log_corpus_deltas {
            let delta = snapshot.delta(self.corpus());
            eprintln!(
                "corpus delta after '{tool}': numbers={:?} integers={:?} strings={:?}",
                delta.numbers, delta.integers, delta.strings
            );
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn finalize(self) -> CoverageReport {
        let mut tracker = self;
        tracker.ensure_counts();
        tracker.counts.insert(LIST_TOOLS_COUNT_LABEL.to_string(), 1);
        let warnings = tracker.build_warnings();
        CoverageReport {
            counts: tracker.counts,
            warnings,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn ensure_counts(&mut self) {
        for tool in self.tools {
            self.counts.entry(tool.name.to_string()).or_insert(0);
        }
    }

    fn build_warnings(&self) -> Vec<CoverageWarning> {
        let mut warnings = Vec::new();
        let allowlist = self.allowlist.as_ref();
        let blocklist = self.blocklist.as_ref();

        for tool in self.tools {
            let name = tool.name.to_string();
            if let Some(allowlist) = allowlist {
                if !allowlist.iter().any(|entry| entry == &name) {
                    continue;
                }
            }
            if let Some(blocklist) = blocklist {
                if blocklist.iter().any(|entry| entry == &name) {
                    continue;
                }
            }

            if let Some(reason) = uncallable_reason(tool, &self.corpus, self.lenient_sourcing) {
                warnings.push(CoverageWarning {
                    tool: name,
                    reason: map_uncallable_reason(reason),
                });
            }
        }

        warnings
    }

    fn validate(&self, rules: &[CoverageRule]) -> Result<(), CoverageValidationFailure> {
        if rules.is_empty() {
            return Ok(());
        }

        let eligible_tools = self.eligible_tools();
        let mut callable_tools = Vec::new();
        for tool in eligible_tools {
            if uncallable_reason(tool, &self.corpus, self.lenient_sourcing).is_none() {
                callable_tools.push(tool.name.to_string());
            }
        }

        for rule in rules {
            match rule {
                CoverageRule::MinCallsPerTool { min } => {
                    let mut violations = Vec::new();
                    for tool in &callable_tools {
                        let count = *self.counts.get(tool).unwrap_or(&0);
                        if count < *min {
                            violations.push(json!({ "tool": tool, "count": count }));
                        }
                    }
                    let failure = if violations.is_empty() {
                        None
                    } else {
                        Some(CoverageValidationFailure {
                            details: json!({
                                "rule": "min_calls_per_tool",
                                "min": min,
                                "violations": violations,
                            }),
                        })
                    };
                    if let Some(failure) = failure {
                        return Err(failure);
                    }
                }
                CoverageRule::NoUncalledTools => {
                    let uncalled: Vec<String> = callable_tools
                        .iter()
                        .filter(|tool| *self.counts.get(*tool).unwrap_or(&0) == 0)
                        .cloned()
                        .collect();
                    let failure = if uncalled.is_empty() {
                        None
                    } else {
                        Some(CoverageValidationFailure {
                            details: json!({
                                "rule": "no_uncalled_tools",
                                "uncalled": uncalled,
                            }),
                        })
                    };
                    if let Some(failure) = failure {
                        return Err(failure);
                    }
                }
                CoverageRule::PercentCalled { min_percent } => {
                    if !min_percent.is_finite() || *min_percent < 0.0 || *min_percent > 100.0 {
                        return Err(CoverageValidationFailure {
                            details: json!({
                                "rule": "percent_called",
                                "error": "min_percent_out_of_range",
                                "min_percent": min_percent,
                            }),
                        });
                    }
                    let denom = callable_tools.len() as f64;
                    if denom == 0.0 {
                        continue;
                    }
                    let called = callable_tools
                        .iter()
                        .filter(|tool| *self.counts.get(*tool).unwrap_or(&0) > 0)
                        .count() as f64;
                    let percent = (called / denom) * 100.0;
                    if percent < *min_percent {
                        return Err(CoverageValidationFailure {
                            details: json!({
                                "rule": "percent_called",
                                "min_percent": min_percent,
                                "percent": percent,
                                "called": called,
                                "eligible": denom,
                            }),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn eligible_tools(&self) -> Vec<&Tool> {
        let allowlist = self.allowlist.as_ref();
        let blocklist = self.blocklist.as_ref();
        self.tools
            .iter()
            .filter(|tool| {
                let name = tool.name.to_string();
                if let Some(allowlist) = allowlist {
                    if !allowlist.iter().any(|entry| entry == &name) {
                        return false;
                    }
                }
                if let Some(blocklist) = blocklist {
                    if blocklist.iter().any(|entry| entry == &name) {
                        return false;
                    }
                }
                true
            })
            .collect()
    }
}

fn map_uncallable_reason(reason: UncallableReason) -> CoverageWarningReason {
    match reason {
        UncallableReason::String => CoverageWarningReason::MissingString,
        UncallableReason::Integer => CoverageWarningReason::MissingInteger,
        UncallableReason::Number => CoverageWarningReason::MissingNumber,
        UncallableReason::RequiredValue => CoverageWarningReason::MissingRequiredValue,
    }
}

fn collect_schema_warnings(tools: &[Tool]) -> Vec<RunWarning> {
    let mut warnings = Vec::new();
    for tool in tools {
        collect_schema_keyword_warnings(tool, "inputSchema", &tool.input_schema, &mut warnings);
        if let Some(schema) = &tool.output_schema {
            collect_schema_keyword_warnings(tool, "outputSchema", schema, &mut warnings);
        }
    }
    warnings
}

fn collect_schema_keyword_warnings(
    tool: &Tool,
    schema_label: &str,
    schema: &JsonObject,
    warnings: &mut Vec<RunWarning>,
) {
    if !schema.contains_key("$defs") {
        return;
    }
    let schema_id = schema
        .get("$schema")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if schema_id.contains("draft-07")
        || schema_id.contains("draft-06")
        || schema_id.contains("draft-04")
    {
        warnings.push(RunWarning {
            code: RunWarningCode::SchemaUnsupportedKeyword,
            message: format!(
                "tool '{}' {schema_label} declares {schema_id} but uses '$defs'; draft-07 and earlier use 'definitions'",
                tool.name
            ),
            tool: Some(tool.name.to_string()),
        });
    }
}

fn coverage_failure(failure: CoverageValidationFailure) -> RunFailure {
    RunFailure {
        reason: "coverage validation failed".to_string(),
        code: Some("coverage_validation_failed".to_string()),
        details: Some(failure.details),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
async fn execute_sequence_with_coverage(
    session: &SessionDriver,
    input_validators: &BTreeMap<String, jsonschema::Validator>,
    output_validators: &BTreeMap<String, jsonschema::Validator>,
    assertions: &AssertionSet,
    sequence: &[ToolInvocation],
    tracker: &mut CoverageTracker<'_>,
) -> Result<Vec<TraceEntry>, FailureContext> {
    let mut trace = Vec::new();
    let mut full_trace = Vec::new();
    let invocations = sequence.to_vec();
    for invocation in sequence {
        validate_invocation_inputs(invocation, input_validators);
        trace.push(TraceEntry::tool_call(invocation.clone()));
        let entry = match session.send_tool_call(invocation.clone()).await {
            Ok(entry) => entry,
            Err(error) => {
                attach_failure_reason(&mut trace, format!("session error: {error:?}"));
                return Err(FailureContext {
                    failure: RunFailure::new(format!("session error: {error:?}")),
                    trace,
                    invocations,
                    coverage: None,
                    corpus: None,
                });
            }
        };

        let (invocation, response) = entry.as_tool_call().expect("tool call trace entry");
        let invocation = invocation.clone();
        let response = response.expect("tool call response").clone();
        full_trace.push(entry);
        if !response.is_error.unwrap_or(false) {
            tracker.record_success(invocation.name.as_ref());
            tracker.mine_response(invocation.name.as_ref(), &response);
        }

        if let Some(reason) = apply_default_assertions(&invocation, &response, output_validators) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                invocations,
                coverage: None,
                corpus: None,
            });
        }

        if let Some(reason) = apply_response_assertions(assertions, &invocation, &response) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                invocations,
                coverage: None,
                corpus: None,
            });
        }
    }

    if let Some(reason) = apply_sequence_assertions(assertions, &full_trace) {
        attach_failure_reason(&mut trace, reason.clone());
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace,
            invocations,
            coverage: None,
            corpus: None,
        });
    }

    Ok(trace)
}

#[derive(Debug)]
struct StateMachineExecution {
    trace: Vec<TraceEntry>,
}

#[allow(clippy::too_many_arguments)]
async fn execute_state_machine_sequence_with_coverage(
    session: &SessionDriver,
    input_validators: &BTreeMap<String, jsonschema::Validator>,
    output_validators: &BTreeMap<String, jsonschema::Validator>,
    assertions: &AssertionSet,
    seeds: &[StateMachineSeed],
    tools: &[Tool],
    predicate: Option<&crate::ToolPredicate>,
    tracker: &mut CoverageTracker<'_>,
    lenient_sourcing: bool,
    min_len: usize,
) -> Result<StateMachineExecution, FailureContext> {
    let mut trace = Vec::new();
    let mut full_trace = Vec::new();
    let mut invocations = Vec::new();

    for seed in seeds {
        let Some(invocation) =
            invocation_from_seed(tools, predicate, tracker.corpus(), lenient_sourcing, *seed)
        else {
            break;
        };

        invocations.push(invocation.clone());
        validate_invocation_inputs(&invocation, input_validators);
        trace.push(TraceEntry::tool_call(invocation.clone()));
        let entry = match session.send_tool_call(invocation.clone()).await {
            Ok(entry) => entry,
            Err(error) => {
                attach_failure_reason(&mut trace, format!("session error: {error:?}"));
                return Err(FailureContext {
                    failure: RunFailure::new(format!("session error: {error:?}")),
                    trace,
                    invocations,
                    coverage: None,
                    corpus: None,
                });
            }
        };

        let (invocation, response) = entry.as_tool_call().expect("tool call trace entry");
        let invocation = invocation.clone();
        let response = response.expect("tool call response").clone();
        full_trace.push(entry);
        if !response.is_error.unwrap_or(false) {
            tracker.record_success(invocation.name.as_ref());
            tracker.mine_response(invocation.name.as_ref(), &response);
        }

        if let Some(reason) = apply_default_assertions(&invocation, &response, output_validators) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                invocations,
                coverage: None,
                corpus: None,
            });
        }

        if let Some(reason) = apply_response_assertions(assertions, &invocation, &response) {
            attach_response(&mut trace, response.clone());
            attach_failure_reason(&mut trace, reason.clone());
            return Err(FailureContext {
                failure: RunFailure::new(reason),
                trace,
                invocations,
                coverage: None,
                corpus: None,
            });
        }
    }

    if invocations.len() < min_len {
        let reason =
            format!("state-machine generator failed to reach minimum sequence length ({min_len})");
        attach_failure_reason(&mut trace, reason.clone());
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace,
            invocations,
            coverage: None,
            corpus: None,
        });
    }

    if let Some(reason) = apply_sequence_assertions(assertions, &full_trace) {
        attach_failure_reason(&mut trace, reason.clone());
        return Err(FailureContext {
            failure: RunFailure::new(reason),
            trace,
            invocations,
            coverage: None,
            corpus: None,
        });
    }

    Ok(StateMachineExecution { trace })
}

fn apply_default_assertions(
    invocation: &ToolInvocation,
    response: &CallToolResult,
    validators: &BTreeMap<String, jsonschema::Validator>,
) -> Option<String> {
    if response.is_error.unwrap_or(false) {
        return Some(format!(
            "tool '{}' returned an error response",
            invocation.name.as_ref()
        ));
    }

    let tool_name = invocation.name.as_ref();
    let validator = validators.get(tool_name)?;
    let Some(structured) = response.structured_content.as_ref() else {
        return Some(format!(
            "tool '{tool_name}' returned no structured_content for output schema"
        ));
    };
    if let Err(error) = validator.validate(structured) {
        return Some(format!(
            "output schema violation for tool '{tool_name}': {error}"
        ));
    }
    None
}

fn validate_invocation_inputs(
    invocation: &ToolInvocation,
    validators: &BTreeMap<String, jsonschema::Validator>,
) {
    let tool_name = invocation.name.as_ref();
    let validator = validators.get(tool_name).unwrap_or_else(|| {
        panic!("missing input schema validator for tool '{tool_name}'");
    });
    let input_payload = invocation
        .arguments
        .clone()
        .map(JsonValue::Object)
        .unwrap_or_else(|| JsonValue::Object(serde_json::Map::new()));
    if let Err(error) = validator.validate(&input_payload) {
        panic!("input schema violation for tool '{tool_name}': {error}; input={input_payload}");
    }
}

fn apply_response_assertions(
    assertions: &AssertionSet,
    invocation: &ToolInvocation,
    response: &CallToolResult,
) -> Option<String> {
    if assertions.rules.is_empty() {
        return None;
    }

    let input_payload = invocation
        .arguments
        .clone()
        .map(JsonValue::Object)
        .unwrap_or(JsonValue::Null);
    let output_payload = serde_json::to_value(response).unwrap_or(JsonValue::Null);
    let structured_payload = response
        .structured_content
        .clone()
        .unwrap_or(JsonValue::Null);
    let payloads = AssertionPayloads {
        input: input_payload,
        output: output_payload,
        structured: structured_payload,
        sequence: None,
    };

    for rule in &assertions.rules {
        let AssertionRule::Response(response_assertion) = rule else {
            continue;
        };
        if let Some(tool) = &response_assertion.tool {
            if tool != invocation.name.as_ref() {
                continue;
            }
        }
        if let Some(reason) = evaluate_checks(
            &response_assertion.checks,
            &payloads,
            Some(invocation.name.as_ref()),
            false,
        ) {
            return Some(reason);
        }
    }

    None
}

fn attach_response(trace: &mut [TraceEntry], response: CallToolResult) {
    if let Some(TraceEntry::ToolCall { response: slot, .. }) = trace.last_mut() {
        *slot = Some(response);
    }
}

fn attach_failure_reason(trace: &mut [TraceEntry], reason: String) {
    if let Some(TraceEntry::ToolCall { failure_reason, .. }) = trace.last_mut() {
        *failure_reason = Some(reason);
    }
}

fn apply_sequence_assertions(assertions: &AssertionSet, trace: &[TraceEntry]) -> Option<String> {
    if assertions.rules.is_empty() {
        return None;
    }

    let sequence_payload = serde_json::to_value(trace).unwrap_or(JsonValue::Null);
    let payloads = AssertionPayloads {
        input: JsonValue::Null,
        output: JsonValue::Null,
        structured: JsonValue::Null,
        sequence: Some(sequence_payload),
    };

    for rule in &assertions.rules {
        let AssertionRule::Sequence(sequence_assertion) = rule else {
            continue;
        };
        if let Some(reason) = evaluate_checks(&sequence_assertion.checks, &payloads, None, true) {
            return Some(reason);
        }
    }
    None
}

struct AssertionPayloads {
    input: JsonValue,
    output: JsonValue,
    structured: JsonValue,
    sequence: Option<JsonValue>,
}

fn evaluate_checks(
    checks: &[AssertionCheck],
    payloads: &AssertionPayloads,
    tool_name: Option<&str>,
    sequence_scope: bool,
) -> Option<String> {
    for check in checks {
        let payload = match (sequence_scope, &check.target) {
            (true, AssertionTarget::Sequence) => payloads.sequence.as_ref().unwrap(),
            (false, AssertionTarget::Input) => &payloads.input,
            (false, AssertionTarget::Output) => &payloads.output,
            (false, AssertionTarget::StructuredOutput) => &payloads.structured,
            (false, AssertionTarget::Sequence) => {
                return Some("sequence target is only valid for sequence assertions".to_string());
            }
            (true, _) => {
                return Some("sequence assertions must target the sequence payload".to_string());
            }
        };
        let actual = match payload.pointer(&check.pointer) {
            Some(value) => value,
            None => {
                return Some(format!("assertion pointer '{}' not found", check.pointer));
            }
        };
        if actual != &check.expected {
            let tool_prefix = tool_name
                .map(|name| format!("tool '{name}' "))
                .unwrap_or_default();
            return Some(format!(
                "{}assertion failed at '{}': expected {}, got {}",
                tool_prefix, check.pointer, check.expected, actual
            ));
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemaDialect {
    Draft4,
    Draft6,
    Draft7,
    Draft2019_09,
    Draft2020_12,
}

fn schema_dialect_for(schema: &JsonValue) -> SchemaDialect {
    let Some(schema_id) = schema.get("$schema").and_then(JsonValue::as_str) else {
        return SchemaDialect::Draft2020_12;
    };
    if schema_id.contains("draft-04") {
        SchemaDialect::Draft4
    } else if schema_id.contains("draft-06") {
        SchemaDialect::Draft6
    } else if schema_id.contains("draft-07") {
        SchemaDialect::Draft7
    } else if schema_id.contains("draft/2019-09") {
        SchemaDialect::Draft2019_09
    } else {
        SchemaDialect::Draft2020_12
    }
}

fn build_schema_validator(
    schema_value: &JsonValue,
    tool_name: &str,
    schema_label: &str,
) -> Result<Validator, String> {
    let validator = match schema_dialect_for(schema_value) {
        SchemaDialect::Draft4 => draft4::new(schema_value),
        SchemaDialect::Draft6 => draft6::new(schema_value),
        SchemaDialect::Draft7 => draft7::new(schema_value),
        SchemaDialect::Draft2019_09 => draft201909::new(schema_value),
        SchemaDialect::Draft2020_12 => draft202012::new(schema_value),
    };
    validator.map_err(|error| {
        format!("failed to compile {schema_label} for tool '{tool_name}': {error}")
    })
}

fn build_output_validators(
    tools: &[Tool],
) -> Result<BTreeMap<String, jsonschema::Validator>, String> {
    let mut validators = BTreeMap::new();
    for tool in tools {
        let Some(schema) = &tool.output_schema else {
            continue;
        };
        let schema_value = JsonValue::Object(schema.as_ref().clone());
        let validator = build_schema_validator(&schema_value, tool.name.as_ref(), "output schema")?;
        validators.insert(tool.name.to_string(), validator);
    }
    Ok(validators)
}

fn build_input_validators(
    tools: &[Tool],
) -> Result<BTreeMap<String, jsonschema::Validator>, String> {
    let mut validators = BTreeMap::new();
    for tool in tools {
        let schema_value = JsonValue::Object(tool.input_schema.as_ref().clone());
        let validator = build_schema_validator(&schema_value, tool.name.as_ref(), "input schema")?;
        validators.insert(tool.name.to_string(), validator);
    }
    Ok(validators)
}

fn validate_tools(tools: Vec<Tool>, config: &crate::SchemaConfig) -> Result<Vec<Tool>, String> {
    let list_tools = ListToolsResult {
        tools,
        next_cursor: None,
        meta: None,
    };
    let payload = serde_json::to_value(&list_tools).expect("list tools serialize");
    let parsed = parse_list_tools(payload, config).map_err(|error| error.to_string())?;
    Ok(parsed.tools)
}

fn failure_result(
    failure: RunFailure,
    trace: Vec<TraceEntry>,
    minimized: Option<MinimizedSequence>,
    warnings: Vec<RunWarning>,
    coverage: Option<CoverageReport>,
    corpus: Option<CorpusReport>,
) -> RunResult {
    RunResult {
        outcome: RunOutcome::Failure(failure),
        trace,
        minimized,
        warnings,
        coverage,
        corpus,
    }
}

fn finalize_run_result<T>(
    run_result: Result<(), TestError<T>>,
    last_trace: &Rc<RefCell<Vec<TraceEntry>>>,
    last_failure: &Rc<RefCell<FailureContext>>,
    last_coverage: &Rc<RefCell<Option<CoverageReport>>>,
    last_corpus: &Rc<RefCell<Option<CorpusReport>>>,
    warnings: &[RunWarning],
) -> RunResult {
    match run_result {
        Ok(()) => RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: warnings.to_vec(),
            coverage: last_coverage.borrow().clone(),
            corpus: last_corpus.borrow().clone(),
        },
        Err(TestError::Abort(reason)) => failure_result(
            RunFailure::new(format!("proptest aborted: {reason}")),
            last_trace.borrow().clone(),
            None,
            warnings.to_vec(),
            last_coverage.borrow().clone(),
            last_corpus.borrow().clone(),
        ),
        Err(TestError::Fail(_reason, _sequence)) => {
            let failure = last_failure.borrow().clone();
            let trace = failure.trace;
            let minimized = Some(MinimizedSequence {
                invocations: failure.invocations,
            });
            failure_result(
                failure.failure,
                trace,
                minimized,
                warnings.to_vec(),
                failure.coverage,
                failure.corpus,
            )
        }
    }
}

type ConnectFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<SessionDriver, crate::SessionError>> + Send + 'a>,
>;

async fn run_with_transport(
    connect: ConnectFuture<'_>,
    label: &str,
    config: &RunConfig,
    options: RunnerOptions,
) -> RunResult {
    let session = match connect.await {
        Ok(session) => session,
        Err(error) => {
            return failure_result(
                RunFailure::new(format!("failed to connect {label} transport: {error:?}")),
                Vec::new(),
                None,
                Vec::new(),
                None,
                None,
            );
        }
    };
    run_with_session(&session, config, options).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{invocation_from_seed, StateMachineSeed};
    use crate::{
        AssertionCheck, AssertionRule, AssertionSet, AssertionTarget, CoverageRule,
        CoverageWarningReason, ErrorCode, ErrorData, JsonObject, ResponseAssertion, SchemaConfig,
        SequenceAssertion, SessionError, StateMachineConfig,
    };
    use rmcp::model::{
        CallToolRequest, CallToolRequestParam, CallToolResult, ClientJsonRpcMessage, ClientRequest,
        Content, JsonRpcMessage, ListResourcesRequest, NumberOrString, ResourceContents,
        ServerJsonRpcMessage,
    };
    use rmcp::service::RoleClient;
    use rmcp::transport::Transport;
    use serde_json::{json, Number};
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex as AsyncMutex};

    use tooltest_test_support::{
        call_tool_response, init_response, list_tools_response, tool_with_schemas, RunnerTransport,
    };

    fn outcome_is_success(outcome: &RunOutcome) -> bool {
        matches!(outcome, RunOutcome::Success)
    }

    fn trace_entry_with(
        name: &str,
        args: Option<JsonValue>,
        response: CallToolResult,
    ) -> TraceEntry {
        TraceEntry::tool_call_with_response(
            ToolInvocation {
                name: name.to_string().into(),
                arguments: args.and_then(|value| value.as_object().cloned()),
            },
            response,
        )
    }

    async fn connect_runner_transport(
        transport: RunnerTransport,
    ) -> Result<SessionDriver, SessionError> {
        SessionDriver::connect_with_transport::<
            RunnerTransport,
            std::convert::Infallible,
            rmcp::transport::TransportAdapterIdentity,
        >(transport)
        .await
    }

    fn connect_result(result: Result<SessionDriver, SessionError>) -> ConnectFuture<'static> {
        Box::pin(async move { result })
    }

    struct IncrementCrashTransport {
        tools: Vec<Tool>,
        responses: Arc<AsyncMutex<mpsc::UnboundedReceiver<ServerJsonRpcMessage>>>,
        response_tx: mpsc::UnboundedSender<ServerJsonRpcMessage>,
    }

    impl IncrementCrashTransport {
        fn new(tools: Vec<Tool>) -> Self {
            let (response_tx, response_rx) = mpsc::unbounded_channel();
            Self {
                tools,
                responses: Arc::new(AsyncMutex::new(response_rx)),
                response_tx,
            }
        }
    }

    impl Transport<RoleClient> for IncrementCrashTransport {
        type Error = std::convert::Infallible;

        fn send(
            &mut self,
            item: ClientJsonRpcMessage,
        ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
            let response_tx = self.response_tx.clone();
            let tools = self.tools.clone();
            if let JsonRpcMessage::Request(request) = &item {
                let response = match &request.request {
                    ClientRequest::InitializeRequest(_) => Some(init_response(request.id.clone())),
                    ClientRequest::ListToolsRequest(_) => {
                        Some(list_tools_response(request.id.clone(), tools))
                    }
                    ClientRequest::CallToolRequest(call) => match call.params.name.as_ref() {
                        "seed" => Some(call_tool_response(
                            request.id.clone(),
                            CallToolResult::structured(json!({ "count": 0 })),
                        )),
                        "increment" => {
                            let count = call
                                .params
                                .arguments
                                .as_ref()
                                .and_then(|args| args.get("count"))
                                .and_then(serde_json::Value::as_i64)
                                .unwrap_or(0);
                            if count > 10 {
                                Some(ServerJsonRpcMessage::error(
                                    ErrorData::new(ErrorCode::INTERNAL_ERROR, "boom", None),
                                    request.id.clone(),
                                ))
                            } else {
                                Some(call_tool_response(
                                    request.id.clone(),
                                    CallToolResult::structured(json!({ "count": count + 1 })),
                                ))
                            }
                        }
                        _ => None,
                    },
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

    fn assert_failure(result: &RunResult) {
        assert!(matches!(result.outcome, RunOutcome::Failure(_)));
    }

    fn assert_warnings_empty(warnings: &[CoverageWarning]) {
        assert!(warnings.is_empty(), "warnings: {:?}", warnings);
    }

    #[allow(dead_code)]
    fn assert_success(result: &RunResult) {
        assert!(matches!(result.outcome, RunOutcome::Success));
    }

    fn assert_failure_reason_contains(result: &RunResult, needle: &str) {
        if let RunOutcome::Failure(failure) = &result.outcome {
            assert!(failure.reason.contains(needle));
        } else {
            panic!("expected failure");
        }
    }

    fn assert_failure_reason_eq(result: &RunResult, expected: &str) {
        if let RunOutcome::Failure(failure) = &result.outcome {
            assert_eq!(failure.reason, expected);
        } else {
            panic!("expected failure");
        }
    }

    #[test]
    fn schema_dialect_for_defaults_without_schema() {
        let schema = json!({ "type": "object" });
        assert_eq!(schema_dialect_for(&schema), SchemaDialect::Draft2020_12);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn state_machine_mining_always_provokes_failure_with_increment_tool() {
        let seed_tool = tool_with_schemas(
            "seed",
            json!({
                "type": "object",
                "properties": {}
            }),
            Some(json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            })),
        );
        let increment_tool = tool_with_schemas(
            "increment",
            json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            }),
            Some(json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            })),
        );
        let transport = IncrementCrashTransport::new(vec![seed_tool.clone(), increment_tool]);
        let session = SessionDriver::connect_with_transport::<
            IncrementCrashTransport,
            std::convert::Infallible,
            rmcp::transport::TransportAdapterIdentity,
        >(transport)
        .await
        .expect("connect");
        let config = RunConfig::new()
            .with_generator_mode(GeneratorMode::StateMachine)
            .with_state_machine(
                StateMachineConfig::default()
                    .with_lenient_sourcing(false)
                    .with_dump_corpus(true),
            );
        let result = run_with_session(
            &session,
            &config,
            RunnerOptions {
                cases: 1,
                sequence_len: 300..=300,
            },
        )
        .await;

        assert_failure(&result);
        assert!(result.corpus.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn increment_crash_transport_ignores_unhandled_requests() {
        let seed_tool = tool_with_schemas(
            "seed",
            json!({
                "type": "object",
                "properties": {}
            }),
            None,
        );
        let mut transport = IncrementCrashTransport::new(vec![seed_tool]);
        let request = ClientJsonRpcMessage::request(
            ClientRequest::ListResourcesRequest(ListResourcesRequest::default()),
            NumberOrString::Number(1),
        );
        let _ = transport.send(request).await;

        let request = ClientJsonRpcMessage::request(
            ClientRequest::CallToolRequest(CallToolRequest::new(CallToolRequestParam {
                name: "unknown".into(),
                arguments: None,
            })),
            NumberOrString::Number(2),
        );
        let _ = transport.send(request).await;
        let _ = transport.close().await;
    }

    #[test]
    fn schema_dialect_for_defaults_for_unknown_schema() {
        let schema = json!({ "$schema": "https://example.com/schema" });
        assert_eq!(schema_dialect_for(&schema), SchemaDialect::Draft2020_12);
    }

    #[test]
    fn finalize_run_result_uses_abort_path() {
        let trace_entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let last_trace = Rc::new(RefCell::new(vec![trace_entry]));
        let last_failure = Rc::new(RefCell::new(FailureContext {
            failure: RunFailure::new(String::new()),
            trace: Vec::new(),
            invocations: Vec::new(),
            coverage: None,
            corpus: None,
        }));
        let result = finalize_run_result(
            Err(TestError::<Vec<ToolInvocation>>::Abort("nope".into())),
            &last_trace,
            &last_failure,
            &Rc::new(RefCell::new(None)),
            &Rc::new(RefCell::new(None)),
            &[],
        );

        assert_failure(&result);
        assert_eq!(result.trace.len(), 1);
        assert!(result.minimized.is_none());
    }

    #[test]
    fn finalize_run_result_success_includes_coverage_and_corpus() {
        let last_trace = Rc::new(RefCell::new(Vec::new()));
        let last_failure = Rc::new(RefCell::new(FailureContext {
            failure: RunFailure::new(String::new()),
            trace: Vec::new(),
            invocations: Vec::new(),
            coverage: None,
            corpus: None,
        }));
        let mut counts = BTreeMap::new();
        counts.insert("echo".to_string(), 1u64);
        let coverage = CoverageReport {
            counts,
            warnings: Vec::new(),
        };
        let corpus = CorpusReport {
            numbers: vec![Number::from(1)],
            integers: vec![1],
            strings: vec!["alpha".to_string()],
        };
        let result = finalize_run_result(
            Ok(()),
            &last_trace,
            &last_failure,
            &Rc::new(RefCell::new(Some(coverage.clone()))),
            &Rc::new(RefCell::new(Some(corpus.clone()))),
            &[],
        );

        assert!(outcome_is_success(&result.outcome));
        assert!(result.trace.is_empty());
        let coverage_report = result.coverage.expect("coverage");
        assert_eq!(coverage_report.counts.get("echo").copied(), Some(1));
        assert!(coverage_report.warnings.is_empty());

        let corpus_report = result.corpus.expect("corpus");
        assert_eq!(corpus_report.numbers, corpus.numbers);
        assert_eq!(corpus_report.integers, corpus.integers);
        assert_eq!(corpus_report.strings, corpus.strings);
    }

    #[test]
    fn outcome_is_success_reports_success_and_failure() {
        assert!(outcome_is_success(&RunOutcome::Success));
        assert!(!outcome_is_success(&RunOutcome::Failure(RunFailure::new(
            "nope"
        ))));
    }

    #[test]
    fn apply_default_assertions_reports_tool_error() {
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::error(vec![Content::text("boom")]),
        );
        let validators = BTreeMap::new();
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result = apply_default_assertions(invocation, response.expect("response"), &validators);
        assert!(result.is_some());
    }

    #[test]
    fn apply_default_assertions_reports_missing_structured_content() {
        let schema = json!({
            "type": "object",
            "properties": { "status": { "type": "string" } },
            "required": ["status"]
        });
        let validator = draft202012::new(&schema).expect("validator");
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let mut validators = BTreeMap::new();
        validators.insert("echo".to_string(), validator);
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result = apply_default_assertions(invocation, response.expect("response"), &validators);
        assert!(result.is_some());
    }

    #[test]
    fn apply_default_assertions_reports_schema_violation() {
        let schema = json!({
            "type": "object",
            "properties": { "status": { "type": "string", "const": "ok" } },
            "required": ["status"]
        });
        let validator = draft202012::new(&schema).expect("validator");
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::structured(json!({ "status": "bad" })),
        );
        let mut validators = BTreeMap::new();
        validators.insert("echo".to_string(), validator);
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result = apply_default_assertions(invocation, response.expect("response"), &validators);
        assert!(result.is_some());
    }

    #[test]
    fn apply_default_assertions_accepts_valid_structured_content() {
        let schema = json!({
            "type": "object",
            "properties": { "status": { "type": "string", "const": "ok" } },
            "required": ["status"]
        });
        let validator = draft202012::new(&schema).expect("validator");
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::structured(json!({ "status": "ok" })),
        );
        let mut validators = BTreeMap::new();
        validators.insert("echo".to_string(), validator);
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result = apply_default_assertions(invocation, response.expect("response"), &validators);
        assert!(result.is_none());
    }

    #[test]
    fn apply_default_assertions_skips_when_missing_validator() {
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::structured(json!({ "status": "ok" })),
        );
        let validators = BTreeMap::new();
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result = apply_default_assertions(invocation, response.expect("response"), &validators);
        assert!(result.is_none());
    }

    #[test]
    fn apply_response_assertions_handles_empty_rules() {
        let entry = trace_entry_with(
            "echo",
            Some(json!({ "flag": true })),
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet::default();
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
        assert!(result.is_none());
    }

    #[test]
    fn apply_response_assertions_reports_pointer_missing() {
        let entry = trace_entry_with(
            "echo",
            Some(json!({ "flag": true })),
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Response(ResponseAssertion {
                tool: Some("echo".to_string()),
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/missing".to_string(),
                    expected: json!(true),
                }],
            })],
        };
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
        assert!(result.is_some());
    }

    #[test]
    fn apply_response_assertions_reports_value_mismatch() {
        let entry = trace_entry_with(
            "echo",
            Some(json!({ "flag": true })),
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Response(ResponseAssertion {
                tool: Some("echo".to_string()),
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/flag".to_string(),
                    expected: json!(false),
                }],
            })],
        };
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
        assert!(result.is_some());
    }

    #[test]
    fn apply_response_assertions_skips_tool_mismatch() {
        let entry = trace_entry_with(
            "echo",
            Some(json!({ "flag": true })),
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Response(ResponseAssertion {
                tool: Some("other".to_string()),
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/flag".to_string(),
                    expected: json!(true),
                }],
            })],
        };
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
        assert!(result.is_none());
    }

    #[test]
    fn apply_response_assertions_supports_unscoped_rules() {
        let entry = trace_entry_with(
            "echo",
            Some(json!({ "flag": true })),
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Response(ResponseAssertion {
                tool: None,
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/flag".to_string(),
                    expected: json!(true),
                }],
            })],
        };
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
        assert!(result.is_none());
    }

    #[test]
    fn apply_response_assertions_skips_non_response_rules() {
        let entry = trace_entry_with(
            "echo",
            Some(json!({ "flag": true })),
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Sequence(SequenceAssertion {
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Sequence,
                    pointer: "/0".to_string(),
                    expected: json!([]),
                }],
            })],
        };
        let (invocation, response) = entry.as_tool_call().expect("tool call");
        let result =
            apply_response_assertions(&assertions, invocation, response.expect("response"));
        assert!(result.is_none());
    }

    #[test]
    fn attach_response_updates_last_tool_call() {
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: Some(JsonObject::new()),
        };
        let mut trace = vec![TraceEntry::tool_call(invocation)];
        let response = CallToolResult::success(vec![Content::text("ok")]);
        attach_response(&mut trace, response.clone());
        let (_, stored) = trace[0].as_tool_call().expect("tool call");
        assert_eq!(stored, Some(&response));
    }

    #[test]
    fn attach_response_ignores_non_tool_call() {
        let mut trace = vec![TraceEntry::list_tools()];
        let response = CallToolResult::success(vec![Content::text("ok")]);
        attach_response(&mut trace, response);
        assert!(trace[0].as_tool_call().is_none());
    }

    #[test]
    fn attach_failure_reason_updates_last_tool_call() {
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: Some(JsonObject::new()),
        };
        let mut trace = vec![TraceEntry::tool_call(invocation)];
        attach_failure_reason(&mut trace, "failure".to_string());
        assert!(matches!(
            &trace[0],
            TraceEntry::ToolCall {
                failure_reason: Some(reason),
                ..
            } if reason == "failure"
        ));
    }

    #[test]
    fn attach_failure_reason_ignores_non_tool_call() {
        let mut trace = vec![TraceEntry::list_tools()];
        attach_failure_reason(&mut trace, "failure".to_string());
        assert!(trace[0].as_tool_call().is_none());
    }

    #[test]
    fn apply_sequence_assertions_handles_empty_rules() {
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet::default();
        let result = apply_sequence_assertions(&assertions, &[entry]);
        assert!(result.is_none());
    }

    #[test]
    fn apply_sequence_assertions_reports_invalid_target() {
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Sequence(SequenceAssertion {
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/flag".to_string(),
                    expected: json!(true),
                }],
            })],
        };
        let result = apply_sequence_assertions(&assertions, &[entry]);
        assert!(result.is_some());
    }

    #[test]
    fn apply_sequence_assertions_skips_non_sequence_rules() {
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Response(ResponseAssertion {
                tool: None,
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/flag".to_string(),
                    expected: json!(true),
                }],
            })],
        };
        let result = apply_sequence_assertions(&assertions, &[entry]);
        assert!(result.is_none());
    }

    #[test]
    fn apply_sequence_assertions_accepts_passing_checks() {
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Sequence(SequenceAssertion {
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Sequence,
                    pointer: "/0/invocation/name".to_string(),
                    expected: json!("echo"),
                }],
            })],
        };
        let result = apply_sequence_assertions(&assertions, &[entry]);
        assert!(result.is_none());
    }

    #[test]
    fn evaluate_checks_rejects_sequence_target_in_response_scope() {
        let payloads = AssertionPayloads {
            input: json!({ "flag": true }),
            output: JsonValue::Null,
            structured: JsonValue::Null,
            sequence: Some(json!([])),
        };
        let result = evaluate_checks(
            &[AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/0".to_string(),
                expected: json!(true),
            }],
            &payloads,
            None,
            false,
        );
        assert!(result.is_some());
    }

    #[test]
    fn evaluate_checks_rejects_non_sequence_target_in_sequence_scope() {
        let payloads = AssertionPayloads {
            input: json!({ "flag": true }),
            output: JsonValue::Null,
            structured: JsonValue::Null,
            sequence: Some(json!([])),
        };
        let result = evaluate_checks(
            &[AssertionCheck {
                target: AssertionTarget::Input,
                pointer: "/flag".to_string(),
                expected: json!(true),
            }],
            &payloads,
            None,
            true,
        );
        assert!(result.is_some());
    }

    #[test]
    fn evaluate_checks_reads_output_payload() {
        let payloads = AssertionPayloads {
            input: JsonValue::Null,
            output: json!({ "ok": true }),
            structured: JsonValue::Null,
            sequence: Some(json!([])),
        };
        let result = evaluate_checks(
            &[AssertionCheck {
                target: AssertionTarget::Output,
                pointer: "/ok".to_string(),
                expected: json!(true),
            }],
            &payloads,
            None,
            false,
        );
        assert!(result.is_none());
    }

    #[test]
    fn evaluate_checks_accepts_sequence_target_in_sequence_scope() {
        let payloads = AssertionPayloads {
            input: JsonValue::Null,
            output: JsonValue::Null,
            structured: JsonValue::Null,
            sequence: Some(json!([{ "invocation": { "name": "echo" } }])),
        };
        let result = evaluate_checks(
            &[AssertionCheck {
                target: AssertionTarget::Sequence,
                pointer: "/0/invocation/name".to_string(),
                expected: json!("echo"),
            }],
            &payloads,
            None,
            true,
        );
        assert!(result.is_none());
    }

    #[test]
    fn evaluate_checks_accepts_structured_output_target() {
        let payloads = AssertionPayloads {
            input: JsonValue::Null,
            output: JsonValue::Null,
            structured: json!({ "status": "ok" }),
            sequence: None,
        };
        let result = evaluate_checks(
            &[AssertionCheck {
                target: AssertionTarget::StructuredOutput,
                pointer: "/status".to_string(),
                expected: json!("ok"),
            }],
            &payloads,
            None,
            false,
        );
        assert!(result.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_with_transport_success_path() {
        let tool = tool_with_schemas(
            "echo",
            json!({ "type": "object" }),
            Some(json!({ "type": "object" })),
        );
        let response = CallToolResult::structured(json!({}));
        let transport = RunnerTransport::new(tool, response);
        let session = SessionDriver::connect_with_transport(transport)
            .await
            .expect("connect");

        let result = run_with_transport(
            connect_result(Ok(session)),
            "local",
            &RunConfig::new(),
            RunnerOptions {
                cases: 1,
                sequence_len: 1..=1,
            },
        )
        .await;

        assert_success(&result);
    }

    #[cfg(coverage)]
    #[test]
    fn coverage_smoke_for_assert_helpers() {
        let success = RunResult {
            outcome: RunOutcome::Success,
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
            corpus: None,
        };
        let failure = RunResult {
            outcome: RunOutcome::Failure(RunFailure::new("boom".to_string())),
            trace: Vec::new(),
            minimized: None,
            warnings: Vec::new(),
            coverage: None,
            corpus: None,
        };
        assert_success(&success);
        assert_failure(&failure);
        assert_warnings_empty(&[]);
        assert_failure_reason_contains(&failure, "boom");
        assert_failure_reason_eq(&failure, "boom");
        assert!(
            std::panic::catch_unwind(|| assert_failure_reason_contains(&success, "boom")).is_err()
        );
        assert!(std::panic::catch_unwind(|| assert_failure_reason_eq(&success, "boom")).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_reports_session_error() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool.clone(), response).with_call_tool_error(
            ErrorData::new(ErrorCode::INTERNAL_ERROR, "call failed", None),
        );
        let session = connect_runner_transport(transport).await.expect("connect");
        let input_validators = build_input_validators(&[tool]).expect("validators");
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: None,
        };
        let result = execute_sequence(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &AssertionSet::default(),
            &[invocation],
        )
        .await;
        let failure = result.expect_err("expected failure");
        assert!(failure.failure.reason.contains("session error"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_state_machine_sequence_mines_structured_output() {
        let seed_tool = tool_with_schemas("seed", json!({ "type": "object" }), None);
        let use_tool = tool_with_schemas(
            "use",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        );
        let response = CallToolResult::structured(json!({ "text": "alpha" }));
        let transport = RunnerTransport::new(seed_tool.clone(), response);
        let session = connect_runner_transport(transport).await.expect("connect");

        let tools = vec![seed_tool.clone()];
        let input_validators = build_input_validators(&tools).expect("validators");
        let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default());
        let seeds = vec![StateMachineSeed(1)];
        let result = execute_state_machine_sequence_with_coverage(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &AssertionSet::default(),
            &seeds,
            &tools,
            None,
            &mut tracker,
            false,
            1,
        )
        .await;

        assert!(result.is_ok());
        assert!(tracker
            .corpus()
            .strings()
            .iter()
            .any(|value| value == "text"));
        let invocation = invocation_from_seed(
            &[use_tool],
            None,
            tracker.corpus(),
            false,
            StateMachineSeed(2),
        )
        .expect("callable");
        let args = invocation.arguments.as_ref().expect("args");
        let value = args.get("text").expect("text value");
        assert!(value.is_string());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_state_machine_sequence_fails_min_length() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        );
        let response = CallToolResult::structured(json!({}));
        let transport = RunnerTransport::new(tool.clone(), response);
        let session = connect_runner_transport(transport).await.expect("connect");

        let tools = vec![tool.clone()];
        let input_validators = build_input_validators(&tools).expect("validators");
        let mut tracker = CoverageTracker::new(&tools, &StateMachineConfig::default());
        let seeds = vec![StateMachineSeed(3)];
        let result = execute_state_machine_sequence_with_coverage(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &AssertionSet::default(),
            &seeds,
            &tools,
            None,
            &mut tracker,
            false,
            1,
        )
        .await;

        let failure = result.expect_err("expected failure");
        assert!(failure.failure.reason.contains("minimum sequence length"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_reports_default_assertion_failure() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::error(vec![Content::text("boom")]);
        let transport = RunnerTransport::new(tool.clone(), response);
        let session = connect_runner_transport(transport).await.expect("connect");
        let input_validators = build_input_validators(&[tool]).expect("validators");
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: None,
        };
        let result = execute_sequence(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &AssertionSet::default(),
            &[invocation],
        )
        .await;
        let failure = result.expect_err("expected failure");
        assert!(failure
            .failure
            .reason
            .contains("returned an error response"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_reports_response_assertion_failure() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool.clone(), response);
        let session = connect_runner_transport(transport).await.expect("connect");
        let input_validators = build_input_validators(&[tool]).expect("validators");
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: None,
        };
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Response(ResponseAssertion {
                tool: None,
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/missing".to_string(),
                    expected: json!(true),
                }],
            })],
        };
        let result = execute_sequence(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &assertions,
            &[invocation],
        )
        .await;
        let failure = result.expect_err("expected failure");
        assert!(failure.failure.reason.contains("assertion pointer"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_reports_sequence_assertion_failure() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool.clone(), response);
        let session = connect_runner_transport(transport).await.expect("connect");
        let input_validators = build_input_validators(&[tool]).expect("validators");
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: None,
        };
        let assertions = AssertionSet {
            rules: vec![AssertionRule::Sequence(SequenceAssertion {
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Sequence,
                    pointer: "/missing".to_string(),
                    expected: json!(true),
                }],
            })],
        };
        let result = execute_sequence(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &assertions,
            &[invocation],
        )
        .await;
        let failure = result.expect_err("expected failure");
        assert!(failure.failure.reason.contains("assertion pointer"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_succeeds_with_valid_response() {
        let tool = tool_with_schemas(
            "echo",
            json!({ "type": "object" }),
            Some(json!({
                "type": "object",
                "properties": { "status": { "type": "string", "const": "ok" } },
                "required": ["status"]
            })),
        );
        let response = CallToolResult::structured(json!({ "status": "ok" }));
        let transport = RunnerTransport::new(tool.clone(), response);
        let session = connect_runner_transport(transport).await.expect("connect");
        let input_validators = build_input_validators(&[tool.clone()]).expect("validators");
        let output_validators = build_output_validators(&[tool]).expect("validators");
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: Some(JsonObject::new()),
        };

        let result = execute_sequence(
            &session,
            &input_validators,
            &output_validators,
            &AssertionSet::default(),
            &[invocation],
        )
        .await;

        let trace = result.expect("expected success");
        assert_eq!(trace.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_succeeds_with_empty_sequence() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool, response);
        let session = connect_runner_transport(transport).await.expect("connect");

        let result = execute_sequence(
            &session,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &AssertionSet::default(),
            &[],
        )
        .await;

        let trace = result.expect("expected success");
        assert!(trace.is_empty());
    }

    #[test]
    fn finalize_run_result_uses_fail_path() {
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: None,
        };
        let trace_entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let last_trace = Rc::new(RefCell::new(vec![trace_entry]));
        let last_failure = Rc::new(RefCell::new(FailureContext {
            failure: RunFailure::new("failure".to_string()),
            trace: Vec::new(),
            invocations: vec![invocation.clone()],
            coverage: None,
            corpus: None,
        }));
        let result = finalize_run_result(
            Err(TestError::Fail("nope".into(), vec![invocation])),
            &last_trace,
            &last_failure,
            &Rc::new(RefCell::new(None)),
            &Rc::new(RefCell::new(None)),
            &[],
        );

        assert_failure_reason_eq(&result, "failure");
        assert!(result.minimized.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_with_transport_reports_connect_error() {
        let result = run_with_transport(
            connect_result(Err(SessionError::Transport(Box::new(
                std::io::Error::other("connect failed"),
            )))),
            "local",
            &RunConfig::new(),
            RunnerOptions::default(),
        )
        .await;

        assert_failure_reason_contains(&result, "failed to connect local transport");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_http_reports_transport_error() {
        let config = HttpConfig {
            url: "http://localhost:1234/mcp".to_string(),
            auth_token: None,
        };
        let result = run_http(&config, &RunConfig::new(), RunnerOptions::default()).await;
        assert_failure(&result);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_stdio_reports_transport_error() {
        let config = StdioConfig::new("mcp-server");
        let result = run_stdio(&config, &RunConfig::new(), RunnerOptions::default()).await;
        assert_failure(&result);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn runner_transport_ignores_unhandled_request() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let mut transport = RunnerTransport::new(tool, response);
        let request = ClientJsonRpcMessage::request(
            ClientRequest::ListPromptsRequest(rmcp::model::ListPromptsRequest {
                method: Default::default(),
                params: Some(rmcp::model::PaginatedRequestParam { cursor: None }),
                extensions: Default::default(),
            }),
            rmcp::model::NumberOrString::Number(1),
        );
        let _ = transport.send(request).await;
        let _ = transport.close().await;
    }

    #[test]
    fn build_output_validators_skips_missing_schema() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let validators = build_output_validators(&[tool]).expect("validators");
        assert!(validators.is_empty());
    }

    #[test]
    fn build_output_validators_accepts_valid_schema() {
        let tool = tool_with_schemas(
            "echo",
            json!({ "type": "object" }),
            Some(json!({
                "type": "object",
                "properties": { "status": { "type": "string" } }
            })),
        );
        let validators = build_output_validators(&[tool]).expect("validators");
        assert!(validators.contains_key("echo"));
    }

    #[test]
    fn build_output_validators_reports_invalid_schema() {
        let tool = tool_with_schemas(
            "echo",
            json!({ "type": "object" }),
            Some(json!({ "type": "object", "properties": { "bad": 5 } })),
        );
        let error = build_output_validators(&[tool]).expect_err("error");
        assert!(error.contains("failed to compile output schema"));
    }

    #[test]
    fn build_input_validators_reports_invalid_schema() {
        let tool = tool_with_schemas(
            "echo",
            json!({ "type": "object", "properties": { "bad": 5 } }),
            None,
        );
        let error = build_input_validators(&[tool]).expect_err("error");
        assert!(error.contains("failed to compile input schema"));
    }

    #[test]
    fn build_input_validators_respects_declared_schema_draft() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "$schema": "http://json-schema.org/draft-04/schema#",
                "type": "object",
                "properties": {
                    "value": {
                        "type": "number",
                        "minimum": 1,
                        "exclusiveMinimum": true
                    }
                }
            }),
            None,
        );
        let validators = build_input_validators(&[tool]).expect("validators");
        assert!(validators.contains_key("echo"));
    }

    #[test]
    fn build_input_validators_supports_additional_schema_drafts() {
        let tools = vec![
            tool_with_schemas(
                "draft6",
                json!({
                    "$schema": "http://json-schema.org/draft-06/schema#",
                    "type": "object"
                }),
                None,
            ),
            tool_with_schemas(
                "draft7",
                json!({
                    "$schema": "http://json-schema.org/draft-07/schema#",
                    "type": "object"
                }),
                None,
            ),
            tool_with_schemas(
                "draft2019",
                json!({
                    "$schema": "https://json-schema.org/draft/2019-09/schema",
                    "type": "object"
                }),
                None,
            ),
        ];
        let validators = build_input_validators(&tools).expect("validators");
        assert!(validators.contains_key("draft6"));
        assert!(validators.contains_key("draft7"));
        assert!(validators.contains_key("draft2019"));
    }

    #[test]
    fn collect_schema_keyword_warnings_reports_direct_draft_defs() {
        let tool = tool_with_schemas(
            "draft07",
            json!({
                "type": "object",
                "$schema": "http://json-schema.org/draft-07/schema#",
                "$defs": { "payload": { "type": "string" } }
            }),
            None,
        );
        let mut warnings = Vec::new();
        collect_schema_keyword_warnings(
            &tool,
            "inputSchema",
            tool.input_schema.as_ref(),
            &mut warnings,
        );
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn collect_schema_keyword_warnings_ignores_modern_defs() {
        let tool = tool_with_schemas(
            "draft2020",
            json!({
                "type": "object",
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$defs": { "payload": { "type": "string" } }
            }),
            None,
        );
        let mut warnings = Vec::new();
        collect_schema_keyword_warnings(
            &tool,
            "inputSchema",
            tool.input_schema.as_ref(),
            &mut warnings,
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn validate_invocation_inputs_panics_on_schema_violation() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "type": "object",
                "properties": { "value": { "type": "string" } },
                "required": ["value"]
            }),
            None,
        );
        let validators = build_input_validators(&[tool]).expect("validators");
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: None,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            validate_invocation_inputs(&invocation, &validators);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn validate_invocation_inputs_panics_on_missing_validator() {
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: None,
        };
        let validators = std::collections::BTreeMap::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            validate_invocation_inputs(&invocation, &validators);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn validate_tools_rejects_invalid_schema() {
        let tool = tool_with_schemas("bad", json!({ "type": "string" }), None);
        let error = validate_tools(vec![tool], &SchemaConfig::default()).expect_err("error");
        assert!(error.contains("invalid tools/list"));
    }

    #[test]
    fn validate_tools_accepts_valid_schema() {
        let tool = tool_with_schemas("good", json!({ "type": "object" }), None);
        let tools = validate_tools(vec![tool], &SchemaConfig::default()).expect("valid tools");
        assert_eq!(tools.len(), 1);
    }

    #[test]
    fn coverage_tracker_mines_structured_content() {
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let config = StateMachineConfig::default();
        let mut tracker = CoverageTracker::new(&tools, &config);
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::structured(json!({ "value": 2, "label": "ok" })),
        );

        let (_, response) = entry.as_tool_call().expect("tool call entry");
        tracker.mine_response("echo", response.expect("response"));

        assert!(tracker.corpus.numbers().contains(&Number::from(2)));
        assert!(tracker.corpus.strings().contains(&"label".to_string()));
    }

    #[test]
    fn coverage_tracker_mines_text_tokens_when_enabled() {
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let config = StateMachineConfig::default().with_mine_text(true);
        let mut tracker = CoverageTracker::new(&tools, &config);
        let response = CallToolResult {
            content: vec![Content::text("gamma 1")],
            structured_content: Some(json!({ "message": "alpha beta", "count": 2 })),
            is_error: Some(false),
            meta: None,
        };

        tracker.mine_response("echo", &response);

        assert!(tracker.corpus.strings().contains(&"message".to_string()));
        assert!(tracker.corpus.strings().contains(&"alpha".to_string()));
        assert!(tracker.corpus.strings().contains(&"beta".to_string()));
        assert!(tracker.corpus.strings().contains(&"gamma".to_string()));
        assert!(tracker.corpus.numbers().contains(&Number::from(1)));
        assert!(tracker.corpus.numbers().contains(&Number::from(2)));
    }

    #[test]
    fn coverage_tracker_logs_corpus_deltas_when_enabled() {
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let config = StateMachineConfig::default()
            .with_mine_text(true)
            .with_log_corpus_deltas(true);
        let mut tracker = CoverageTracker::new(&tools, &config);
        let response = CallToolResult::success(vec![Content::text("hello 1")]);

        tracker.mine_response("echo", &response);
    }

    #[test]
    fn coverage_tracker_mines_text_from_resource_content() {
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let config = StateMachineConfig::default().with_mine_text(true);
        let mut tracker = CoverageTracker::new(&tools, &config);
        let response = CallToolResult {
            content: vec![Content::embedded_text("resource://text", "delta 5")],
            structured_content: None,
            is_error: Some(false),
            meta: None,
        };

        tracker.mine_response("echo", &response);

        assert!(tracker.corpus.strings().contains(&"delta".to_string()));
        assert!(tracker.corpus.numbers().contains(&Number::from(5)));
    }

    #[test]
    fn coverage_tracker_mines_text_from_resource_payload() {
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let config = StateMachineConfig::default().with_mine_text(true);
        let mut tracker = CoverageTracker::new(&tools, &config);
        let response = CallToolResult {
            content: vec![Content::resource(ResourceContents::TextResourceContents {
                uri: "resource://payload".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: "echo 7".to_string(),
                meta: None,
            })],
            structured_content: None,
            is_error: Some(false),
            meta: None,
        };

        tracker.mine_response("echo", &response);

        assert!(tracker.corpus.strings().contains(&"echo".to_string()));
        assert!(tracker.corpus.numbers().contains(&Number::from(7)));
    }

    #[test]
    fn coverage_tracker_ignores_blob_resource_content() {
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let config = StateMachineConfig::default().with_mine_text(true);
        let mut tracker = CoverageTracker::new(&tools, &config);
        let response = CallToolResult {
            content: vec![Content::resource(ResourceContents::BlobResourceContents {
                uri: "resource://blob".to_string(),
                mime_type: Some("application/octet-stream".to_string()),
                blob: "ZGF0YQ==".to_string(),
                meta: None,
            })],
            structured_content: None,
            is_error: Some(false),
            meta: None,
        };

        tracker.mine_response("echo", &response);

        assert!(tracker.corpus.strings().is_empty());
        assert!(tracker.corpus.numbers().is_empty());
    }

    #[test]
    fn coverage_tracker_ignores_image_content_for_text_mining() {
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let config = StateMachineConfig::default().with_mine_text(true);
        let mut tracker = CoverageTracker::new(&tools, &config);
        let response = CallToolResult {
            content: vec![Content::image("iVBORw0KGgo=", "image/png")],
            structured_content: None,
            is_error: Some(false),
            meta: None,
        };

        tracker.mine_response("echo", &response);

        assert!(tracker.corpus.strings().is_empty());
        assert!(tracker.corpus.numbers().is_empty());
    }

    #[test]
    fn coverage_tracker_skips_text_mining_for_error_responses() {
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let config = StateMachineConfig::default().with_mine_text(true);
        let mut tracker = CoverageTracker::new(&tools, &config);
        let response = CallToolResult::error(vec![Content::text("boom 3")]);

        tracker.mine_response("echo", &response);

        assert!(tracker.corpus.strings().is_empty());
        assert!(tracker.corpus.numbers().is_empty());
        assert!(tracker.corpus.integers().is_empty());
    }

    #[test]
    fn coverage_tracker_merge_aggregates_corpus_and_counts() {
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
        let tools = vec![tool];
        let config = StateMachineConfig::default();
        let mut tracker = CoverageTracker::new(&tools, &config);
        let response = CallToolResult::structured(json!({ "text": "alpha" }));

        tracker.record_success("echo");
        tracker.mine_response("echo", &response);

        let mut aggregate = CoverageTracker::new(&tools, &config);
        aggregate.merge_from(&tracker);
        let report = aggregate.report();

        assert_eq!(report.counts.get("echo").copied(), Some(1));
        assert_warnings_empty(&report.warnings);
    }

    #[test]
    fn coverage_tracker_ignores_missing_structured_content() {
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let config = StateMachineConfig::default();
        let mut tracker = CoverageTracker::new(&tools, &config);
        let entry = trace_entry_with(
            "echo",
            None,
            CallToolResult::success(vec![Content::text("ok")]),
        );

        let (_, response) = entry.as_tool_call().expect("tool call entry");
        tracker.mine_response("echo", response.expect("response"));

        assert!(tracker.corpus.numbers().is_empty());
        assert!(tracker.corpus.strings().is_empty());
    }

    #[test]
    fn coverage_tracker_finalize_reports_warnings() {
        let tools = vec![tool_with_schemas(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        )];
        let config = StateMachineConfig::default();
        let tracker = CoverageTracker::new(&tools, &config);
        let report = tracker.finalize();
        assert!(!report.warnings.is_empty());
    }

    #[test]
    fn coverage_tracker_skips_blocklisted_tools() {
        let tools = vec![tool_with_schemas(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        )];
        let config =
            StateMachineConfig::default().with_coverage_blocklist(vec!["echo".to_string()]);
        let tracker = CoverageTracker::new(&tools, &config);
        let warnings = tracker.build_warnings();
        assert!(warnings.is_empty());
    }

    #[test]
    fn coverage_tracker_respects_allowlist_for_warnings() {
        let alpha = tool_with_schemas(
            "alpha",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        );
        let beta = tool_with_schemas(
            "beta",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        );
        let config =
            StateMachineConfig::default().with_coverage_allowlist(vec!["alpha".to_string()]);
        let tools = vec![alpha, beta];
        let tracker = CoverageTracker::new(&tools, &config);

        let warnings = tracker.build_warnings();

        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].tool, "alpha");
        assert_eq!(warnings[0].reason, CoverageWarningReason::MissingString);
    }

    #[test]
    fn coverage_tracker_validate_returns_ok_when_rules_empty() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let config = StateMachineConfig::default();
        let tools = vec![tool];
        let tracker = CoverageTracker::new(&tools, &config);
        assert!(tracker.validate(&[]).is_ok());
    }

    #[test]
    fn coverage_tracker_min_calls_per_tool_reports_failure() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let config = StateMachineConfig::default();
        let tools = vec![tool];
        let tracker = CoverageTracker::new(&tools, &config);
        let error = tracker
            .validate(&[CoverageRule::min_calls_per_tool(1)])
            .expect_err("expected failure");
        assert_eq!(error.details["rule"], "min_calls_per_tool");
    }

    #[test]
    fn coverage_tracker_reports_no_uncalled_tools_failure() {
        let alpha = tool_with_schemas(
            "alpha",
            json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            }),
            None,
        );
        let beta = tool_with_schemas(
            "beta",
            json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            }),
            None,
        );
        let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
        let tools = vec![alpha, beta];
        let tracker = CoverageTracker::new(&tools, &config);
        let error = tracker
            .validate(&[CoverageRule::no_uncalled_tools()])
            .expect_err("expected failure");
        assert_eq!(error.details["rule"], "no_uncalled_tools");
    }

    #[test]
    fn coverage_tracker_min_calls_per_tool_succeeds() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            }),
            None,
        );
        let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
        let tools = vec![tool];
        let mut tracker = CoverageTracker::new(&tools, &config);
        tracker.record_success("echo");
        assert!(tracker
            .validate(&[CoverageRule::min_calls_per_tool(1)])
            .is_ok());
    }

    #[test]
    fn coverage_tracker_no_uncalled_tools_succeeds() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            }),
            None,
        );
        let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
        let tools = vec![tool];
        let mut tracker = CoverageTracker::new(&tools, &config);
        tracker.record_success("echo");
        assert!(tracker
            .validate(&[CoverageRule::no_uncalled_tools()])
            .is_ok());
    }

    #[test]
    fn coverage_tracker_reports_percent_called_failure() {
        let alpha = tool_with_schemas(
            "alpha",
            json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            }),
            None,
        );
        let beta = tool_with_schemas(
            "beta",
            json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            }),
            None,
        );
        let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
        let tools = vec![alpha, beta];
        let mut tracker = CoverageTracker::new(&tools, &config);
        tracker.record_success("alpha");
        let error = tracker
            .validate(&[CoverageRule::percent_called(100.0)])
            .expect_err("expected failure");
        assert_eq!(error.details["rule"], "percent_called");
    }

    #[test]
    fn coverage_tracker_rejects_invalid_percent_called() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let config = StateMachineConfig::default();
        let tools = vec![tool];
        let tracker = CoverageTracker::new(&tools, &config);
        let error = tracker
            .validate(&[CoverageRule::percent_called(101.0)])
            .expect_err("expected failure");
        assert_eq!(error.details["rule"], "percent_called");
        assert_eq!(error.details["error"], "min_percent_out_of_range");
    }

    #[test]
    fn coverage_tracker_percent_called_succeeds() {
        let alpha = tool_with_schemas(
            "alpha",
            json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            }),
            None,
        );
        let beta = tool_with_schemas(
            "beta",
            json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } },
                "required": ["count"]
            }),
            None,
        );
        let config = StateMachineConfig::default().with_seed_numbers(vec![Number::from(1)]);
        let tools = vec![alpha, beta];
        let mut tracker = CoverageTracker::new(&tools, &config);
        tracker.record_success("alpha");
        assert!(tracker
            .validate(&[CoverageRule::percent_called(50.0)])
            .is_ok());
    }

    #[test]
    fn coverage_tracker_skips_percent_called_when_no_callable_tools() {
        let tools = vec![tool_with_schemas(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            None,
        )];
        let config = StateMachineConfig::default();
        let tracker = CoverageTracker::new(&tools, &config);
        assert!(tracker
            .validate(&[CoverageRule::percent_called(50.0)])
            .is_ok());
    }

    #[test]
    fn eligible_tools_respects_allowlist() {
        let alpha = tool_with_schemas("alpha", json!({ "type": "object" }), None);
        let beta = tool_with_schemas("beta", json!({ "type": "object" }), None);
        let config =
            StateMachineConfig::default().with_coverage_allowlist(vec!["alpha".to_string()]);
        let tools = vec![alpha, beta];
        let tracker = CoverageTracker::new(&tools, &config);
        let eligible = tracker.eligible_tools();
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].name.as_ref(), "alpha");
    }

    #[test]
    fn eligible_tools_respects_blocklist() {
        let alpha = tool_with_schemas("alpha", json!({ "type": "object" }), None);
        let beta = tool_with_schemas("beta", json!({ "type": "object" }), None);
        let config =
            StateMachineConfig::default().with_coverage_blocklist(vec!["alpha".to_string()]);
        let tools = vec![alpha, beta];
        let tracker = CoverageTracker::new(&tools, &config);
        let eligible = tracker.eligible_tools();
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].name.as_ref(), "beta");
    }

    #[test]
    fn map_uncallable_reason_maps_variants() {
        assert_eq!(
            map_uncallable_reason(UncallableReason::Integer),
            CoverageWarningReason::MissingInteger
        );
        assert_eq!(
            map_uncallable_reason(UncallableReason::Number),
            CoverageWarningReason::MissingNumber
        );
        assert_eq!(
            map_uncallable_reason(UncallableReason::RequiredValue),
            CoverageWarningReason::MissingRequiredValue
        );
    }

    #[test]
    fn collect_schema_warnings_flags_defs_in_draft07() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "$schema": "http://json-schema.org/draft-07/schema#",
                "$defs": {
                    "thing": { "type": "string" }
                },
                "type": "object",
                "properties": {}
            }),
            None,
        );
        let warnings = collect_schema_warnings(&[tool]);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, RunWarningCode::SchemaUnsupportedKeyword);
        assert!(warnings[0].message.contains("$defs"));
    }

    #[test]
    fn collect_schema_warnings_flags_defs_in_draft06() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "$schema": "http://json-schema.org/draft-06/schema#",
                "$defs": {
                    "thing": { "type": "string" }
                },
                "type": "object",
                "properties": {}
            }),
            None,
        );
        let warnings = collect_schema_warnings(&[tool]);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, RunWarningCode::SchemaUnsupportedKeyword);
        assert!(warnings[0].message.contains("draft-06"));
    }

    #[test]
    fn collect_schema_warnings_flags_defs_in_draft04() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "$schema": "http://json-schema.org/draft-04/schema#",
                "$defs": {
                    "thing": { "type": "string" }
                },
                "type": "object",
                "properties": {}
            }),
            None,
        );
        let warnings = collect_schema_warnings(&[tool]);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, RunWarningCode::SchemaUnsupportedKeyword);
        assert!(warnings[0].message.contains("draft-04"));
    }

    #[test]
    fn collect_schema_warnings_skips_without_defs() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "properties": {}
            }),
            None,
        );
        let warnings = collect_schema_warnings(&[tool]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn collect_schema_warnings_ignores_defs_in_modern_schema() {
        let tool = tool_with_schemas(
            "echo",
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$defs": {
                    "thing": { "type": "string" }
                },
                "type": "object",
                "properties": {}
            }),
            None,
        );
        let warnings = collect_schema_warnings(&[tool]);
        assert!(warnings.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_with_coverage_reports_session_error() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool, response).with_call_tool_error(ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            "call failed",
            None,
        ));
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let session = connect_runner_transport(transport).await.expect("connect");
        let config = StateMachineConfig::default();
        let mut tracker = CoverageTracker::new(&tools, &config);
        let input_validators = build_input_validators(&tools).expect("validators");

        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: Some(JsonObject::new()),
        };
        let result = execute_sequence_with_coverage(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &AssertionSet { rules: Vec::new() },
            &[invocation],
            &mut tracker,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_with_coverage_reports_response_assertion_failure() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool, response);
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let session = connect_runner_transport(transport).await.expect("connect");
        let config = StateMachineConfig::default();
        let mut tracker = CoverageTracker::new(&tools, &config);
        let input_validators = build_input_validators(&tools).expect("validators");

        let assertions = AssertionSet {
            rules: vec![AssertionRule::Response(ResponseAssertion {
                tool: Some("echo".to_string()),
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Input,
                    pointer: "/missing".to_string(),
                    expected: json!(true),
                }],
            })],
        };
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: Some(JsonObject::new()),
        };
        let result = execute_sequence_with_coverage(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &assertions,
            &[invocation],
            &mut tracker,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_with_coverage_reports_sequence_assertion_failure() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::success(vec![Content::text("ok")]);
        let transport = RunnerTransport::new(tool, response);
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let session = connect_runner_transport(transport).await.expect("connect");
        let config = StateMachineConfig::default();
        let mut tracker = CoverageTracker::new(&tools, &config);
        let input_validators = build_input_validators(&tools).expect("validators");

        let assertions = AssertionSet {
            rules: vec![AssertionRule::Sequence(SequenceAssertion {
                checks: vec![AssertionCheck {
                    target: AssertionTarget::Sequence,
                    pointer: "/missing".to_string(),
                    expected: json!(true),
                }],
            })],
        };
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: Some(JsonObject::new()),
        };
        let result = execute_sequence_with_coverage(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &assertions,
            &[invocation],
            &mut tracker,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_with_coverage_reports_default_assertion_failure() {
        let tool = tool_with_schemas("echo", json!({ "type": "object" }), None);
        let response = CallToolResult::error(vec![Content::text("boom")]);
        let transport = RunnerTransport::new(tool, response);
        let tools = vec![tool_with_schemas("echo", json!({ "type": "object" }), None)];
        let session = connect_runner_transport(transport).await.expect("connect");
        let config = StateMachineConfig::default();
        let mut tracker = CoverageTracker::new(&tools, &config);
        let input_validators = build_input_validators(&tools).expect("validators");
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: Some(JsonObject::new()),
        };

        let result = execute_sequence_with_coverage(
            &session,
            &input_validators,
            &BTreeMap::new(),
            &AssertionSet { rules: Vec::new() },
            &[invocation],
            &mut tracker,
        )
        .await;

        let failure = result.expect_err("expected failure");
        assert!(failure
            .failure
            .reason
            .contains("returned an error response"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn execute_sequence_with_coverage_succeeds_and_tracks() {
        let tool = tool_with_schemas(
            "echo",
            json!({ "type": "object" }),
            Some(json!({
                "type": "object",
                "properties": { "status": { "type": "string", "const": "ok" } },
                "required": ["status"]
            })),
        );
        let response = CallToolResult::structured(json!({ "status": "ok" }));
        let transport = RunnerTransport::new(tool.clone(), response);
        let session = connect_runner_transport(transport).await.expect("connect");
        let input_validators = build_input_validators(&[tool.clone()]).expect("validators");
        let output_validators = build_output_validators(&[tool.clone()]).expect("validators");
        let config = StateMachineConfig::default();
        let tools = vec![tool];
        let mut tracker = CoverageTracker::new(&tools, &config);
        let invocation = ToolInvocation {
            name: "echo".to_string().into(),
            arguments: Some(JsonObject::new()),
        };

        let result = execute_sequence_with_coverage(
            &session,
            &input_validators,
            &output_validators,
            &AssertionSet { rules: Vec::new() },
            &[invocation],
            &mut tracker,
        )
        .await;

        let trace = result.expect("expected success");
        assert_eq!(trace.len(), 1);
        assert_eq!(tracker.counts.get("echo").copied(), Some(1));
    }

    #[test]
    fn trace_entry_with_accepts_object_args() {
        let entry = trace_entry_with(
            "echo",
            Some(json!({ "value": "ok" })),
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let (invocation, _) = entry.as_tool_call().expect("tool call");
        let args = invocation.arguments.clone().expect("arguments");
        assert_eq!(args.get("value"), Some(&json!("ok")));
    }

    #[test]
    fn trace_entry_with_ignores_non_object_args() {
        let entry = trace_entry_with(
            "echo",
            Some(json!(true)),
            CallToolResult::success(vec![Content::text("ok")]),
        );
        let (invocation, _) = entry.as_tool_call().expect("tool call");
        assert!(invocation.arguments.is_none());
    }
}
