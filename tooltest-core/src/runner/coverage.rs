use std::collections::BTreeMap;

use chrono::Utc;
use rmcp::model::{CallToolResult, Tool};
use serde_json::{json, Number, Value as JsonValue};

use crate::generator::{uncallable_reason, UncallableReason, ValueCorpus};
use crate::{
    CorpusReport, CoverageReport, CoverageRule, CoverageWarning, CoverageWarningReason, RunFailure,
    StateMachineConfig, ToolInvocation, UncallableToolCall,
};

const LIST_TOOLS_COUNT_LABEL: &str = "tools/list";

#[derive(Clone, Debug)]
pub(super) struct CoverageValidationFailure {
    pub(super) details: JsonValue,
}

pub(super) struct CoverageTracker<'a> {
    tools: &'a [Tool],
    corpus: ValueCorpus,
    counts: BTreeMap<String, u64>,
    failures: BTreeMap<String, u64>,
    call_history: BTreeMap<String, Vec<UncallableToolCall>>,
    uncallable_limit: usize,
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

impl<'a> CoverageTracker<'a> {
    pub(super) fn new(
        tools: &'a [Tool],
        config: &StateMachineConfig,
        uncallable_limit: usize,
    ) -> Self {
        let mut corpus = ValueCorpus::default();
        corpus.seed_numbers(config.seed_numbers.clone());
        corpus.seed_strings(config.seed_strings.clone());
        Self {
            tools,
            corpus,
            counts: BTreeMap::new(),
            failures: BTreeMap::new(),
            call_history: BTreeMap::new(),
            uncallable_limit,
            allowlist: config.coverage_allowlist.clone(),
            blocklist: config.coverage_blocklist.clone(),
            lenient_sourcing: config.lenient_sourcing,
            mine_text: config.mine_text,
            log_corpus_deltas: config.log_corpus_deltas,
        }
    }

    pub(super) fn corpus(&self) -> &ValueCorpus {
        &self.corpus
    }

    pub(super) fn lenient_sourcing(&self) -> bool {
        self.lenient_sourcing
    }

    pub(super) fn merge_from(&mut self, other: &CoverageTracker<'_>) {
        for (tool, count) in &other.counts {
            *self.counts.entry(tool.clone()).or_insert(0) += count;
        }
        for (tool, count) in &other.failures {
            *self.failures.entry(tool.clone()).or_insert(0) += count;
        }
        for (tool, calls) in &other.call_history {
            self.append_calls(tool, calls);
        }
        self.corpus.merge_from(other.corpus());
    }

    pub(super) fn report(&self) -> CoverageReport {
        let mut counts = self.counts.clone();
        let mut failures = self.failures.clone();
        for tool in self.tools {
            counts.entry(tool.name.to_string()).or_insert(0);
            failures.entry(tool.name.to_string()).or_insert(0);
        }
        counts.insert(LIST_TOOLS_COUNT_LABEL.to_string(), 1);
        CoverageReport {
            counts,
            failures,
            warnings: self.build_warnings(),
            uncallable_traces: self.uncallable_traces(),
        }
    }

    pub(super) fn corpus_report(&self) -> CorpusReport {
        CorpusReport {
            numbers: self.corpus.numbers().to_vec(),
            integers: self.corpus.integers().to_vec(),
            strings: self.corpus.strings().to_vec(),
        }
    }

    pub(super) fn record_success(&mut self, tool: &str) {
        *self.counts.entry(tool.to_string()).or_insert(0) += 1;
    }

    pub(super) fn record_failure(&mut self, tool: &str) {
        *self.failures.entry(tool.to_string()).or_insert(0) += 1;
    }

    pub(super) fn record_call(&mut self, invocation: &ToolInvocation, response: &CallToolResult) {
        let (output, error) = if response.is_error.unwrap_or(false) {
            (None, Some(response.clone()))
        } else {
            (Some(response.clone()), None)
        };
        let call = UncallableToolCall {
            input: invocation.clone(),
            output,
            error,
            timestamp: Utc::now().to_rfc3339(),
        };
        let calls = self
            .call_history
            .entry(invocation.name.to_string())
            .or_default();
        calls.push(call);
        Self::truncate_calls(calls, self.uncallable_limit);
    }

    pub(super) fn mine_response(&mut self, tool: &str, response: &CallToolResult) {
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

    pub(super) fn build_warnings(&self) -> Vec<CoverageWarning> {
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

    pub(super) fn uncallable_traces(&self) -> BTreeMap<String, Vec<UncallableToolCall>> {
        let mut traces = BTreeMap::new();
        for tool in self.eligible_tools() {
            let name = tool.name.to_string();
            let successes = *self.counts.get(&name).unwrap_or(&0);
            if successes == 0 {
                let calls = self.call_history.get(&name).cloned().unwrap_or_default();
                traces.insert(name, calls);
            }
        }
        traces
    }

    pub(super) fn validate(&self, rules: &[CoverageRule]) -> Result<(), CoverageValidationFailure> {
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

    pub(super) fn eligible_tools(&self) -> Vec<&Tool> {
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

    fn append_calls(&mut self, tool: &str, calls: &[UncallableToolCall]) {
        if calls.is_empty() {
            return;
        }
        let entries = self.call_history.entry(tool.to_string()).or_default();
        entries.extend_from_slice(calls);
        Self::truncate_calls(entries, self.uncallable_limit);
    }

    fn truncate_calls(calls: &mut Vec<UncallableToolCall>, limit: usize) {
        if limit == 0 {
            calls.clear();
            return;
        }
        if calls.len() > limit {
            let start = calls.len() - limit;
            calls.drain(0..start);
        }
    }
}

pub(super) fn map_uncallable_reason(reason: UncallableReason) -> CoverageWarningReason {
    match reason {
        UncallableReason::String => CoverageWarningReason::MissingString,
        UncallableReason::Integer => CoverageWarningReason::MissingInteger,
        UncallableReason::Number => CoverageWarningReason::MissingNumber,
        UncallableReason::RequiredValue => CoverageWarningReason::MissingRequiredValue,
    }
}

pub(super) fn coverage_failure(failure: CoverageValidationFailure) -> RunFailure {
    RunFailure {
        reason: "coverage validation failed".to_string(),
        code: Some("coverage_validation_failed".to_string()),
        details: Some(failure.details),
    }
}
