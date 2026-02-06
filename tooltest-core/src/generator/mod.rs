//! Proptest-based tool invocation generation driven by MCP schemas.
#![cfg_attr(not(test), allow(dead_code))]

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::Deref;

use nonempty::NonEmpty;
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngAlgorithm, TestRng, TestRunner};
use regex::Regex;
use regex_syntax::hir::Hir;
use regex_syntax::ParserBuilder;
use rmcp::model::{JsonObject, Tool};
use serde_json::{Number, Value as JsonValue};

use crate::{StateMachineConfig, ToolInvocation, ToolPredicate};

mod corpus;
mod schema;

pub(crate) use corpus::ValueCorpus;
use schema::value_matches_type;
#[allow(unused_imports)]
pub(crate) use schema::{
    decode_pointer_segment, path_from_pointer, Constraint, ConstraintKind, PathSegment,
};

#[cfg(test)]
#[path = "../../tests/internal/generator_unit_tests.rs"]
mod tests;

#[cfg(test)]
use corpus::number_to_i64;

thread_local! {
    static LAST_REJECT_CONTEXT: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub(crate) fn clear_reject_context() {
    LAST_REJECT_CONTEXT.with(|context| {
        *context.borrow_mut() = None;
    });
}

pub(crate) fn take_reject_context() -> Option<String> {
    LAST_REJECT_CONTEXT.with(|context| context.borrow_mut().take())
}

pub(crate) fn record_reject_context(context: String) {
    LAST_REJECT_CONTEXT.with(|stored| {
        *stored.borrow_mut() = Some(context);
    });
}

#[cfg(test)]
pub(crate) fn set_reject_context_for_test(context: String) {
    record_reject_context(context);
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedTool {
    tool: Tool,
    patterns: SchemaRegexIndex,
}

impl PreparedTool {
    pub(crate) fn new(tool: Tool) -> Self {
        let patterns = SchemaRegexIndex::from_schema(tool.input_schema.as_ref());
        Self { tool, patterns }
    }

    pub(crate) fn patterns(&self) -> &SchemaRegexIndex {
        &self.patterns
    }
}

impl From<Tool> for PreparedTool {
    fn from(tool: Tool) -> Self {
        Self::new(tool)
    }
}

pub(crate) fn prepare_tools(tools: Vec<Tool>) -> Vec<PreparedTool> {
    tools.into_iter().map(PreparedTool::from).collect()
}

impl Deref for PreparedTool {
    type Target = Tool;

    fn deref(&self) -> &Self::Target {
        &self.tool
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SchemaRegexIndex {
    patterns: HashMap<String, CompiledPattern>,
}

impl SchemaRegexIndex {
    pub(crate) fn from_schema(schema: &JsonObject) -> Self {
        let mut pattern_set = HashSet::new();
        collect_pattern_strings_from_object(schema, &mut pattern_set);
        let patterns = pattern_set
            .into_iter()
            .map(|pattern| {
                let compiled = CompiledPattern::new(&pattern);
                (pattern, compiled)
            })
            .collect();
        Self { patterns }
    }

    fn pattern(&self, pattern: &str) -> Option<&CompiledPattern> {
        self.patterns.get(pattern)
    }
}

#[derive(Clone, Debug)]
struct CompiledPattern {
    generation: Result<CompiledGenerationPattern, PatternGenerationError>,
    validation: Result<Regex, regex::Error>,
}

impl CompiledPattern {
    fn new(pattern: &str) -> Self {
        let validation = Regex::new(pattern);
        let generation = compile_generation_pattern(pattern);
        Self {
            generation,
            validation,
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledGenerationPattern {
    hir: Hir,
}

#[derive(Clone, Debug)]
enum PatternGenerationError {
    Unsupported(String),
    Parse(String),
}

impl PatternGenerationError {
    fn reason(&self) -> String {
        match self {
            PatternGenerationError::Unsupported(reason) => reason.clone(),
            PatternGenerationError::Parse(error) => {
                format!("pattern must be a valid regex: {error}")
            }
        }
    }
}

/// Errors emitted while generating tool invocations from schema data.
#[derive(Debug)]
pub(crate) enum InvocationError {
    /// No tools are eligible for invocation generation.
    NoEligibleTools,
    /// Schema data could not be interpreted for generation.
    UnsupportedSchema { tool: String, reason: String },
}

impl fmt::Display for InvocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvocationError::NoEligibleTools => write!(f, "no eligible tools to generate"),
            InvocationError::UnsupportedSchema { tool, reason } => {
                write!(f, "unsupported schema for tool '{tool}': {reason}")
            }
        }
    }
}

impl std::error::Error for InvocationError {}

#[derive(Clone, Debug)]
pub(crate) struct StateMachineSequence {
    pub(crate) seeds: Vec<u64>,
}

impl StateMachineSequence {
    fn empty() -> Self {
        Self { seeds: Vec::new() }
    }
}

/// Builds a proptest strategy that yields tool invocations from MCP tool schemas.
pub(crate) fn invocation_strategy(
    tools: &[PreparedTool],
    predicate: Option<&ToolPredicate>,
) -> Result<BoxedStrategy<ToolInvocation>, InvocationError> {
    let mut strategies = Vec::new();
    for tool in tools {
        let tool_name = tool.name.clone();
        let predicate_name = tool.name.to_string();
        let arguments = input_object_strategy(tool)?;
        let predicate = predicate.cloned();

        let strategy = arguments
            .prop_filter_map("predicate rejected tool input", move |args| {
                if let Some(predicate) = &predicate {
                    let input = JsonValue::Object(args.clone());
                    if !predicate(&predicate_name, &input) {
                        return None;
                    }
                }
                Some(ToolInvocation {
                    name: tool_name.clone(),
                    arguments: Some(args),
                })
            })
            .boxed();

        strategies.push(strategy);
    }

    if strategies.is_empty() {
        return Err(InvocationError::NoEligibleTools);
    }

    let union = proptest::strategy::Union::new(strategies).boxed();
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    if union.new_tree(&mut runner).is_err() {
        return Err(InvocationError::NoEligibleTools);
    }
    Ok(union)
}

/// Builds a strategy that yields sequences of tool invocations.
pub(crate) fn invocation_sequence_strategy(
    tools: &[PreparedTool],
    predicate: Option<&ToolPredicate>,
    len_range: std::ops::RangeInclusive<usize>,
) -> Result<BoxedStrategy<Vec<ToolInvocation>>, InvocationError> {
    let invocation = invocation_strategy(tools, predicate)?;
    Ok(proptest::collection::vec(invocation, len_range).boxed())
}

pub(crate) fn invocation_strategy_from_corpus(
    tools: &[PreparedTool],
    predicate: Option<&ToolPredicate>,
    corpus: &ValueCorpus,
    lenient_sourcing: bool,
) -> Result<Option<BoxedStrategy<ToolInvocation>>, InvocationError> {
    let mut strategies = Vec::new();
    for tool in tools {
        if let Some(strategy) = invocation_from_corpus(tool, predicate, corpus, lenient_sourcing) {
            strategies.push(strategy.boxed());
        }
    }

    if strategies.is_empty() {
        return Ok(None);
    }

    let union = proptest::strategy::Union::new(strategies).boxed();
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    if union.new_tree(&mut runner).is_err() {
        return Err(InvocationError::NoEligibleTools);
    }
    Ok(Some(union))
}

pub(crate) fn invocation_from_corpus_seeded(
    tools: &[PreparedTool],
    predicate: Option<&ToolPredicate>,
    corpus: &ValueCorpus,
    lenient_sourcing: bool,
    seed: u64,
) -> Result<Option<ToolInvocation>, InvocationError> {
    Ok(invocation_plan_from_corpus_seeded(tools, predicate, corpus, lenient_sourcing, seed)?
        .map(|(_tool_index, invocation)| invocation))
}

pub(crate) fn invocation_plan_from_corpus_seeded(
    tools: &[PreparedTool],
    predicate: Option<&ToolPredicate>,
    corpus: &ValueCorpus,
    lenient_sourcing: bool,
    seed: u64,
) -> Result<Option<(usize, ToolInvocation)>, InvocationError> {
    validate_state_machine_tools(tools)?;
    let Some(strategy) =
        invocation_plan_strategy_from_corpus(tools, predicate, corpus, lenient_sourcing)?
    else {
        return Ok(None);
    };
    let mut runner = seeded_test_runner(seed);
    Ok(invocation_plan_from_strategy(&strategy, &mut runner))
}

fn invocation_plan_strategy_from_corpus(
    tools: &[PreparedTool],
    predicate: Option<&ToolPredicate>,
    corpus: &ValueCorpus,
    lenient_sourcing: bool,
) -> Result<Option<BoxedStrategy<(usize, ToolInvocation)>>, InvocationError> {
    let mut strategies: Vec<BoxedStrategy<(usize, ToolInvocation)>> = Vec::new();
    for (tool_index, tool) in tools.iter().enumerate() {
        if let Some(strategy) = invocation_from_corpus(tool, predicate, corpus, lenient_sourcing) {
            strategies.push(
                strategy
                    .prop_map(move |invocation| (tool_index, invocation))
                    .boxed(),
            );
        }
    }

    if strategies.is_empty() {
        return Ok(None);
    }

    let union = proptest::strategy::Union::new(strategies).boxed();
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    if union.new_tree(&mut runner).is_err() {
        return Err(InvocationError::NoEligibleTools);
    }
    Ok(Some(union))
}

fn invocation_from_strategy(
    strategy: &BoxedStrategy<ToolInvocation>,
    runner: &mut TestRunner,
) -> Option<ToolInvocation> {
    match strategy.new_tree(runner) {
        Ok(tree) => Some(tree.current()),
        Err(_) => None,
    }
}

fn invocation_plan_from_strategy(
    strategy: &BoxedStrategy<(usize, ToolInvocation)>,
    runner: &mut TestRunner,
) -> Option<(usize, ToolInvocation)> {
    match strategy.new_tree(runner) {
        Ok(tree) => Some(tree.current()),
        Err(_) => None,
    }
}

fn seeded_test_runner(seed: u64) -> TestRunner {
    let config = ProptestConfig {
        rng_algorithm: RngAlgorithm::ChaCha,
        ..ProptestConfig::default()
    };
    let seed_bytes = seed_bytes(seed, 32);
    let rng = TestRng::from_seed(config.rng_algorithm, &seed_bytes);
    TestRunner::new_with_rng(config, rng)
}

fn seed_bytes(seed: u64, len: usize) -> Vec<u8> {
    let bytes = seed.to_le_bytes();
    let mut output = Vec::with_capacity(len);
    while output.len() < len {
        output.extend_from_slice(&bytes);
    }
    output.truncate(len);
    output
}

pub(crate) fn state_machine_sequence_strategy(
    tools: &[PreparedTool],
    predicate: Option<&ToolPredicate>,
    config: &StateMachineConfig,
    len_range: std::ops::RangeInclusive<usize>,
) -> Result<BoxedStrategy<StateMachineSequence>, InvocationError> {
    validate_state_machine_tools(tools)?;
    let mut corpus = ValueCorpus::default();
    corpus.seed_numbers(config.seed_numbers.clone());
    corpus.seed_strings(config.seed_strings.clone());
    let has_callable =
        invocation_strategy_from_corpus(tools, predicate, &corpus, config.lenient_sourcing)?;
    if has_callable.is_none() {
        return Ok(Just(StateMachineSequence::empty()).boxed());
    }

    Ok(proptest::collection::vec(any::<u64>(), len_range)
        .prop_map(|seeds| StateMachineSequence { seeds })
        .boxed())
}

fn validate_state_machine_tools(tools: &[PreparedTool]) -> Result<(), InvocationError> {
    for tool in tools {
        let schema = tool.input_schema.as_ref();
        match schema.get("type") {
            Some(JsonValue::String(schema_type)) if schema_type == "object" => {}
            Some(JsonValue::String(other)) => {
                return Err(InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: format!("inputSchema type must be object, got {other}"),
                })
            }
            Some(_) => {
                return Err(InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: "inputSchema type must be a string".to_string(),
                })
            }
            None => {
                return Err(InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: "inputSchema missing type".to_string(),
                })
            }
        }

        let required_error = match schema.get("required") {
            Some(JsonValue::Array(required)) => match schema.get("properties") {
                Some(JsonValue::Object(properties)) => {
                    let required_keys = required
                        .iter()
                        .filter_map(JsonValue::as_str)
                        .collect::<Vec<_>>();
                    if required_keys
                        .iter()
                        .all(|key| properties.contains_key(*key))
                    {
                        None
                    } else {
                        Some(InvocationError::UnsupportedSchema {
                            tool: tool.name.to_string(),
                            reason: "inputSchema required must reference known properties"
                                .to_string(),
                        })
                    }
                }
                _ => {
                    if required.is_empty() {
                        None
                    } else {
                        Some(missing_properties_required_error(tool))
                    }
                }
            },
            _ => None,
        };
        if let Some(error) = required_error {
            return Err(error);
        }

        for (name, schema_value) in schema
            .get("properties")
            .and_then(JsonValue::as_object)
            .into_iter()
            .flat_map(|properties| properties.iter())
        {
            let schema_object =
                schema_value
                    .as_object()
                    .ok_or_else(|| InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: format!("property '{name}' schema must be an object"),
                    })?;
            if let Err(error) = schema_value_strategy(schema_object, tool) {
                let detail = schema_error_detail(error);
                let schema_json = JsonValue::Object(schema_object.clone()).to_string();
                return Err(InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: format!(
                        "property '{name}' schema unsupported: {detail}; schema={schema_json}"
                    ),
                });
            }
        }
    }
    Ok(())
}

fn schema_error_detail(error: InvocationError) -> String {
    match error {
        InvocationError::UnsupportedSchema { reason, .. } => reason,
        InvocationError::NoEligibleTools => "no eligible tools to generate".to_string(),
    }
}

fn missing_properties_required_error(tool: &PreparedTool) -> InvocationError {
    InvocationError::UnsupportedSchema {
        tool: tool.name.to_string(),
        reason: "inputSchema required must be empty when no properties exist".to_string(),
    }
}

fn invocation_from_corpus(
    tool: &PreparedTool,
    predicate: Option<&ToolPredicate>,
    corpus: &ValueCorpus,
    lenient_sourcing: bool,
) -> Option<BoxedStrategy<ToolInvocation>> {
    let strategy = invocation_from_corpus_unfiltered(tool, corpus, lenient_sourcing)?;
    let predicate = predicate.cloned();
    let tool_name = tool.name.clone();
    if predicate.is_none() {
        return Some(strategy);
    }
    Some(
        strategy
            .prop_filter_map("predicate rejected tool input", move |invocation| {
                let allowed = predicate.as_ref().is_some_and(|predicate| {
                    let input = invocation
                        .arguments
                        .clone()
                        .map(JsonValue::Object)
                        .unwrap_or(JsonValue::Null);
                    predicate(tool_name.as_ref(), &input)
                });
                if allowed {
                    Some(invocation)
                } else {
                    record_reject_context(format!(
                        "predicate rejected tool '{}'",
                        tool_name.as_ref()
                    ));
                    None
                }
            })
            .boxed(),
    )
}

fn invocation_from_corpus_unfiltered(
    tool: &PreparedTool,
    corpus: &ValueCorpus,
    lenient_sourcing: bool,
) -> Option<BoxedStrategy<ToolInvocation>> {
    let schema = tool.input_schema.as_ref();
    match schema_object_union_branches(schema, tool) {
        Ok(Some((kind, branches, base))) => {
            let omit_optional = matches!(kind, ObjectUnionKind::OneOf);
            let mut required_sets = Vec::with_capacity(branches.len());
            let mut merged_branches = Vec::with_capacity(branches.len());
            for branch in branches {
                let merged = merge_object_schema(&base, &branch);
                required_sets.push(required_key_set(&merged));
                merged_branches.push(merged);
            }
            let mut strategies = Vec::new();
            for (idx, merged) in merged_branches.into_iter().enumerate() {
                let forbidden = forbidden_keys_for_oneof(kind, &required_sets, idx);
                if let Some(strategy) = invocation_from_corpus_for_schema(
                    tool,
                    &merged,
                    corpus,
                    omit_optional,
                    &forbidden,
                    lenient_sourcing,
                ) {
                    strategies.push(strategy);
                }
            }
            if strategies.is_empty() {
                return None;
            }
            let union = proptest::strategy::Union::new(strategies).boxed();
            return Some(union);
        }
        Ok(None) => {}
        Err(_) => return None,
    }

    let omit_keys = HashSet::new();
    invocation_from_corpus_for_schema(tool, schema, corpus, false, &omit_keys, lenient_sourcing)
}

fn invocation_from_corpus_for_schema(
    tool: &PreparedTool,
    schema: &JsonObject,
    corpus: &ValueCorpus,
    omit_optional: bool,
    omit_keys: &HashSet<String>,
    lenient_sourcing: bool,
) -> Option<BoxedStrategy<ToolInvocation>> {
    if schema.get("$ref").is_some() || schema.get("allOf").is_some() {
        let resolved = resolve_object_schema(schema, tool).ok()?;
        if &resolved != schema {
            return invocation_from_corpus_for_schema(
                tool,
                &resolved,
                corpus,
                omit_optional,
                omit_keys,
                lenient_sourcing,
            );
        }
    }

    let properties = match schema.get("properties") {
        Some(JsonValue::Object(map)) => map,
        Some(_) => return None,
        None => {
            let missing_required = schema
                .get("required")
                .and_then(JsonValue::as_array)
                .map(|required| !required.is_empty())
                .unwrap_or(false);
            if missing_required {
                return None;
            }
            let invocation = ToolInvocation {
                name: tool.name.clone(),
                arguments: Some(JsonObject::new()),
            };
            return Some(Just(invocation).boxed());
        }
    };

    let required_keys = required_key_set(schema);

    let mut property_strategies = Vec::with_capacity(properties.len());
    for (name, schema_value) in properties {
        let schema_object = schema_value.as_object()?;
        let required = required_keys.contains(name);
        let allow_schema_fallback = lenient_sourcing || omit_optional;
        match property_strategy_from_corpus(
            schema_object,
            required,
            corpus,
            tool,
            allow_schema_fallback,
        ) {
            PropertyOutcome::Include(strategy) => {
                let strategy = if omit_optional && !required {
                    prop_oneof![Just(None), strategy.prop_map(Some)].boxed()
                } else if omit_keys.contains(name) && !required {
                    Just(None).boxed()
                } else {
                    strategy.prop_map(Some).boxed()
                };
                property_strategies.push((name.clone(), strategy));
            }
            PropertyOutcome::Omit => {}
            PropertyOutcome::MissingRequired => return None,
        }
    }

    let mut strategy: BoxedStrategy<Vec<(String, Option<JsonValue>)>> = Just(Vec::new()).boxed();
    for (name, value_strategy) in property_strategies {
        strategy = strategy
            .prop_flat_map(move |entries| {
                let name = name.clone();
                let value_strategy = value_strategy.clone();
                value_strategy.prop_map(move |value| {
                    let mut next = entries.clone();
                    next.push((name.clone(), value));
                    next
                })
            })
            .boxed();
    }

    let tool_name = tool.name.clone();
    Some(
        strategy
            .prop_map(move |entries| {
                let mut map = JsonObject::new();
                for (name, value) in entries {
                    if let Some(value) = value {
                        map.insert(name, value);
                    }
                }
                ToolInvocation {
                    name: tool_name.clone(),
                    arguments: Some(map),
                }
            })
            .boxed(),
    )
}

enum PropertyOutcome {
    Include(BoxedStrategy<JsonValue>),
    Omit,
    MissingRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemaType {
    String,
    Integer,
    Number,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UncallableReason {
    String,
    Integer,
    Number,
    RequiredValue,
}

fn property_strategy_from_corpus(
    schema: &JsonObject,
    required: bool,
    corpus: &ValueCorpus,
    tool: &PreparedTool,
    lenient_sourcing: bool,
) -> PropertyOutcome {
    if schema.get("enum").is_some() {
        return match schema_value_strategy(schema, tool) {
            Ok(strategy) => PropertyOutcome::Include(strategy),
            Err(_) => {
                if required {
                    PropertyOutcome::MissingRequired
                } else {
                    PropertyOutcome::Omit
                }
            }
        };
    }
    match schema_type_hint(schema) {
        Some(SchemaType::String) => {
            let values = corpus
                .strings()
                .iter()
                .map(|value| JsonValue::String(value.clone()))
                .filter(|value| schema_violations(schema, value, tool.patterns()).is_empty())
                .collect::<Vec<_>>();
            if values.is_empty() {
                return if required {
                    if lenient_sourcing {
                        match schema_value_strategy(schema, tool) {
                            Ok(strategy) => PropertyOutcome::Include(strategy),
                            Err(_) => PropertyOutcome::MissingRequired,
                        }
                    } else {
                        PropertyOutcome::MissingRequired
                    }
                } else {
                    PropertyOutcome::Omit
                };
            }
            PropertyOutcome::Include(proptest::sample::select(values).boxed())
        }
        Some(SchemaType::Integer) => {
            let values = corpus
                .integers()
                .iter()
                .map(|value| JsonValue::Number(Number::from(*value)))
                .filter(|value| schema_violations(schema, value, tool.patterns()).is_empty())
                .collect::<Vec<_>>();
            if values.is_empty() {
                return if required {
                    if lenient_sourcing {
                        match schema_value_strategy(schema, tool) {
                            Ok(strategy) => PropertyOutcome::Include(strategy),
                            Err(_) => PropertyOutcome::MissingRequired,
                        }
                    } else {
                        PropertyOutcome::MissingRequired
                    }
                } else {
                    PropertyOutcome::Omit
                };
            }
            PropertyOutcome::Include(proptest::sample::select(values).boxed())
        }
        Some(SchemaType::Number) => {
            let values = corpus
                .numbers()
                .iter()
                .map(|value| JsonValue::Number(value.clone()))
                .filter(|value| schema_violations(schema, value, tool.patterns()).is_empty())
                .collect::<Vec<_>>();
            if values.is_empty() {
                return if required {
                    if lenient_sourcing {
                        match schema_value_strategy(schema, tool) {
                            Ok(strategy) => PropertyOutcome::Include(strategy),
                            Err(_) => PropertyOutcome::MissingRequired,
                        }
                    } else {
                        PropertyOutcome::MissingRequired
                    }
                } else {
                    PropertyOutcome::Omit
                };
            }
            PropertyOutcome::Include(proptest::sample::select(values).boxed())
        }
        _ => match schema_value_strategy(schema, tool) {
            Ok(strategy) => PropertyOutcome::Include(strategy),
            Err(_) => PropertyOutcome::MissingRequired,
        },
    }
}

fn schema_type_hint(schema: &JsonObject) -> Option<SchemaType> {
    if let Some(schema_type) = schema.get("type").and_then(JsonValue::as_str) {
        return match schema_type {
            "string" => Some(SchemaType::String),
            "integer" => Some(SchemaType::Integer),
            "number" => Some(SchemaType::Number),
            _ => None,
        };
    }
    if let Some(JsonValue::String(_)) = schema.get("const") {
        return Some(SchemaType::String);
    }
    if let Some(JsonValue::Number(_)) = schema.get("const") {
        return Some(SchemaType::Number);
    }
    if let Some(JsonValue::Array(values)) = schema.get("enum") {
        if values
            .iter()
            .all(|value| matches!(value, JsonValue::String(_)))
        {
            return Some(SchemaType::String);
        }
        if values
            .iter()
            .all(|value| matches!(value, JsonValue::Number(_)))
        {
            return Some(SchemaType::Number);
        }
    }
    None
}

pub(crate) fn uncallable_reason(
    tool: &PreparedTool,
    corpus: &ValueCorpus,
    lenient_sourcing: bool,
) -> Option<UncallableReason> {
    let schema = tool.input_schema.as_ref();
    let properties = match schema.get("properties") {
        Some(JsonValue::Object(map)) => map,
        Some(_) => return Some(UncallableReason::RequiredValue),
        None => {
            return match schema.get("required") {
                Some(JsonValue::Array(required)) if !required.is_empty() => {
                    Some(UncallableReason::RequiredValue)
                }
                _ => None,
            };
        }
    };

    let mut required_keys = schema
        .get("required")
        .and_then(JsonValue::as_array)
        .map(|required| {
            required
                .iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    required_keys.sort();

    for name in required_keys {
        let Some(schema_value) = properties.get(&name) else {
            return Some(UncallableReason::RequiredValue);
        };
        let Some(schema_object) = schema_value.as_object() else {
            return Some(UncallableReason::RequiredValue);
        };
        if schema_object.get("enum").is_some() {
            if schema_value_strategy(schema_object, tool).is_err() {
                return Some(UncallableReason::RequiredValue);
            }
            continue;
        }
        let reason = match schema_type_hint(schema_object) {
            Some(SchemaType::String) => {
                let has_match = corpus
                    .strings()
                    .iter()
                    .map(|value| JsonValue::String(value.clone()))
                    .any(|value| {
                        schema_violations(schema_object, &value, tool.patterns()).is_empty()
                    });
                if has_match {
                    None
                } else if lenient_sourcing {
                    schema_value_strategy(schema_object, tool)
                        .err()
                        .map(|_| UncallableReason::RequiredValue)
                } else if schema_value_strategy(schema_object, tool).is_err() {
                    Some(UncallableReason::RequiredValue)
                } else {
                    Some(UncallableReason::String)
                }
            }
            Some(SchemaType::Integer) => {
                let has_match = corpus
                    .integers()
                    .iter()
                    .map(|value| JsonValue::Number(Number::from(*value)))
                    .any(|value| {
                        schema_violations(schema_object, &value, tool.patterns()).is_empty()
                    });
                if has_match {
                    None
                } else if lenient_sourcing {
                    schema_value_strategy(schema_object, tool)
                        .err()
                        .map(|_| UncallableReason::RequiredValue)
                } else if schema_value_strategy(schema_object, tool).is_err() {
                    Some(UncallableReason::RequiredValue)
                } else {
                    Some(UncallableReason::Integer)
                }
            }
            Some(SchemaType::Number) => {
                let has_match = corpus
                    .numbers()
                    .iter()
                    .map(|value| JsonValue::Number(value.clone()))
                    .any(|value| {
                        schema_violations(schema_object, &value, tool.patterns()).is_empty()
                    });
                if has_match {
                    None
                } else if lenient_sourcing {
                    schema_value_strategy(schema_object, tool)
                        .err()
                        .map(|_| UncallableReason::RequiredValue)
                } else if schema_value_strategy(schema_object, tool).is_err() {
                    Some(UncallableReason::RequiredValue)
                } else {
                    Some(UncallableReason::Number)
                }
            }
            None => schema_value_strategy(schema_object, tool)
                .err()
                .map(|_| UncallableReason::RequiredValue),
        };
        if let Some(reason) = reason {
            return Some(reason);
        }
    }

    None
}

fn input_object_strategy(
    tool: &PreparedTool,
) -> Result<BoxedStrategy<JsonObject>, InvocationError> {
    let omit_keys = HashSet::new();
    input_object_strategy_for_schema(tool.input_schema.as_ref(), tool, false, &omit_keys)
}

fn input_object_strategy_for_schema(
    schema: &JsonObject,
    tool: &PreparedTool,
    omit_optional: bool,
    omit_keys: &HashSet<String>,
) -> Result<BoxedStrategy<JsonObject>, InvocationError> {
    if schema.get("$ref").is_some() || schema.get("allOf").is_some() {
        let resolved = resolve_object_schema(schema, tool)?;
        if &resolved != schema {
            return input_object_strategy_for_schema(&resolved, tool, omit_optional, omit_keys);
        }
    }

    match schema.get("type") {
        Some(JsonValue::String(schema_type)) if schema_type == "object" => {}
        Some(JsonValue::String(other)) => {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: format!("inputSchema type must be object, got {other}"),
            })
        }
        Some(_) => {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "inputSchema type must be a string".to_string(),
            })
        }
        None => {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "inputSchema missing type".to_string(),
            })
        }
    }

    if let Some((kind, branches, base)) = schema_object_union_branches(schema, tool)? {
        let omit_optional = matches!(kind, ObjectUnionKind::OneOf);
        let mut required_sets = Vec::with_capacity(branches.len());
        let mut merged_branches = Vec::with_capacity(branches.len());
        for branch in branches {
            let merged = merge_object_schema(&base, &branch);
            required_sets.push(required_key_set(&merged));
            merged_branches.push(merged);
        }
        let mut strategies = Vec::with_capacity(merged_branches.len());
        for (idx, merged) in merged_branches.into_iter().enumerate() {
            let forbidden = forbidden_keys_for_oneof(kind, &required_sets, idx);
            strategies.push(input_object_strategy_for_schema(
                &merged,
                tool,
                omit_optional,
                &forbidden,
            )?);
        }
        let union = proptest::strategy::Union::new(strategies).boxed();
        return Ok(union);
    }

    let properties = match schema.get("properties") {
        Some(JsonValue::Object(map)) => map,
        Some(_) => {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "inputSchema properties must be an object".to_string(),
            })
        }
        None => {
            if let Some(JsonValue::Array(required)) = schema.get("required") {
                if !required.is_empty() {
                    return Err(InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: "inputSchema required must be empty when no properties exist"
                            .to_string(),
                    });
                }
            }
            return Ok(Just(JsonObject::new()).boxed());
        }
    };

    let required_keys = required_key_set(schema);

    if !required_keys.iter().all(|key| properties.contains_key(key)) {
        return Err(InvocationError::UnsupportedSchema {
            tool: tool.name.to_string(),
            reason: "inputSchema required must reference known properties".to_string(),
        });
    }

    let mut property_strategies = Vec::with_capacity(properties.len());
    for (name, schema_value) in properties {
        let schema_object =
            schema_value
                .as_object()
                .ok_or_else(|| InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: format!("property '{name}' schema must be an object"),
                })?;
        let strategy = schema_value_strategy(schema_object, tool)?;
        let required = required_keys.contains(name);
        let strategy = if omit_optional && !required {
            prop_oneof![Just(None), strategy.prop_map(Some)].boxed()
        } else if omit_keys.contains(name) && !required {
            Just(None).boxed()
        } else {
            strategy.prop_map(Some).boxed()
        };
        property_strategies.push((name.clone(), strategy));
    }

    let mut strategy: BoxedStrategy<Vec<(String, Option<JsonValue>)>> = Just(Vec::new()).boxed();
    for (name, value_strategy) in property_strategies {
        strategy = strategy
            .prop_flat_map(move |entries| {
                let name = name.clone();
                let value_strategy = value_strategy.clone();
                value_strategy.prop_map(move |value| {
                    let mut next = entries.clone();
                    next.push((name.clone(), value));
                    next
                })
            })
            .boxed();
    }

    Ok(strategy
        .prop_map(|entries| {
            let mut map = JsonObject::new();
            for (name, value) in entries {
                if let Some(value) = value {
                    map.insert(name, value);
                }
            }
            map
        })
        .boxed())
}

fn schema_value_strategy(
    schema: &JsonObject,
    tool: &PreparedTool,
) -> Result<BoxedStrategy<JsonValue>, InvocationError> {
    if let Some(resolved) = resolve_schema_ref(schema, tool)? {
        return schema_value_strategy(&resolved, tool);
    }
    if schema.get("allOf").is_some() {
        let resolved = resolve_object_schema(schema, tool)?;
        if &resolved != schema {
            return schema_value_strategy(&resolved, tool);
        }
    }

    if let Some(value) = schema.get("const") {
        return Ok(Just(value.clone()).boxed());
    }

    if let Some(JsonValue::Array(values)) = schema.get("enum") {
        if values.is_empty() {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "enum must include at least one value".to_string(),
            });
        }
        return Ok(proptest::sample::select(values.clone())
            .prop_map(|value| value)
            .boxed());
    }

    if let Some(branches) = schema_union_branches_for_generation(schema, tool)? {
        let mut strategies = Vec::with_capacity(branches.len());
        for branch in branches {
            strategies.push(schema_value_strategy(&branch, tool)?);
        }
        let union = proptest::strategy::Union::new(strategies).boxed();
        return Ok(union);
    }

    let schema_type = schema
        .get("type")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| InvocationError::UnsupportedSchema {
            tool: tool.name.to_string(),
            reason: "schema type must be a string or array of strings".to_string(),
        })?;

    match schema_type {
        "string" => {
            let min_length = schema
                .get("minLength")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0) as usize;
            let max_length = schema
                .get("maxLength")
                .and_then(JsonValue::as_u64)
                .unwrap_or(16) as usize;
            if max_length < min_length {
                return Err(InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: "maxLength must be >= minLength".to_string(),
                });
            }

            if let Some(pattern) = schema.get("pattern").and_then(JsonValue::as_str) {
                let compiled = tool.patterns().pattern(pattern).ok_or_else(|| {
                    InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: "pattern was not compiled".to_string(),
                    }
                })?;
                let generation = compiled.generation.as_ref().map_err(|error| {
                    InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: error.reason(),
                    }
                })?;
                let strategy =
                    proptest::string::string_regex_parsed(&generation.hir).map_err(|err| {
                        InvocationError::UnsupportedSchema {
                            tool: tool.name.to_string(),
                            reason: format!("pattern must be a valid regex: {err}"),
                        }
                    })?;
                Ok(strategy
                    .prop_filter("string length out of bounds", move |value| {
                        let len = value.chars().count();
                        len >= min_length && len <= max_length
                    })
                    .prop_map(JsonValue::String)
                    .boxed())
            } else {
                Ok(
                    proptest::collection::vec(proptest::char::any(), min_length..=max_length)
                        .prop_map(|chars| JsonValue::String(chars.into_iter().collect()))
                        .boxed(),
                )
            }
        }
        "number" => {
            let minimum = schema.get("minimum").and_then(JsonValue::as_f64);
            let maximum = schema.get("maximum").and_then(JsonValue::as_f64);
            if let (Some(minimum), Some(maximum)) = (minimum, maximum) {
                if maximum < minimum {
                    return Err(InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: "maximum must be >= minimum".to_string(),
                    });
                }
            }
            let strategy = if minimum.is_some() || maximum.is_some() {
                let min = minimum.unwrap_or(f64::NEG_INFINITY);
                let max = maximum.unwrap_or(f64::INFINITY);
                proptest::num::f64::NORMAL
                    .prop_map(move |value| JsonValue::from(value.clamp(min, max)))
                    .boxed()
            } else {
                proptest::num::f64::NORMAL.prop_map(JsonValue::from).boxed()
            };
            Ok(strategy)
        }
        "integer" => {
            let minimum = schema.get("minimum").and_then(JsonValue::as_f64);
            let maximum = schema.get("maximum").and_then(JsonValue::as_f64);
            let min_bound = minimum.map(|value| value.ceil() as i64).unwrap_or(i64::MIN);
            let max_bound = maximum
                .map(|value| value.floor() as i64)
                .unwrap_or(i64::MAX);
            if max_bound < min_bound {
                return Err(InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: "maximum must be >= minimum".to_string(),
                });
            }
            Ok((min_bound..=max_bound).prop_map(JsonValue::from).boxed())
        }
        "boolean" => Ok(any::<bool>().prop_map(JsonValue::from).boxed()),
        "null" => Ok(Just(JsonValue::Null).boxed()),
        "array" => {
            let min_items = schema
                .get("minItems")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0) as usize;
            let max_items = schema
                .get("maxItems")
                .and_then(JsonValue::as_u64)
                .unwrap_or(4) as usize;
            if max_items < min_items {
                return Err(InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: "maxItems must be >= minItems".to_string(),
                });
            }
            let item_schema = schema
                .get("items")
                .and_then(JsonValue::as_object)
                .ok_or_else(|| InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: "array schema must include object-valued items".to_string(),
                })?;
            let item_strategy = schema_value_strategy(item_schema, tool)?;
            Ok(
                proptest::collection::vec(item_strategy, min_items..=max_items)
                    .prop_map(JsonValue::from)
                    .boxed(),
            )
        }
        "object" => {
            let properties = schema.get("properties").and_then(JsonValue::as_object);
            if let Some(properties) = properties {
                if let Some(JsonValue::Array(required)) = schema.get("required") {
                    let required_keys = required
                        .iter()
                        .filter_map(JsonValue::as_str)
                        .collect::<Vec<_>>();
                    if !required_keys
                        .iter()
                        .all(|key| properties.contains_key(*key))
                    {
                        return Err(InvocationError::UnsupportedSchema {
                            tool: tool.name.to_string(),
                            reason: "required must reference known properties".to_string(),
                        });
                    }
                }
                let mut property_strategies = Vec::with_capacity(properties.len());
                for (name, schema_value) in properties {
                    let schema_object = schema_value.as_object().ok_or_else(|| {
                        InvocationError::UnsupportedSchema {
                            tool: tool.name.to_string(),
                            reason: format!("property '{name}' schema must be an object"),
                        }
                    })?;
                    let strategy = schema_value_strategy(schema_object, tool)?;
                    property_strategies.push((name.clone(), strategy));
                }

                let mut strategy: BoxedStrategy<Vec<(String, JsonValue)>> =
                    Just(Vec::new()).boxed();
                for (name, value_strategy) in property_strategies {
                    strategy = strategy
                        .prop_flat_map(move |entries| {
                            let name = name.clone();
                            let value_strategy = value_strategy.clone();
                            value_strategy.prop_map(move |value| {
                                let mut next = entries.clone();
                                next.push((name.clone(), value));
                                next
                            })
                        })
                        .boxed();
                }

                Ok(strategy
                    .prop_map(|entries| {
                        let mut map = JsonObject::new();
                        for (name, value) in entries {
                            map.insert(name, value);
                        }
                        JsonValue::Object(map)
                    })
                    .boxed())
            } else {
                if let Some(JsonValue::Array(required)) = schema.get("required") {
                    if !required.is_empty() {
                        return Err(InvocationError::UnsupportedSchema {
                            tool: tool.name.to_string(),
                            reason: "required must be empty when no properties exist".to_string(),
                        });
                    }
                }
                Ok(Just(JsonValue::Object(JsonObject::new())).boxed())
            }
        }
        other => Err(InvocationError::UnsupportedSchema {
            tool: tool.name.to_string(),
            reason: format!("unsupported schema type '{other}'"),
        }),
    }
}

fn resolve_schema_ref(
    schema: &JsonObject,
    tool: &Tool,
) -> Result<Option<JsonObject>, InvocationError> {
    let Some(JsonValue::String(reference)) = schema.get("$ref") else {
        return Ok(None);
    };
    if !reference.starts_with("#/") && reference != "#" {
        return Err(InvocationError::UnsupportedSchema {
            tool: tool.name.to_string(),
            reason: format!("schema $ref must be a local reference, got '{reference}'"),
        });
    }
    let root = JsonValue::Object(tool.input_schema.as_ref().clone());
    let target = resolve_pointer_value(&root, reference).ok_or_else(|| {
        InvocationError::UnsupportedSchema {
            tool: tool.name.to_string(),
            reason: format!("schema $ref '{reference}' must point to a schema object"),
        }
    })?;
    let target_object = target
        .as_object()
        .ok_or_else(|| InvocationError::UnsupportedSchema {
            tool: tool.name.to_string(),
            reason: format!("schema $ref '{reference}' must point to a schema object"),
        })?;
    let mut merged = target_object.clone();
    for (key, value) in schema {
        if key != "$ref" {
            merged.insert(key.clone(), value.clone());
        }
    }
    Ok(Some(merged))
}

fn resolve_object_schema(schema: &JsonObject, tool: &Tool) -> Result<JsonObject, InvocationError> {
    if let Some(resolved) = resolve_schema_ref(schema, tool)? {
        return resolve_object_schema(&resolved, tool);
    }

    if let Some(JsonValue::Array(all_of)) = schema.get("allOf") {
        if all_of.is_empty() {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "allOf must include at least one schema object".to_string(),
            });
        }
        let mut merged = schema.clone();
        merged.remove("allOf");
        for (idx, value) in all_of.iter().enumerate() {
            let schema_object =
                value
                    .as_object()
                    .ok_or_else(|| InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: format!("allOf[{idx}] schema must be an object"),
                    })?;
            let resolved = resolve_object_schema(schema_object, tool)?;
            merged = merge_object_schema(&merged, &resolved);
        }
        return Ok(merged);
    }

    Ok(schema.clone())
}

fn resolve_pointer_value<'a>(root: &'a JsonValue, pointer: &str) -> Option<&'a JsonValue> {
    if pointer == "#" {
        return Some(root);
    }
    let mut current = root;
    for segment in pointer.split('/').skip(1) {
        let decoded = decode_pointer_segment(segment);
        match current {
            JsonValue::Object(map) => {
                current = map.get(&decoded)?;
            }
            JsonValue::Array(items) => {
                let index = decoded.parse::<usize>().ok()?;
                current = items.get(index)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

fn resolve_schema_for_validation(schema: &JsonObject, root: &JsonObject) -> Option<JsonObject> {
    if let Some(JsonValue::String(reference)) = schema.get("$ref") {
        if !reference.starts_with("#/") && reference != "#" {
            return None;
        }
        let root_value = JsonValue::Object(root.clone());
        let target = resolve_pointer_value(&root_value, reference)?;
        let target_object = target.as_object()?;
        let mut merged = target_object.clone();
        for (key, value) in schema {
            if key != "$ref" {
                merged.insert(key.clone(), value.clone());
            }
        }
        return Some(merged);
    }

    let JsonValue::Array(all_of) = schema.get("allOf")? else {
        return None;
    };
    let mut merged = schema.clone();
    merged.remove("allOf");
    for value in all_of {
        let schema_object = value.as_object()?;
        let resolved = resolve_schema_for_validation(schema_object, root)
            .unwrap_or_else(|| schema_object.clone());
        merged = merge_object_schema(&merged, &resolved);
    }
    Some(merged)
}

fn schema_union_branches_for_generation(
    schema: &JsonObject,
    tool: &Tool,
) -> Result<Option<Vec<JsonObject>>, InvocationError> {
    if let Some(JsonValue::Array(one_of)) = schema.get("oneOf") {
        if one_of.is_empty() {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "oneOf must include at least one schema object".to_string(),
            });
        }
        let base = schema_without_oneof(schema);
        let mut branches = Vec::with_capacity(one_of.len());
        for (idx, value) in one_of.iter().enumerate() {
            let schema_object =
                value
                    .as_object()
                    .ok_or_else(|| InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: format!("oneOf[{idx}] schema must be an object"),
                    })?;
            let resolved = resolve_object_schema(schema_object, tool)?;
            branches.push(merge_object_schema(&base, &resolved));
        }
        return Ok(Some(branches));
    }

    if let Some(JsonValue::Array(any_of)) = schema.get("anyOf") {
        if any_of.is_empty() {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "anyOf must include at least one schema object".to_string(),
            });
        }
        let base = schema_without_anyof(schema);
        let mut branches = Vec::with_capacity(any_of.len());
        for (idx, value) in any_of.iter().enumerate() {
            let schema_object =
                value
                    .as_object()
                    .ok_or_else(|| InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: format!("anyOf[{idx}] schema must be an object"),
                    })?;
            let resolved = resolve_object_schema(schema_object, tool)?;
            branches.push(merge_object_schema(&base, &resolved));
        }
        return Ok(Some(branches));
    }

    if let Some(JsonValue::Array(types)) = schema.get("type") {
        if types.is_empty() {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "schema type array must include at least one string".to_string(),
            });
        }
        let mut branches = Vec::with_capacity(types.len());
        for (idx, value) in types.iter().enumerate() {
            let schema_type = value
                .as_str()
                .ok_or_else(|| InvocationError::UnsupportedSchema {
                    tool: tool.name.to_string(),
                    reason: format!(
                        "schema type array must contain strings; found {value} at {idx}"
                    ),
                })?;
            let mut branch = schema.clone();
            branch.insert(
                "type".to_string(),
                JsonValue::String(schema_type.to_string()),
            );
            branches.push(branch);
        }
        return Ok(Some(branches));
    }

    Ok(None)
}

fn normalize_pattern_for_generation(pattern: &str) -> Result<String, String> {
    if pattern.is_empty() {
        return Ok(String::new());
    }
    if contains_boundary_escape(pattern) {
        return Err(
            "pattern uses word boundary escapes which are unsupported for string generation"
                .to_string(),
        );
    }
    let bytes = pattern.as_bytes();
    let mut start = 0;
    let mut end = bytes.len();
    if bytes.first() == Some(&b'^') {
        start = 1;
    }
    if end > start && bytes[end - 1] == b'$' && !is_escaped(bytes, end - 1) {
        end -= 1;
    }
    Ok(pattern[start..end].to_string())
}

fn contains_boundary_escape(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'\\' {
            if let Some(next) = bytes.get(idx + 1) {
                match *next {
                    b'b' | b'B' | b'A' | b'Z' | b'z' | b'G' => return true,
                    _ => {
                        idx += 2;
                        continue;
                    }
                }
            } else {
                break;
            }
        }
        idx += 1;
    }
    false
}

fn is_escaped(bytes: &[u8], idx: usize) -> bool {
    if idx == 0 {
        return false;
    }
    let mut count = 0;
    let mut pos = idx;
    while pos > 0 {
        pos -= 1;
        if bytes[pos] == b'\\' {
            count += 1;
        } else {
            break;
        }
    }
    count % 2 == 1
}

fn collect_pattern_strings_from_object(schema: &JsonObject, patterns: &mut HashSet<String>) {
    if let Some(JsonValue::String(pattern)) = schema.get("pattern") {
        patterns.insert(pattern.clone());
    }
    for value in schema.values() {
        collect_pattern_strings(value, patterns);
    }
}

fn collect_pattern_strings(value: &JsonValue, patterns: &mut HashSet<String>) {
    match value {
        JsonValue::Object(map) => collect_pattern_strings_from_object(map, patterns),
        JsonValue::Array(values) => {
            for value in values {
                collect_pattern_strings(value, patterns);
            }
        }
        _ => {}
    }
}

fn compile_generation_pattern(
    pattern: &str,
) -> Result<CompiledGenerationPattern, PatternGenerationError> {
    let normalized =
        normalize_pattern_for_generation(pattern).map_err(PatternGenerationError::Unsupported)?;
    let hir = ParserBuilder::new()
        .build()
        .parse(&normalized)
        .map_err(|error| PatternGenerationError::Parse(error.to_string()))?;
    if let Err(error) = proptest::string::string_regex_parsed(&hir) {
        return Err(PatternGenerationError::Parse(error.to_string()));
    }
    Ok(CompiledGenerationPattern { hir })
}

fn nonempty_path(path: &[PathSegment]) -> NonEmpty<PathSegment> {
    match path.split_first() {
        Some((head, tail)) => NonEmpty {
            head: head.clone(),
            tail: tail.to_vec(),
        },
        None => NonEmpty::new(PathSegment::Root),
    }
}

pub(crate) fn schema_violations(
    schema: &JsonObject,
    value: &JsonValue,
    patterns: &SchemaRegexIndex,
) -> Vec<Constraint> {
    let mut violations = Vec::new();
    let mut path = Vec::new();
    collect_violations(schema, value, &mut path, &mut violations, patterns);
    violations
}

fn collect_violations(
    schema: &JsonObject,
    value: &JsonValue,
    path: &mut Vec<PathSegment>,
    violations: &mut Vec<Constraint>,
    patterns: &SchemaRegexIndex,
) {
    collect_violations_inner(schema, value, path, violations, patterns, schema);
}

fn collect_violations_inner(
    schema: &JsonObject,
    value: &JsonValue,
    path: &mut Vec<PathSegment>,
    violations: &mut Vec<Constraint>,
    patterns: &SchemaRegexIndex,
    root: &JsonObject,
) {
    if let Some(resolved) = resolve_schema_for_validation(schema, root) {
        collect_violations_inner(&resolved, value, path, violations, patterns, root);
        return;
    }

    match schema_oneof_branches(schema) {
        Ok(Some(one_of)) => {
            let base = schema_without_oneof(schema);
            let mut base_violations = schema_violations_inner(&base, value, patterns, root);
            if !base_violations.is_empty() {
                violations.append(&mut base_violations);
                return;
            }
            let mut matches = 0;
            let mut best: Option<Vec<Constraint>> = None;
            for branch in &one_of {
                let branch_violations = schema_violations_inner(branch, value, patterns, root);
                if branch_violations.is_empty() {
                    matches += 1;
                    continue;
                }
                let is_better = best
                    .as_ref()
                    .map(|current| branch_violations.len() < current.len())
                    .unwrap_or(true);
                if is_better {
                    best = Some(branch_violations);
                }
            }
            if matches == 1 {
                return;
            }
            if matches > 1 {
                violations.push(Constraint {
                    path: nonempty_path(path),
                    kind: ConstraintKind::OneOfMatches(matches),
                });
                return;
            }
            let mut best = best.expect("oneOf branches must yield a best violation set");
            violations.append(&mut best);
            return;
        }
        Ok(None) => {}
        Err(reason) => {
            violations.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::Schema(reason),
            });
            return;
        }
    }

    match schema_anyof_branches(schema) {
        Ok(Some(any_of)) => {
            let base = schema_without_anyof(schema);
            let mut base_violations = schema_violations_inner(&base, value, patterns, root);
            if !base_violations.is_empty() {
                violations.append(&mut base_violations);
                return;
            }
            let mut best: Option<Vec<Constraint>> = None;
            for branch in &any_of {
                let branch_violations = schema_violations_inner(branch, value, patterns, root);
                if branch_violations.is_empty() {
                    return;
                }
                let is_better = best
                    .as_ref()
                    .map(|current| branch_violations.len() < current.len())
                    .unwrap_or(true);
                if is_better {
                    best = Some(branch_violations);
                }
            }
            let mut best = best.expect("anyOf branches must yield a best violation set");
            violations.append(&mut best);
            return;
        }
        Ok(None) => {}
        Err(reason) => {
            violations.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::Schema(reason),
            });
            return;
        }
    }

    if let Some(type_union) = schema_type_union_branches(schema) {
        let mut best: Option<Vec<Constraint>> = None;
        for branch in &type_union {
            let branch_violations = schema_violations_inner(branch, value, patterns, root);
            if branch_violations.is_empty() {
                return;
            }
            let is_better = best
                .as_ref()
                .map(|current| branch_violations.len() < current.len())
                .unwrap_or(true);
            if is_better {
                best = Some(branch_violations);
            }
        }
        let mut best = best.expect("type union branches must yield a best violation set");
        violations.append(&mut best);
        return;
    }

    if let Some(const_value) = schema.get("const") {
        if value != const_value {
            violations.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::Const(const_value.clone()),
            });
        }
    }

    if let Some(JsonValue::Array(values)) = schema.get("enum") {
        if !values.contains(value) {
            violations.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::Enum(values.clone()),
            });
        }
    }

    if let Some(JsonValue::String(schema_type)) = schema.get("type") {
        if !value_matches_type(value, schema_type) {
            violations.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::Type(schema_type.clone()),
            });
            return;
        }
    }

    match value {
        JsonValue::String(value_str) => {
            if let Some(min_length) = schema.get("minLength").and_then(JsonValue::as_u64) {
                if value_str.chars().count() < min_length as usize {
                    violations.push(Constraint {
                        path: nonempty_path(path),
                        kind: ConstraintKind::MinLength(min_length as usize),
                    });
                }
            }
            if let Some(max_length) = schema.get("maxLength").and_then(JsonValue::as_u64) {
                if value_str.chars().count() > max_length as usize {
                    violations.push(Constraint {
                        path: nonempty_path(path),
                        kind: ConstraintKind::MaxLength(max_length as usize),
                    });
                }
            }
            if let Some(JsonValue::String(pattern)) = schema.get("pattern") {
                let compiled = patterns.pattern(pattern);
                let is_match = compiled
                    .and_then(|compiled| compiled.validation.as_ref().ok())
                    .map(|regex| regex.is_match(value_str))
                    .unwrap_or(false);
                if !is_match {
                    violations.push(Constraint {
                        path: nonempty_path(path),
                        kind: ConstraintKind::Pattern(pattern.clone()),
                    });
                }
            }
        }
        JsonValue::Number(number) => {
            if let Some(minimum) = schema.get("minimum").and_then(JsonValue::as_f64) {
                if number.as_f64().is_some_and(|value| value < minimum) {
                    violations.push(Constraint {
                        path: nonempty_path(path),
                        kind: ConstraintKind::Minimum(minimum),
                    });
                }
            }
            if let Some(maximum) = schema.get("maximum").and_then(JsonValue::as_f64) {
                if number.as_f64().is_some_and(|value| value > maximum) {
                    violations.push(Constraint {
                        path: nonempty_path(path),
                        kind: ConstraintKind::Maximum(maximum),
                    });
                }
            }
        }
        JsonValue::Array(items) => {
            if let Some(min_items) = schema.get("minItems").and_then(JsonValue::as_u64) {
                if items.len() < min_items as usize {
                    violations.push(Constraint {
                        path: nonempty_path(path),
                        kind: ConstraintKind::MinItems(min_items as usize),
                    });
                }
            }
            if let Some(max_items) = schema.get("maxItems").and_then(JsonValue::as_u64) {
                if items.len() > max_items as usize {
                    violations.push(Constraint {
                        path: nonempty_path(path),
                        kind: ConstraintKind::MaxItems(max_items as usize),
                    });
                }
            }
            if let Some(JsonValue::Object(item_schema)) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    path.push(PathSegment::Index(index));
                    collect_violations_inner(item_schema, item, path, violations, patterns, root);
                    path.pop();
                }
            }
        }
        JsonValue::Object(map) => {
            if let Some(JsonValue::Array(required)) = schema.get("required") {
                for required_key in required.iter().filter_map(JsonValue::as_str) {
                    if !map.contains_key(required_key) {
                        violations.push(Constraint {
                            path: nonempty_path(path),
                            kind: ConstraintKind::Required(required_key.to_string()),
                        });
                    }
                }
            }
            if let Some(JsonValue::Object(properties)) = schema.get("properties") {
                for (name, property_schema) in properties {
                    if let Some(property_value) = map.get(name) {
                        if let Some(property_schema) = property_schema.as_object() {
                            path.push(PathSegment::Key(name.clone()));
                            collect_violations_inner(
                                property_schema,
                                property_value,
                                path,
                                violations,
                                patterns,
                                root,
                            );
                            path.pop();
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn schema_violations_inner(
    schema: &JsonObject,
    value: &JsonValue,
    patterns: &SchemaRegexIndex,
    root: &JsonObject,
) -> Vec<Constraint> {
    let mut violations = Vec::new();
    let mut path = Vec::new();
    collect_violations_inner(schema, value, &mut path, &mut violations, patterns, root);
    violations
}

fn schema_anyof_branches(schema: &JsonObject) -> Result<Option<Vec<JsonObject>>, String> {
    let Some(value) = schema.get("anyOf") else {
        return Ok(None);
    };
    let JsonValue::Array(any_of) = value else {
        return Err("anyOf must be an array".to_string());
    };
    if any_of.is_empty() {
        return Err("anyOf must include at least one schema object".to_string());
    }
    let mut branches = Vec::with_capacity(any_of.len());
    for (idx, value) in any_of.iter().enumerate() {
        let schema_object = value
            .as_object()
            .ok_or_else(|| format!("anyOf[{idx}] schema must be an object"))?;
        branches.push(schema_object.clone());
    }
    Ok(Some(branches))
}

fn schema_oneof_branches(schema: &JsonObject) -> Result<Option<Vec<JsonObject>>, String> {
    let Some(value) = schema.get("oneOf") else {
        return Ok(None);
    };
    let JsonValue::Array(one_of) = value else {
        return Err("oneOf must be an array".to_string());
    };
    if one_of.is_empty() {
        return Err("oneOf must include at least one schema object".to_string());
    }
    let mut branches = Vec::with_capacity(one_of.len());
    for (idx, value) in one_of.iter().enumerate() {
        let schema_object = value
            .as_object()
            .ok_or_else(|| format!("oneOf[{idx}] schema must be an object"))?;
        branches.push(schema_object.clone());
    }
    Ok(Some(branches))
}

fn schema_type_union_branches(schema: &JsonObject) -> Option<Vec<JsonObject>> {
    let JsonValue::Array(types) = schema.get("type")? else {
        return None;
    };
    if types.is_empty() {
        return None;
    }
    let mut branches = Vec::with_capacity(types.len());
    for value in types {
        let schema_type = value.as_str()?;
        let mut branch = schema.clone();
        branch.insert(
            "type".to_string(),
            JsonValue::String(schema_type.to_string()),
        );
        branches.push(branch);
    }
    Some(branches)
}

fn schema_without_anyof(schema: &JsonObject) -> JsonObject {
    let mut base = schema.clone();
    base.remove("anyOf");
    base
}

fn schema_without_oneof(schema: &JsonObject) -> JsonObject {
    let mut base = schema.clone();
    base.remove("oneOf");
    base
}

fn required_key_set(schema: &JsonObject) -> HashSet<String> {
    schema
        .get("required")
        .and_then(JsonValue::as_array)
        .map(|required| {
            required
                .iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_string)
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default()
}

fn forbidden_keys_for_oneof(
    kind: ObjectUnionKind,
    required_sets: &[HashSet<String>],
    idx: usize,
) -> HashSet<String> {
    let mut forbidden = HashSet::new();
    if matches!(kind, ObjectUnionKind::OneOf) {
        for (other_idx, required) in required_sets.iter().enumerate() {
            if other_idx == idx {
                continue;
            }
            for key in required {
                if !required_sets[idx].contains(key) {
                    forbidden.insert(key.clone());
                }
            }
        }
    }
    forbidden
}

fn merge_object_schema(base: &JsonObject, branch: &JsonObject) -> JsonObject {
    let mut merged = base.clone();
    for (key, value) in branch {
        match key.as_str() {
            "properties" => {
                if let (Some(JsonValue::Object(base_props)), JsonValue::Object(branch_props)) =
                    (merged.get_mut("properties"), value)
                {
                    for (prop_key, prop_value) in branch_props {
                        base_props.insert(prop_key.clone(), prop_value.clone());
                    }
                } else {
                    merged.insert(key.clone(), value.clone());
                }
            }
            "required" => {
                if let (Some(JsonValue::Array(base_required)), JsonValue::Array(branch_required)) =
                    (merged.get_mut("required"), value)
                {
                    let mut seen = HashSet::new();
                    let mut combined = Vec::new();
                    for item in base_required.iter().chain(branch_required.iter()) {
                        if let Some(value) = item.as_str() {
                            if seen.insert(value.to_string()) {
                                combined.push(JsonValue::String(value.to_string()));
                            }
                        }
                    }
                    *base_required = combined;
                } else {
                    merged.insert(key.clone(), value.clone());
                }
            }
            _ => {
                merged.insert(key.clone(), value.clone());
            }
        }
    }
    merged
}

#[derive(Clone, Copy, Debug)]
enum ObjectUnionKind {
    OneOf,
    AnyOf,
}

fn schema_object_union_branches(
    schema: &JsonObject,
    tool: &Tool,
) -> Result<Option<(ObjectUnionKind, Vec<JsonObject>, JsonObject)>, InvocationError> {
    if let Some(JsonValue::Array(one_of)) = schema.get("oneOf") {
        if one_of.is_empty() {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "oneOf must include at least one schema object".to_string(),
            });
        }
        let mut branches = Vec::with_capacity(one_of.len());
        for (idx, value) in one_of.iter().enumerate() {
            let schema_object =
                value
                    .as_object()
                    .ok_or_else(|| InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: format!("oneOf[{idx}] schema must be an object"),
                    })?;
            branches.push(schema_object.clone());
        }
        return Ok(Some((
            ObjectUnionKind::OneOf,
            branches,
            schema_without_oneof(schema),
        )));
    }

    if let Some(JsonValue::Array(any_of)) = schema.get("anyOf") {
        if any_of.is_empty() {
            return Err(InvocationError::UnsupportedSchema {
                tool: tool.name.to_string(),
                reason: "anyOf must include at least one schema object".to_string(),
            });
        }
        let mut branches = Vec::with_capacity(any_of.len());
        for (idx, value) in any_of.iter().enumerate() {
            let schema_object =
                value
                    .as_object()
                    .ok_or_else(|| InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason: format!("anyOf[{idx}] schema must be an object"),
                    })?;
            branches.push(schema_object.clone());
        }
        return Ok(Some((
            ObjectUnionKind::AnyOf,
            branches,
            schema_without_anyof(schema),
        )));
    }

    Ok(None)
}
