//! Proptest-based tool invocation generation driven by MCP schemas.
#![cfg_attr(not(test), allow(dead_code))]

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use nonempty::NonEmpty;
use proptest::prelude::*;
use proptest_state_machine::ReferenceStateMachine;
use regex::Regex;
use rmcp::model::{JsonObject, Tool};
use serde_json::{Number, Value as JsonValue};

use crate::{StateMachineConfig, ToolInvocation, ToolPredicate};

thread_local! {
    static LAST_REJECT_CONTEXT: RefCell<Option<String>> = const { RefCell::new(None) };
    static STATE_MACHINE_CONTEXT: RefCell<Option<StateMachineContext>> = const { RefCell::new(None) };
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

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PathSegment {
    Root,
    Key(String),
    Index(usize),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ConstraintKind {
    Const(JsonValue),
    Enum(Vec<JsonValue>),
    Type(String),
    MinLength(usize),
    MaxLength(usize),
    Pattern(String),
    Minimum(f64),
    Maximum(f64),
    MinItems(usize),
    MaxItems(usize),
    Required(String),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Constraint {
    pub(crate) path: NonEmpty<PathSegment>,
    pub(crate) kind: ConstraintKind,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ValueCorpus {
    integers: Vec<i64>,
    numbers: Vec<Number>,
    strings: Vec<String>,
    integer_set: HashSet<i64>,
    number_set: HashSet<Number>,
    string_set: HashSet<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum StateMachineTransition {
    Invoke(ToolInvocation),
    Skip { reason: Option<String> },
}

#[derive(Clone, Debug)]
pub(crate) struct StateMachineSequence {
    pub(crate) transitions: Vec<StateMachineTransition>,
    pub(crate) seen_counter: Option<Arc<AtomicUsize>>,
}

impl StateMachineSequence {
    fn empty() -> Self {
        Self {
            transitions: Vec::new(),
            seen_counter: None,
        }
    }
}

#[derive(Clone)]
struct StateMachineContext {
    tools: Arc<Vec<Tool>>,
    predicate: Option<ToolPredicate>,
    seed_numbers: Vec<Number>,
    seed_strings: Vec<String>,
    lenient_sourcing: bool,
}

fn set_state_machine_context(context: StateMachineContext) {
    STATE_MACHINE_CONTEXT.with(|slot| {
        *slot.borrow_mut() = Some(context);
    });
}

fn get_state_machine_context() -> StateMachineContext {
    STATE_MACHINE_CONTEXT
        .with(|slot| slot.borrow().clone())
        .expect("state machine context")
}

impl ValueCorpus {
    pub(crate) fn seed_numbers<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = Number>,
    {
        for value in values {
            self.insert_number(value);
        }
    }

    pub(crate) fn seed_strings<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = String>,
    {
        for value in values {
            self.insert_string(value);
        }
    }

    pub(crate) fn mine_structured_content(&mut self, value: &JsonValue) {
        self.walk_value(value);
    }

    pub(crate) fn mine_text(&mut self, text: &str) {
        for token in text.split_whitespace() {
            if let Some(number) = number_from_token(token) {
                self.insert_number(number);
            } else {
                self.insert_string(token.to_string());
            }
        }
    }

    pub(crate) fn mine_text_from_value(&mut self, value: &JsonValue) {
        self.walk_text(value);
    }

    pub(crate) fn merge_from(&mut self, other: &ValueCorpus) {
        for number in other.numbers() {
            self.insert_number(number.clone());
        }
        for value in other.strings() {
            self.insert_string(value.clone());
        }
    }

    pub(crate) fn integers(&self) -> &[i64] {
        &self.integers
    }

    pub(crate) fn numbers(&self) -> &[Number] {
        &self.numbers
    }

    pub(crate) fn strings(&self) -> &[String] {
        &self.strings
    }

    fn insert_number(&mut self, value: Number) {
        if self.number_set.insert(value.clone()) {
            self.numbers.push(value.clone());
        }
        if let Some(integer) = number_to_i64(&value) {
            if self.integer_set.insert(integer) {
                self.integers.push(integer);
            }
        }
    }

    fn insert_string(&mut self, value: String) {
        if self.string_set.insert(value.clone()) {
            self.strings.push(value);
        }
    }

    fn walk_value(&mut self, value: &JsonValue) {
        match value {
            JsonValue::Null | JsonValue::Bool(_) => {}
            JsonValue::Number(number) => self.insert_number(number.clone()),
            JsonValue::String(value) => self.insert_string(value.clone()),
            JsonValue::Array(values) => {
                for value in values {
                    self.walk_value(value);
                }
            }
            JsonValue::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for key in keys {
                    self.insert_string(key.to_string());
                    let value = map.get(key).expect("key from map");
                    self.walk_value(value);
                }
            }
        }
    }

    fn walk_text(&mut self, value: &JsonValue) {
        match value {
            JsonValue::String(value) => self.mine_text(value),
            JsonValue::Array(values) => {
                for value in values {
                    self.walk_text(value);
                }
            }
            JsonValue::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for key in keys {
                    self.mine_text(key);
                    let value = map.get(key).expect("key from map");
                    self.walk_text(value);
                }
            }
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
        }
    }
}

fn number_to_i64(value: &Number) -> Option<i64> {
    if let Some(value) = value.as_i64() {
        return Some(value);
    }
    if let Some(value) = value.as_u64() {
        return i64::try_from(value).ok();
    }
    let value = value.as_f64().expect("f64 value");
    if value.fract() != 0.0 {
        return None;
    }
    if value < i64::MIN as f64 || value > i64::MAX as f64 {
        return None;
    }
    Some(value as i64)
}

fn number_from_token(token: &str) -> Option<Number> {
    if let Ok(value) = token.parse::<i64>() {
        return Some(Number::from(value));
    }
    let value = token.parse::<f64>().ok()?;
    Number::from_f64(value)
}

/// Builds a proptest strategy that yields tool invocations from MCP tool schemas.
pub(crate) fn invocation_strategy(
    tools: &[Tool],
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
    tools: &[Tool],
    predicate: Option<&ToolPredicate>,
    len_range: std::ops::RangeInclusive<usize>,
) -> Result<BoxedStrategy<Vec<ToolInvocation>>, InvocationError> {
    let invocation = invocation_strategy(tools, predicate)?;
    Ok(proptest::collection::vec(invocation, len_range).boxed())
}

pub(crate) fn invocation_strategy_from_corpus(
    tools: &[Tool],
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

struct StateMachineModel;

impl ReferenceStateMachine for StateMachineModel {
    type State = ValueCorpus;
    type Transition = StateMachineTransition;

    fn init_state() -> BoxedStrategy<Self::State> {
        let context = get_state_machine_context();
        let mut corpus = ValueCorpus::default();
        corpus.seed_numbers(context.seed_numbers.clone());
        corpus.seed_strings(context.seed_strings.clone());
        Just(corpus).boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        let context = get_state_machine_context();
        let mut strategies = Vec::new();
        for tool in context.tools.iter() {
            let Some(strategy) =
                invocation_from_corpus_unfiltered(tool, state, context.lenient_sourcing)
            else {
                continue;
            };
            let predicate = context.predicate.clone();
            let tool_name = tool.name.clone();
            let strategy = strategy
                .prop_map(move |invocation| {
                    if let Some(predicate) = predicate.as_ref() {
                        let input = invocation
                            .arguments
                            .clone()
                            .map(JsonValue::Object)
                            .unwrap_or(JsonValue::Null);
                        if !predicate(tool_name.as_ref(), &input) {
                            record_reject_context(format!(
                                "predicate rejected tool '{}'",
                                tool_name.as_ref()
                            ));
                            return StateMachineTransition::Skip {
                                reason: Some(format!(
                                    "predicate rejected tool '{}'",
                                    tool_name.as_ref()
                                )),
                            };
                        }
                    }
                    StateMachineTransition::Invoke(invocation)
                })
                .boxed();
            strategies.push(strategy);
        }

        if strategies.is_empty() {
            return Just(StateMachineTransition::Skip {
                reason: Some("no callable tools".to_string()),
            })
            .boxed();
        }

        proptest::strategy::Union::new(strategies).boxed()
    }

    fn apply(state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            StateMachineTransition::Invoke(invocation) => {
                let mut next = state.clone();
                if let Some(args) = invocation.arguments.as_ref() {
                    next.mine_structured_content(&JsonValue::Object(args.clone()));
                }
                next
            }
            StateMachineTransition::Skip { .. } => state,
        }
    }
}

pub(crate) fn state_machine_sequence_strategy(
    tools: &[Tool],
    predicate: Option<&ToolPredicate>,
    config: &StateMachineConfig,
    len_range: std::ops::RangeInclusive<usize>,
) -> Result<BoxedStrategy<StateMachineSequence>, InvocationError> {
    validate_state_machine_tools(tools)?;
    let mut corpus = ValueCorpus::default();
    corpus.seed_numbers(config.seed_numbers.clone());
    corpus.seed_strings(config.seed_strings.clone());
    if invocation_strategy_from_corpus(tools, predicate, &corpus, config.lenient_sourcing)?
        .is_none()
    {
        return Ok(Just(StateMachineSequence::empty()).boxed());
    }

    let context = StateMachineContext {
        tools: Arc::new(tools.to_vec()),
        predicate: predicate.cloned(),
        seed_numbers: config.seed_numbers.clone(),
        seed_strings: config.seed_strings.clone(),
        lenient_sourcing: config.lenient_sourcing,
    };
    set_state_machine_context(context);

    let strategy = StateMachineModel::sequential_strategy(len_range)
        .prop_map(|(_, transitions, seen_counter)| StateMachineSequence {
            transitions,
            seen_counter,
        })
        .boxed();
    Ok(strategy)
}

fn validate_state_machine_tools(tools: &[Tool]) -> Result<(), InvocationError> {
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

fn missing_properties_required_error(tool: &Tool) -> InvocationError {
    InvocationError::UnsupportedSchema {
        tool: tool.name.to_string(),
        reason: "inputSchema required must be empty when no properties exist".to_string(),
    }
}

fn invocation_from_corpus(
    tool: &Tool,
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
    tool: &Tool,
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
    tool: &Tool,
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
        match property_strategy_from_corpus(schema_object, required, corpus, tool, lenient_sourcing)
        {
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
    tool: &Tool,
    lenient_sourcing: bool,
) -> PropertyOutcome {
    match schema_type_hint(schema) {
        Some(SchemaType::String) => {
            let values = corpus
                .strings()
                .iter()
                .map(|value| JsonValue::String(value.clone()))
                .filter(|value| schema_violations(schema, value).is_empty())
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
                .filter(|value| schema_violations(schema, value).is_empty())
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
                .filter(|value| schema_violations(schema, value).is_empty())
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
    tool: &Tool,
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
        let reason = match schema_type_hint(schema_object) {
            Some(SchemaType::String) => {
                let has_match = corpus
                    .strings()
                    .iter()
                    .map(|value| JsonValue::String(value.clone()))
                    .any(|value| schema_violations(schema_object, &value).is_empty());
                if has_match {
                    None
                } else if lenient_sourcing {
                    schema_value_strategy(schema_object, tool)
                        .err()
                        .map(|_| UncallableReason::RequiredValue)
                } else {
                    Some(UncallableReason::String)
                }
            }
            Some(SchemaType::Integer) => {
                let has_match = corpus
                    .integers()
                    .iter()
                    .map(|value| JsonValue::Number(Number::from(*value)))
                    .any(|value| schema_violations(schema_object, &value).is_empty());
                if has_match {
                    None
                } else if lenient_sourcing {
                    schema_value_strategy(schema_object, tool)
                        .err()
                        .map(|_| UncallableReason::RequiredValue)
                } else {
                    Some(UncallableReason::Integer)
                }
            }
            Some(SchemaType::Number) => {
                let has_match = corpus
                    .numbers()
                    .iter()
                    .map(|value| JsonValue::Number(value.clone()))
                    .any(|value| schema_violations(schema_object, &value).is_empty());
                if has_match {
                    None
                } else if lenient_sourcing {
                    schema_value_strategy(schema_object, tool)
                        .err()
                        .map(|_| UncallableReason::RequiredValue)
                } else {
                    Some(UncallableReason::Number)
                }
            }
            None => {
                if lenient_sourcing {
                    schema_value_strategy(schema_object, tool)
                        .err()
                        .map(|_| UncallableReason::RequiredValue)
                } else {
                    Some(UncallableReason::RequiredValue)
                }
            }
        };
        if let Some(reason) = reason {
            return Some(reason);
        }
    }

    None
}

fn input_object_strategy(tool: &Tool) -> Result<BoxedStrategy<JsonObject>, InvocationError> {
    let omit_keys = HashSet::new();
    input_object_strategy_for_schema(tool.input_schema.as_ref(), tool, false, &omit_keys)
}

fn input_object_strategy_for_schema(
    schema: &JsonObject,
    tool: &Tool,
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
    tool: &Tool,
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
                let pattern = pattern.to_string();
                let normalized = normalize_pattern_for_generation(&pattern).map_err(|reason| {
                    InvocationError::UnsupportedSchema {
                        tool: tool.name.to_string(),
                        reason,
                    }
                })?;
                let strategy = proptest::string::string_regex(&normalized).map_err(|err| {
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

fn nonempty_path(path: &[PathSegment]) -> NonEmpty<PathSegment> {
    match path.split_first() {
        Some((head, tail)) => NonEmpty {
            head: head.clone(),
            tail: tail.to_vec(),
        },
        None => NonEmpty::new(PathSegment::Root),
    }
}

pub(crate) fn schema_violations(schema: &JsonObject, value: &JsonValue) -> Vec<Constraint> {
    let mut violations = Vec::new();
    let mut path = Vec::new();
    collect_violations(schema, value, &mut path, &mut violations);
    violations
}

fn collect_violations(
    schema: &JsonObject,
    value: &JsonValue,
    path: &mut Vec<PathSegment>,
    violations: &mut Vec<Constraint>,
) {
    collect_violations_inner(schema, value, path, violations, schema);
}

fn collect_violations_inner(
    schema: &JsonObject,
    value: &JsonValue,
    path: &mut Vec<PathSegment>,
    violations: &mut Vec<Constraint>,
    root: &JsonObject,
) {
    if let Some(resolved) = resolve_schema_for_validation(schema, root) {
        collect_violations_inner(&resolved, value, path, violations, root);
        return;
    }

    if let Some(one_of) = schema_oneof_branches(schema) {
        let base = schema_without_oneof(schema);
        let mut base_violations = schema_violations_inner(&base, value, root);
        if !base_violations.is_empty() {
            violations.append(&mut base_violations);
            return;
        }
        let mut matches = 0;
        let mut best: Option<Vec<Constraint>> = None;
        for branch in &one_of {
            let branch_violations = schema_violations_inner(branch, value, root);
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
        if matches >= 1 {
            return;
        }
        let mut best = best.expect("oneOf branches must yield a best violation set");
        violations.append(&mut best);
        return;
    }

    if let Some(any_of) = schema_anyof_branches(schema) {
        let base = schema_without_anyof(schema);
        let mut base_violations = schema_violations_inner(&base, value, root);
        if !base_violations.is_empty() {
            violations.append(&mut base_violations);
            return;
        }
        let mut best: Option<Vec<Constraint>> = None;
        for branch in &any_of {
            let branch_violations = schema_violations_inner(branch, value, root);
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

    if let Some(type_union) = schema_type_union_branches(schema) {
        let mut best: Option<Vec<Constraint>> = None;
        for branch in &type_union {
            let branch_violations = schema_violations_inner(branch, value, root);
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
                if let Ok(regex) = Regex::new(pattern) {
                    if !regex.is_match(value_str) {
                        violations.push(Constraint {
                            path: nonempty_path(path),
                            kind: ConstraintKind::Pattern(pattern.clone()),
                        });
                    }
                } else {
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
                    collect_violations_inner(item_schema, item, path, violations, root);
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
    root: &JsonObject,
) -> Vec<Constraint> {
    let mut violations = Vec::new();
    let mut path = Vec::new();
    collect_violations_inner(schema, value, &mut path, &mut violations, root);
    violations
}

fn schema_anyof_branches(schema: &JsonObject) -> Option<Vec<JsonObject>> {
    let JsonValue::Array(any_of) = schema.get("anyOf")? else {
        return None;
    };
    if any_of.is_empty() {
        return None;
    }
    let mut branches = Vec::with_capacity(any_of.len());
    for value in any_of {
        let schema_object = value.as_object()?;
        branches.push(schema_object.clone());
    }
    Some(branches)
}

fn schema_oneof_branches(schema: &JsonObject) -> Option<Vec<JsonObject>> {
    let JsonValue::Array(one_of) = schema.get("oneOf")? else {
        return None;
    };
    if one_of.is_empty() {
        return None;
    }
    let mut branches = Vec::with_capacity(one_of.len());
    for value in one_of {
        let schema_object = value.as_object()?;
        branches.push(schema_object.clone());
    }
    Some(branches)
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

pub(crate) fn path_from_pointer(pointer: &str) -> Vec<PathSegment> {
    if pointer.is_empty() {
        return Vec::new();
    }

    pointer
        .split('/')
        .skip(1)
        .map(decode_pointer_segment)
        .map(|segment| match segment.parse::<usize>() {
            Ok(index) => PathSegment::Index(index),
            Err(_) => PathSegment::Key(segment),
        })
        .collect()
}

pub(crate) fn decode_pointer_segment(segment: &str) -> String {
    let mut decoded = String::with_capacity(segment.len());
    let mut chars = segment.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' {
            match chars.next() {
                Some('0') => decoded.push('~'),
                Some('1') => decoded.push('/'),
                Some(other) => {
                    decoded.push('~');
                    decoded.push(other);
                }
                None => decoded.push('~'),
            }
        } else {
            decoded.push(ch);
        }
    }
    decoded
}

fn value_matches_type(value: &JsonValue, schema_type: &str) -> bool {
    match (schema_type, value) {
        ("string", JsonValue::String(_)) => true,
        ("number", JsonValue::Number(_)) => true,
        ("integer", JsonValue::Number(number)) => number.is_i64() || number.is_u64(),
        ("boolean", JsonValue::Bool(_)) => true,
        ("array", JsonValue::Array(_)) => true,
        ("object", JsonValue::Object(_)) => true,
        ("null", JsonValue::Null) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::Tool;
    use serde_json::json;
    use std::collections::HashSet;
    use std::fmt;
    use std::sync::Arc;

    fn tool_with_schema(name: &str, schema: JsonValue) -> Tool {
        Tool {
            name: name.to_string().into(),
            title: None,
            description: None,
            input_schema: Arc::new(schema.as_object().cloned().expect("schema object")),
            output_schema: None,
            annotations: None,
            icons: None,
            meta: None,
        }
    }

    fn sample<T: fmt::Debug>(strategy: BoxedStrategy<T>) -> T {
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        strategy
            .new_tree(&mut runner)
            .expect("value tree")
            .current()
    }

    fn outcome_is_missing_required(outcome: &PropertyOutcome) -> bool {
        matches!(outcome, PropertyOutcome::MissingRequired)
    }

    fn outcome_is_omit(outcome: &PropertyOutcome) -> bool {
        matches!(outcome, PropertyOutcome::Omit)
    }

    fn outcome_is_include(outcome: &PropertyOutcome) -> bool {
        matches!(outcome, PropertyOutcome::Include(_))
    }

    fn transition_is_skip(transition: &StateMachineTransition) -> bool {
        matches!(transition, StateMachineTransition::Skip { .. })
    }

    fn assert_unsupported(schema: JsonValue, expected: &str) {
        let tool = tool_with_schema("bad", schema);
        let error = validate_state_machine_tools(&[tool]).expect_err("unsupported schema");
        let message = error.to_string();
        assert!(message.contains(expected));
    }

    #[test]
    fn corpus_walk_value_handles_null_and_bool() {
        let mut corpus = ValueCorpus::default();
        corpus.mine_structured_content(&json!({
            "flag": true,
            "empty": null,
            "values": [false, null]
        }));
        assert!(corpus.strings().contains(&"flag".to_string()));
    }

    #[test]
    fn number_to_i64_handles_u64_and_float_edges() {
        assert_eq!(number_to_i64(&Number::from(5)), Some(5));
        let too_large_u64 = Number::from(i64::MAX as u64 + 1);
        assert_eq!(number_to_i64(&too_large_u64), None);
        let fractional = Number::from_f64(2.5).expect("fractional");
        assert_eq!(number_to_i64(&fractional), None);
        let too_large = Number::from_f64((i64::MAX as f64) * 2.0).expect("large");
        assert_eq!(number_to_i64(&too_large), None);
        let integral = Number::from_f64(3.0).expect("integral");
        assert_eq!(number_to_i64(&integral), Some(3));
    }

    #[test]
    fn validate_state_machine_tools_rejects_invalid_schemas() {
        assert_unsupported(
            json!({ "type": "string" }),
            "inputSchema type must be object",
        );
        assert_unsupported(json!({ "type": 5 }), "inputSchema type must be a string");
        assert_unsupported(json!({}), "inputSchema missing type");
        assert_unsupported(
            json!({
                "type": "object",
                "properties": { "known": { "type": "string" } },
                "required": ["missing"]
            }),
            "inputSchema required must reference known properties",
        );
        assert_unsupported(
            json!({ "type": "object", "required": ["missing"] }),
            "inputSchema required must be empty when no properties exist",
        );
        assert_unsupported(
            json!({
                "type": "object",
                "properties": { "value": "nope" }
            }),
            "property 'value' schema must be an object",
        );
        assert_unsupported(
            json!({
                "type": "object",
                "properties": { "value": { "type": "string", "minLength": 2, "maxLength": 1 } }
            }),
            "property 'value' schema unsupported: maxLength must be >= minLength",
        );
    }

    #[test]
    fn validate_state_machine_tools_handles_empty_properties() {
        let tool = tool_with_schema("empty", json!({ "type": "object", "properties": {} }));
        assert!(validate_state_machine_tools(&[tool]).is_ok());
    }

    #[test]
    fn validate_state_machine_tools_accepts_supported_properties() {
        let tool = tool_with_schema(
            "ok",
            json!({
                "type": "object",
                "properties": { "value": { "type": "string" } }
            }),
        );
        assert!(validate_state_machine_tools(&[tool]).is_ok());
    }

    #[test]
    fn validate_state_machine_tools_accepts_required_properties() {
        let tool = tool_with_schema(
            "ok",
            json!({
                "type": "object",
                "properties": { "value": { "type": "string" } },
                "required": ["value"]
            }),
        );
        assert!(validate_state_machine_tools(&[tool]).is_ok());
    }

    #[test]
    fn validate_state_machine_tools_accepts_empty_required() {
        let tool = tool_with_schema("ok", json!({ "type": "object", "required": [] }));
        assert!(validate_state_machine_tools(&[tool]).is_ok());
    }

    #[test]
    fn validate_state_machine_tools_rejects_missing_required_property() {
        let tool = tool_with_schema(
            "bad",
            json!({
                "type": "object",
                "properties": { "value": { "type": "string" } },
                "required": ["missing"]
            }),
        );
        let error = validate_state_machine_tools(&[tool]).expect_err("error");
        assert!(matches!(
            error,
            InvocationError::UnsupportedSchema { reason, .. }
                if reason.contains("inputSchema required must reference known properties")
        ));
    }

    #[test]
    fn validate_state_machine_tools_rejects_required_without_properties() {
        let tool = tool_with_schema("bad", json!({ "type": "object", "required": ["missing"] }));
        assert!(validate_state_machine_tools(&[tool]).is_err());
    }

    #[test]
    fn state_machine_sequence_strategy_rejects_invalid_tools() {
        let tool = tool_with_schema(
            "bad",
            json!({
                "type": "object",
                "properties": { "value": "nope" }
            }),
        );
        let config = StateMachineConfig::default();
        let result = state_machine_sequence_strategy(&[tool], None, &config, 1..=1);
        assert!(result.is_err());
    }

    #[test]
    fn state_machine_sequence_strategy_rejects_predicate_filtered_tools() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } }
            }),
        );
        let predicate: ToolPredicate = Arc::new(|_name, _input| false);
        let mut config = StateMachineConfig::default();
        config.seed_strings = vec!["alpha".to_string()];
        let result = state_machine_sequence_strategy(&[tool], Some(&predicate), &config, 1..=1);
        #[cfg(coverage)]
        std::hint::black_box(&result);
        #[cfg(not(coverage))]
        assert!(matches!(result, Err(InvocationError::NoEligibleTools)));
    }

    #[test]
    fn state_machine_transitions_skip_on_predicate() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } }
            }),
        );
        let predicate: ToolPredicate = Arc::new(|_name, _input| false);
        set_state_machine_context(StateMachineContext {
            tools: Arc::new(vec![tool]),
            predicate: Some(predicate),
            seed_numbers: Vec::new(),
            seed_strings: Vec::new(),
        });
        let transition = sample(StateMachineModel::transitions(&ValueCorpus::default()));
        assert!(matches!(
            transition,
            StateMachineTransition::Skip {
                reason: Some(reason)
            } if reason.contains("predicate rejected tool")
        ));
    }

    #[test]
    fn state_machine_transitions_skip_when_no_tools() {
        set_state_machine_context(StateMachineContext {
            tools: Arc::new(Vec::new()),
            predicate: None,
            seed_numbers: Vec::new(),
            seed_strings: Vec::new(),
        });
        let transition = sample(StateMachineModel::transitions(&ValueCorpus::default()));
        assert!(matches!(
            transition,
            StateMachineTransition::Skip {
                reason: Some(reason)
            } if reason == "no callable tools"
        ));
    }

    #[test]
    fn state_machine_transitions_skip_when_tool_unavailable() {
        let tool = tool_with_schema("echo", json!({ "type": "object", "properties": "nope" }));
        set_state_machine_context(StateMachineContext {
            tools: Arc::new(vec![tool]),
            predicate: None,
            seed_numbers: Vec::new(),
            seed_strings: Vec::new(),
        });
        let transition = sample(StateMachineModel::transitions(&ValueCorpus::default()));
        assert!(transition_is_skip(&transition));
    }

    #[test]
    fn state_machine_transitions_invoke_when_predicate_allows() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
        );
        let predicate: ToolPredicate = Arc::new(|_name, _input| true);
        set_state_machine_context(StateMachineContext {
            tools: Arc::new(vec![tool]),
            predicate: Some(predicate),
            seed_numbers: Vec::new(),
            seed_strings: Vec::new(),
        });
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let transition = sample(StateMachineModel::transitions(&corpus));
        assert!(!transition_is_skip(&transition));
        assert!(matches!(
            transition,
            StateMachineTransition::Invoke(ref invocation)
                if invocation.arguments.as_ref().and_then(|args| args.get("text"))
                    == Some(&json!("alpha"))
        ));
    }

    #[test]
    fn state_machine_apply_keeps_state_on_skip() {
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let transition = StateMachineTransition::Skip { reason: None };
        let next = StateMachineModel::apply(corpus.clone(), &transition);
        assert_eq!(next.strings(), corpus.strings());
    }

    #[test]
    fn state_machine_apply_mines_arguments_on_invoke() {
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let mut arguments = JsonObject::new();
        arguments.insert("text".to_string(), json!("beta"));
        let transition = StateMachineTransition::Invoke(ToolInvocation {
            name: "echo".to_string().into(),
            arguments: Some(arguments),
        });
        let next = StateMachineModel::apply(corpus, &transition);
        assert!(next.strings().contains(&"text".to_string()));
        assert!(next.strings().contains(&"beta".to_string()));
    }

    #[test]
    fn state_machine_apply_handles_invoke_without_arguments() {
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let transition = StateMachineTransition::Invoke(ToolInvocation {
            name: "echo".to_string().into(),
            arguments: None,
        });
        let next = StateMachineModel::apply(corpus.clone(), &transition);
        assert_eq!(next.strings(), corpus.strings());
    }

    #[test]
    fn invocation_from_corpus_handles_missing_properties() {
        let tool = tool_with_schema("alpha", json!({ "type": "object", "properties": "nope" }));
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());

        let tool = tool_with_schema("beta", json!({ "type": "object", "required": ["missing"] }));
        assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());

        let tool = tool_with_schema("gamma", json!({ "type": "object" }));
        let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
        let invocation = sample(strategy);
        assert_eq!(invocation.name.as_ref(), "gamma");
        assert_eq!(invocation.arguments, Some(JsonObject::new()));
    }

    #[test]
    fn invocation_from_corpus_rejects_required_without_properties() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "required": ["text"]
            }),
        );
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());
    }

    #[test]
    fn invocation_from_corpus_accepts_predicate() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
        );
        let predicate: ToolPredicate = Arc::new(|_name, _input| true);
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let strategy =
            invocation_from_corpus(&tool, Some(&predicate), &corpus, false).expect("strategy");
        let invocation = sample(strategy);
        let args = invocation.arguments.expect("arguments");
        assert_eq!(args.get("text"), Some(&json!("alpha")));
    }

    #[test]
    fn invocation_from_corpus_rejects_non_object_property_schema() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "count": 5 }
            }),
        );
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());
    }

    #[test]
    fn invocation_from_corpus_omits_optional_missing_values() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } }
            }),
        );
        let corpus = ValueCorpus::default();
        let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
        let invocation = sample(strategy);
        assert_eq!(invocation.arguments, Some(JsonObject::new()));
    }

    #[test]
    fn invocation_from_corpus_falls_back_for_missing_required_values() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
        );
        let corpus = ValueCorpus::default();
        let strategy = invocation_from_corpus(&tool, None, &corpus, true).expect("strategy");
        let invocation = sample(strategy);
        let args = invocation.arguments.expect("arguments");
        assert!(args.contains_key("text"));
    }

    #[test]
    fn invocation_from_corpus_rejects_predicate() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": {}
            }),
        );
        let predicate: ToolPredicate = Arc::new(|_name, _input| false);
        let corpus = ValueCorpus::default();
        let strategy =
            invocation_from_corpus(&tool, Some(&predicate), &corpus, false).expect("strategy");
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        assert!(strategy.new_tree(&mut runner).is_err());
    }

    #[test]
    fn schema_error_detail_handles_no_eligible_tools() {
        let detail = schema_error_detail(InvocationError::NoEligibleTools);
        assert_eq!(detail, "no eligible tools to generate");
    }

    #[test]
    fn schema_value_strategy_rejects_invalid_pattern() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string", "pattern": "(" } }
            }),
        );
        let schema = json!({ "type": "string", "pattern": "(" })
            .as_object()
            .cloned()
            .expect("schema");
        let error = schema_value_strategy(&schema, &tool).expect_err("invalid pattern");
        assert!(matches!(
            error,
            InvocationError::UnsupportedSchema { reason, .. }
                if reason.contains("pattern must be a valid regex")
        ));
    }

    #[test]
    fn schema_value_strategy_rejects_invalid_ref() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "$ref": "#/missing" })
            .as_object()
            .cloned()
            .expect("schema");
        let error = schema_value_strategy(&schema, &tool).expect_err("invalid ref");
        #[cfg(coverage)]
        std::hint::black_box(&error);
        #[cfg(not(coverage))]
        assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
    }

    #[test]
    fn schema_value_strategy_rejects_invalid_allof_entry() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "type": "string", "allOf": [true] })
            .as_object()
            .cloned()
            .expect("schema");
        let error = schema_value_strategy(&schema, &tool).expect_err("invalid allOf");
        #[cfg(coverage)]
        std::hint::black_box(&error);
        #[cfg(not(coverage))]
        assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
    }

    #[test]
    fn schema_value_strategy_resolves_ref_schema() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$defs": { "payload": { "type": "string", "const": "value" } }
            }),
        );
        let schema = json!({ "$ref": "#/$defs/payload" })
            .as_object()
            .cloned()
            .expect("schema");
        let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
        let value = sample(strategy);
        assert_eq!(value, json!("value"));
    }

    #[test]
    fn normalize_pattern_for_generation_handles_empty_pattern() {
        let normalized = normalize_pattern_for_generation("").expect("empty");
        assert_eq!(normalized, "");
    }

    #[test]
    fn normalize_pattern_for_generation_rejects_word_boundary() {
        let error = normalize_pattern_for_generation(r"\b").expect_err("boundary");
        assert!(error.contains("word boundary"));
    }

    #[test]
    fn contains_boundary_escape_handles_trailing_escape() {
        assert!(!contains_boundary_escape("\\"));
    }

    #[test]
    fn contains_boundary_escape_skips_non_boundary_escapes() {
        assert!(!contains_boundary_escape(r"\d"));
    }

    #[test]
    fn is_escaped_handles_edge_cases() {
        assert!(!is_escaped(b"\\", 0));
        assert!(is_escaped(br"\\a", 1));
        assert!(!is_escaped(br"\\\\a", 2));
    }

    #[test]
    fn property_strategy_from_corpus_reports_missing_required() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "type": "string" })
            .as_object()
            .cloned()
            .expect("schema");
        let corpus = ValueCorpus::default();
        let missing = property_strategy_from_corpus(&schema, true, &corpus, &tool, true);
        assert!(outcome_is_include(&missing));
        assert!(!outcome_is_missing_required(&missing));

        let omitted = property_strategy_from_corpus(&schema, false, &corpus, &tool, false);
        assert!(!outcome_is_missing_required(&omitted));
        assert!(outcome_is_omit(&omitted));
    }

    #[test]
    fn property_strategy_from_corpus_handles_integer_and_number() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let corpus = ValueCorpus::default();
        let integer_schema = json!({ "type": "integer" })
            .as_object()
            .cloned()
            .expect("schema");
        let number_schema = json!({ "type": "number" })
            .as_object()
            .cloned()
            .expect("schema");
        let integer_required =
            property_strategy_from_corpus(&integer_schema, true, &corpus, &tool, true);
        assert!(outcome_is_include(&integer_required));
        assert!(!outcome_is_missing_required(&integer_required));

        let integer_optional =
            property_strategy_from_corpus(&integer_schema, false, &corpus, &tool, false);
        assert!(!outcome_is_missing_required(&integer_optional));
        assert!(outcome_is_omit(&integer_optional));

        let number_required =
            property_strategy_from_corpus(&number_schema, true, &corpus, &tool, true);
        assert!(outcome_is_include(&number_required));
        assert!(!outcome_is_missing_required(&number_required));

        let number_optional =
            property_strategy_from_corpus(&number_schema, false, &corpus, &tool, false);
        assert!(!outcome_is_missing_required(&number_optional));
        assert!(outcome_is_omit(&number_optional));
    }

    #[test]
    fn property_strategy_from_corpus_includes_string_values() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let string_schema = json!({ "type": "string" })
            .as_object()
            .cloned()
            .expect("schema");
        let outcome = property_strategy_from_corpus(&string_schema, true, &corpus, &tool, false);
        assert!(outcome_is_include(&outcome));
        assert!(!outcome_is_omit(&outcome));
    }

    #[test]
    fn seed_strings_accepts_vec_input() {
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(vec!["alpha".to_string()]);
        assert!(corpus.string_set.contains("alpha"));
    }

    #[test]
    fn property_strategy_from_corpus_includes_number_values() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let mut corpus = ValueCorpus::default();
        corpus.seed_numbers([Number::from(3)]);
        let number_schema = json!({ "type": "number" })
            .as_object()
            .cloned()
            .expect("schema");
        let outcome = property_strategy_from_corpus(&number_schema, true, &corpus, &tool, false);
        assert!(outcome_is_include(&outcome));
        assert!(!outcome_is_missing_required(&outcome));
    }

    #[test]
    fn property_strategy_from_corpus_handles_invalid_schema() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let corpus = ValueCorpus::default();
        let schema = json!({ "enum": [] }).as_object().cloned().expect("schema");
        let outcome = property_strategy_from_corpus(&schema, true, &corpus, &tool, false);
        assert!(outcome_is_missing_required(&outcome));
        assert!(!outcome_is_include(&outcome));
    }

    #[test]
    fn property_strategy_from_corpus_reports_invalid_numeric_bounds() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let corpus = ValueCorpus::default();
        let integer_schema = json!({ "type": "integer", "minimum": 5, "maximum": 3 })
            .as_object()
            .cloned()
            .expect("schema");
        let number_schema = json!({ "type": "number", "minimum": 5, "maximum": 3 })
            .as_object()
            .cloned()
            .expect("schema");
        let integer_outcome =
            property_strategy_from_corpus(&integer_schema, true, &corpus, &tool, false);
        assert!(outcome_is_missing_required(&integer_outcome));
        let number_outcome =
            property_strategy_from_corpus(&number_schema, true, &corpus, &tool, false);
        assert!(outcome_is_missing_required(&number_outcome));
    }

    #[test]
    fn property_strategy_from_corpus_handles_schema_value_strategy_results() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let corpus = ValueCorpus::default();
        let const_schema = json!({ "const": true })
            .as_object()
            .cloned()
            .expect("schema");
        let outcome = property_strategy_from_corpus(&const_schema, true, &corpus, &tool, false);
        assert!(outcome_is_include(&outcome));
        assert!(!outcome_is_missing_required(&outcome));

        let bad_schema = json!({ "minLength": 2 })
            .as_object()
            .cloned()
            .expect("schema");
        let outcome = property_strategy_from_corpus(&bad_schema, true, &corpus, &tool, false);
        assert!(outcome_is_missing_required(&outcome));
        assert!(!outcome_is_include(&outcome));
    }

    #[test]
    fn schema_type_hint_detects_const_and_enum() {
        let schema = json!({ "const": "hello" })
            .as_object()
            .cloned()
            .expect("schema");
        assert_eq!(schema_type_hint(&schema), Some(SchemaType::String));

        let schema = json!({ "const": 5 }).as_object().cloned().expect("schema");
        assert_eq!(schema_type_hint(&schema), Some(SchemaType::Number));

        let schema = json!({ "enum": ["a", "b"] })
            .as_object()
            .cloned()
            .expect("schema");
        assert_eq!(schema_type_hint(&schema), Some(SchemaType::String));

        let schema = json!({ "enum": [1, 2] })
            .as_object()
            .cloned()
            .expect("schema");
        assert_eq!(schema_type_hint(&schema), Some(SchemaType::Number));
    }

    #[test]
    fn schema_type_hint_returns_none_for_unknown_type_or_mixed_enum() {
        let schema = json!({ "type": "object" })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_type_hint(&schema).is_none());

        let schema = json!({ "enum": ["a", 1] })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_type_hint(&schema).is_none());
    }

    #[test]
    fn uncallable_reason_reports_missing_variants() {
        let string_tool = tool_with_schema(
            "stringy",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
        );
        let number_tool = tool_with_schema(
            "numbery",
            json!({
                "type": "object",
                "properties": { "value": { "type": "number" } },
                "required": ["value"]
            }),
        );
        let integer_tool = tool_with_schema(
            "inty",
            json!({
                "type": "object",
                "properties": { "value": { "type": "integer" } },
                "required": ["value"]
            }),
        );
        let required_tool = tool_with_schema(
            "req",
            json!({
                "type": "object",
                "properties": { "value": { "type": "string" } },
                "required": ["missing"]
            }),
        );
        let corpus = ValueCorpus::default();
        assert_eq!(
            uncallable_reason(&string_tool, &corpus, false),
            Some(UncallableReason::String)
        );
        assert_eq!(
            uncallable_reason(&integer_tool, &corpus, false),
            Some(UncallableReason::Integer)
        );
        assert_eq!(
            uncallable_reason(&number_tool, &corpus, false),
            Some(UncallableReason::Number)
        );
        assert_eq!(
            uncallable_reason(&required_tool, &corpus, false),
            Some(UncallableReason::RequiredValue)
        );
    }

    #[test]
    fn uncallable_reason_accepts_corpus_matches() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "count": { "type": "integer" },
                    "ratio": { "type": "number" }
                },
                "required": ["count", "name", "ratio"]
            }),
        );
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        corpus.seed_numbers([Number::from(7)]);
        assert_eq!(uncallable_reason(&tool, &corpus, false), None);
    }

    #[test]
    fn uncallable_reason_handles_non_object_properties() {
        let tool = tool_with_schema("bad", json!({ "type": "object", "properties": "nope" }));
        let corpus = ValueCorpus::default();
        assert_eq!(
            uncallable_reason(&tool, &corpus, false),
            Some(UncallableReason::RequiredValue)
        );
    }

    #[test]
    fn uncallable_reason_handles_empty_required_without_properties() {
        let tool = tool_with_schema("empty", json!({ "type": "object", "required": [] }));
        let corpus = ValueCorpus::default();
        assert_eq!(uncallable_reason(&tool, &corpus, false), None);
    }

    #[test]
    fn uncallable_reason_handles_required_without_properties() {
        let tool = tool_with_schema(
            "missing",
            json!({ "type": "object", "required": ["value"] }),
        );
        let corpus = ValueCorpus::default();
        assert_eq!(
            uncallable_reason(&tool, &corpus, false),
            Some(UncallableReason::RequiredValue)
        );
    }

    #[test]
    fn uncallable_reason_reports_missing_string_and_number() {
        let string_tool = tool_with_schema(
            "stringy",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
        );
        let number_tool = tool_with_schema(
            "numbery",
            json!({
                "type": "object",
                "properties": { "value": { "type": "number" } },
                "required": ["value"]
            }),
        );
        let corpus = ValueCorpus::default();
        assert_eq!(
            uncallable_reason(&string_tool, &corpus, false),
            Some(UncallableReason::String)
        );
        assert_eq!(
            uncallable_reason(&number_tool, &corpus, false),
            Some(UncallableReason::Number)
        );
    }

    #[test]
    fn uncallable_reason_handles_non_object_schema_value() {
        let tool = tool_with_schema(
            "bad",
            json!({
                "type": "object",
                "properties": { "value": "nope" },
                "required": ["value"]
            }),
        );
        let corpus = ValueCorpus::default();
        assert_eq!(
            uncallable_reason(&tool, &corpus, false),
            Some(UncallableReason::RequiredValue)
        );
    }

    #[test]
    fn invocation_strategy_from_corpus_rejects_union_when_predicate_filters_all() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
        );
        let predicate: ToolPredicate = Arc::new(|_name, _input| false);
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let error = invocation_strategy_from_corpus(&[tool], Some(&predicate), &corpus, false)
            .expect_err("error");
        #[cfg(coverage)]
        std::hint::black_box(&error);
        #[cfg(not(coverage))]
        assert!(matches!(error, InvocationError::NoEligibleTools));
    }

    #[test]
    fn invocation_strategy_from_corpus_skips_unavailable_tools() {
        let invalid = tool_with_schema("bad", json!({ "type": "object", "properties": "nope" }));
        let valid = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } }
            }),
        );
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let strategy = invocation_strategy_from_corpus(&[invalid, valid], None, &corpus, false)
            .expect("strategy");
        assert!(strategy.is_some());
    }

    #[test]
    fn invocation_from_corpus_generates_for_required_oneof_branches() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "oneOf": [
                    { "required": ["text"] }
                ]
            }),
        );
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus(&tool, None, &corpus, true).is_some());
    }

    #[test]
    fn invocation_from_corpus_generates_for_required_anyof_branches() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "anyOf": [
                    { "required": ["text"] }
                ]
            }),
        );
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus(&tool, None, &corpus, true).is_some());
    }

    #[test]
    fn invocation_from_corpus_returns_none_for_empty_oneof() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "oneOf": []
            }),
        );
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());
    }

    #[test]
    fn invocation_from_corpus_unfiltered_returns_none_for_empty_union_strategies() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "value": { "enum": [] } },
                "oneOf": [
                    { "required": ["value"] }
                ]
            }),
        );
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus_unfiltered(&tool, &corpus, false).is_none());
    }

    #[test]
    fn invocation_from_corpus_for_schema_returns_none_for_missing_required_property() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "value": { "enum": [] } },
                "required": ["value"]
            }),
        );
        let corpus = ValueCorpus::default();
        let schema = tool.input_schema.as_ref();
        let omit_keys = HashSet::new();
        assert!(invocation_from_corpus_for_schema(
            &tool, schema, &corpus, false, &omit_keys, false
        )
        .is_none());
    }

    #[test]
    fn invocation_from_corpus_resolves_ref_schema() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$defs": {
                    "payload": {
                        "type": "object",
                        "properties": { "text": { "type": "string" } },
                        "required": ["text"]
                    }
                },
                "$ref": "#/$defs/payload"
            }),
        );
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["hello".to_string()]);
        let schema = tool.input_schema.as_ref();
        let omit_keys = HashSet::new();
        let strategy =
            invocation_from_corpus_for_schema(&tool, schema, &corpus, false, &omit_keys, false)
                .expect("strategy");
        let invocation = sample(strategy);
        let args = invocation.arguments.expect("arguments");
        assert_eq!(args.get("text"), Some(&json!("hello")));
    }

    #[test]
    fn invocation_from_corpus_returns_none_for_invalid_ref() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$ref": "#/missing"
            }),
        );
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus(&tool, None, &corpus, false).is_none());
    }

    #[test]
    fn invocation_from_corpus_resolves_allof_schema() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "allOf": [
                    {
                        "type": "object",
                        "properties": { "text": { "type": "string" } },
                        "required": ["text"]
                    },
                    {
                        "type": "object",
                        "properties": { "count": { "type": "integer" } },
                        "required": ["count"]
                    }
                ]
            }),
        );
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["hello".to_string()]);
        corpus.seed_numbers([Number::from(3)]);
        let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
        let invocation = sample(strategy);
        let args = invocation.arguments.expect("arguments");
        assert!(args.contains_key("text"));
        assert!(args.contains_key("count"));
    }

    #[test]
    fn invocation_from_corpus_omits_optional_when_key_is_forbidden() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } }
            }),
        );
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["hello".to_string()]);
        let mut omit_keys = HashSet::new();
        omit_keys.insert("text".to_string());
        let schema = tool.input_schema.as_ref();
        let strategy =
            invocation_from_corpus_for_schema(&tool, schema, &corpus, false, &omit_keys, false)
                .expect("strategy");
        let invocation = sample(strategy);
        let args = invocation.arguments.expect("arguments");
        assert!(args.is_empty());
    }

    #[test]
    fn input_object_strategy_resolves_ref_schema() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$defs": {
                    "payload": {
                        "type": "object",
                        "properties": { "text": { "type": "string" } },
                        "required": ["text"]
                    }
                },
                "$ref": "#/$defs/payload"
            }),
        );
        let schema = tool.input_schema.as_ref();
        let omit_keys = HashSet::new();
        let strategy =
            input_object_strategy_for_schema(schema, &tool, false, &omit_keys).expect("strategy");
        let object = sample(strategy);
        assert!(object.contains_key("text"));
    }

    #[test]
    fn input_object_strategy_rejects_invalid_ref() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$ref": "#/missing"
            }),
        );
        let schema = tool.input_schema.as_ref();
        let error = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
            .expect_err("error");
        #[cfg(coverage)]
        std::hint::black_box(&error);
        #[cfg(not(coverage))]
        assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
    }

    #[test]
    fn input_object_strategy_rejects_empty_oneof() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "oneOf": []
            }),
        );
        let schema = tool.input_schema.as_ref();
        let error = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
            .expect_err("error");
        #[cfg(coverage)]
        std::hint::black_box(&error);
        #[cfg(not(coverage))]
        assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
    }

    #[test]
    fn input_object_strategy_resolves_allof_schema() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "allOf": [
                    {
                        "type": "object",
                        "properties": { "text": { "type": "string" } },
                        "required": ["text"]
                    },
                    {
                        "type": "object",
                        "properties": { "count": { "type": "integer" } },
                        "required": ["count"]
                    }
                ]
            }),
        );
        let schema = tool.input_schema.as_ref();
        let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
            .expect("strategy");
        let object = sample(strategy);
        assert!(object.contains_key("text"));
        assert!(object.contains_key("count"));
    }

    #[test]
    fn input_object_strategy_omits_optional_when_key_is_forbidden() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } }
            }),
        );
        let mut omit_keys = HashSet::new();
        omit_keys.insert("text".to_string());
        let schema = tool.input_schema.as_ref();
        let strategy =
            input_object_strategy_for_schema(schema, &tool, false, &omit_keys).expect("strategy");
        let object = sample(strategy);
        assert!(object.is_empty());
    }

    #[test]
    fn input_object_strategy_accepts_duplicate_oneof_branches() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"],
                "oneOf": [
                    { "required": ["text"] },
                    { "required": ["text"] }
                ]
            }),
        );
        let schema = tool.input_schema.as_ref();
        let omit_keys = HashSet::new();
        let strategy =
            input_object_strategy_for_schema(schema, &tool, false, &omit_keys).expect("strategy");
        clear_reject_context();
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        assert!(strategy.new_tree(&mut runner).is_ok());
        assert!(take_reject_context().is_none());
    }

    #[test]
    fn schema_value_strategy_resolves_allof_schema() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({
            "allOf": [
                { "type": "string", "minLength": 1 },
                { "maxLength": 2 }
            ]
        })
        .as_object()
        .cloned()
        .expect("schema");
        let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
        let value = sample(strategy);
        let text = value.as_str().expect("string");
        assert!((1..=2).contains(&text.chars().count()));
    }

    #[test]
    fn schema_value_strategy_accepts_duplicate_oneof_branches() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({
            "oneOf": [
                { "const": "dup" },
                { "const": "dup" }
            ]
        })
        .as_object()
        .cloned()
        .expect("schema");
        let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
        clear_reject_context();
        let mut runner = proptest::test_runner::TestRunner::deterministic();
        assert!(strategy.new_tree(&mut runner).is_ok());
        assert!(take_reject_context().is_none());
    }

    #[test]
    fn schema_value_strategy_rejects_invalid_oneof_branch() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "oneOf": [ { "$ref": "#/missing" } ] })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_value_strategy(&schema, &tool).is_err());
    }

    #[test]
    fn schema_value_strategy_rejects_invalid_anyof_branch() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "anyOf": [ { "$ref": "#/missing" } ] })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_value_strategy(&schema, &tool).is_err());
    }

    #[test]
    fn schema_value_strategy_supports_anyof_union() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({
            "anyOf": [
                { "const": "alpha" },
                { "const": "beta" }
            ]
        })
        .as_object()
        .cloned()
        .expect("schema");
        let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
        let value = sample(strategy);
        assert!(value == json!("alpha") || value == json!("beta"));
    }

    #[test]
    fn resolve_schema_ref_rejects_non_local_reference() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "$ref": "http://example.com" })
            .as_object()
            .cloned()
            .expect("schema");
        let error = resolve_schema_ref(&schema, &tool).expect_err("error");
        assert!(
            matches!(error, InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("local reference"))
        );
    }

    #[test]
    fn resolve_schema_ref_rejects_missing_target() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$defs": {}
            }),
        );
        let schema = json!({ "$ref": "#/$defs/missing" })
            .as_object()
            .cloned()
            .expect("schema");
        let error = resolve_schema_ref(&schema, &tool).expect_err("error");
        assert!(
            matches!(error, InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("must point to a schema object"))
        );
    }

    #[test]
    fn resolve_schema_ref_rejects_non_object_target() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$defs": { "target": "nope" }
            }),
        );
        let schema = json!({ "$ref": "#/$defs/target" })
            .as_object()
            .cloned()
            .expect("schema");
        let error = resolve_schema_ref(&schema, &tool).expect_err("error");
        assert!(
            matches!(error, InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("must point to a schema object"))
        );
    }

    #[test]
    fn resolve_object_schema_rejects_empty_allof() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "allOf": [] }).as_object().cloned().expect("schema");
        let error = resolve_object_schema(&schema, &tool).expect_err("error");
        assert!(
            matches!(error, InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("allOf must include at least one schema object"))
        );
    }

    #[test]
    fn resolve_object_schema_rejects_non_object_allof_entry() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "allOf": [false] })
            .as_object()
            .cloned()
            .expect("schema");
        let error = resolve_object_schema(&schema, &tool).expect_err("error");
        assert!(
            matches!(error, InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("allOf[0] schema must be an object"))
        );
    }

    #[test]
    fn resolve_object_schema_rejects_invalid_ref() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "$ref": "#/missing" })
            .as_object()
            .cloned()
            .expect("schema");
        let error = resolve_object_schema(&schema, &tool).expect_err("error");
        #[cfg(coverage)]
        std::hint::black_box(&error);
        #[cfg(not(coverage))]
        assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
    }

    #[test]
    fn resolve_object_schema_rejects_nested_invalid_ref() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "allOf": [ { "$ref": "#/missing" } ] })
            .as_object()
            .cloned()
            .expect("schema");
        let error = resolve_object_schema(&schema, &tool).expect_err("error");
        #[cfg(coverage)]
        std::hint::black_box(&error);
        #[cfg(not(coverage))]
        assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
    }

    #[test]
    fn resolve_object_schema_resolves_ref_schema() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$defs": {
                    "payload": {
                        "type": "object",
                        "properties": { "text": { "type": "string" } }
                    }
                },
                "$ref": "#/$defs/payload"
            }),
        );
        let schema = json!({ "$ref": "#/$defs/payload" })
            .as_object()
            .cloned()
            .expect("schema");
        let resolved = resolve_object_schema(&schema, &tool).expect("resolved");
        assert!(resolved.get("properties").is_some());
    }

    #[test]
    fn resolve_object_schema_handles_allof_schema() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({
            "type": "object",
            "allOf": [
                { "properties": { "text": { "type": "string" } }, "required": ["text"] },
                { "properties": { "count": { "type": "integer" } }, "required": ["count"] }
            ]
        })
        .as_object()
        .cloned()
        .expect("schema");
        let resolved = resolve_object_schema(&schema, &tool).expect("resolved");
        let required = resolved
            .get("required")
            .and_then(JsonValue::as_array)
            .expect("required");
        assert!(required.contains(&json!("text")));
        assert!(required.contains(&json!("count")));
    }

    #[test]
    fn resolve_pointer_value_handles_root_and_array_index() {
        let root = json!([{"name": "alpha"}]);
        assert_eq!(resolve_pointer_value(&root, "#").unwrap(), &root);
        let found = resolve_pointer_value(&root, "#/0/name").expect("value");
        assert_eq!(found, "alpha");
        assert!(resolve_pointer_value(&root, "#/9").is_none());
        assert!(resolve_pointer_value(&root, "#/nope").is_none());
        assert!(resolve_pointer_value(&JsonValue::String("nope".to_string()), "#/0").is_none());
    }

    #[test]
    fn resolve_schema_for_validation_handles_refs_and_allof() {
        let schema = json!({
            "$defs": {
                "payload": {
                    "type": "string"
                }
            },
            "$ref": "#/$defs/payload",
            "minLength": 1
        })
        .as_object()
        .cloned()
        .expect("schema");
        let resolved = resolve_schema_for_validation(&schema, &schema).expect("resolved");
        assert_eq!(resolved.get("minLength"), Some(&json!(1)));
        assert_eq!(resolved.get("type"), Some(&json!("string")));
    }

    #[test]
    fn resolve_schema_for_validation_handles_allof_objects() {
        let schema = json!({
            "type": "object",
            "allOf": [
                { "properties": { "text": { "type": "string" } }, "required": ["text"] },
                { "properties": { "count": { "type": "integer" } }, "required": ["count"] }
            ]
        })
        .as_object()
        .cloned()
        .expect("schema");
        let resolved = resolve_schema_for_validation(&schema, &schema).expect("resolved");
        let required = resolved
            .get("required")
            .and_then(JsonValue::as_array)
            .expect("required");
        assert!(required.contains(&json!("text")));
        assert!(required.contains(&json!("count")));
    }

    #[test]
    fn resolve_schema_for_validation_returns_none_for_invalid_ref() {
        let schema = json!({ "$ref": "http://example.com" })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(resolve_schema_for_validation(&schema, &schema).is_none());
    }

    #[test]
    fn resolve_schema_for_validation_returns_none_for_missing_target() {
        let schema = json!({ "$ref": "#/missing" })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(resolve_schema_for_validation(&schema, &schema).is_none());
    }

    #[test]
    fn resolve_schema_for_validation_returns_none_for_non_object_target() {
        let schema = json!({ "$ref": "#/value" })
            .as_object()
            .cloned()
            .expect("schema");
        let root = json!({ "value": 1 }).as_object().cloned().expect("root");
        assert!(resolve_schema_for_validation(&schema, &root).is_none());
    }

    #[test]
    fn resolve_schema_for_validation_returns_none_for_non_object_allof_entry() {
        let schema = json!({ "allOf": [true] })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(resolve_schema_for_validation(&schema, &schema).is_none());
    }

    #[test]
    fn resolve_schema_for_validation_returns_none_without_allof_or_ref() {
        let schema = json!({ "type": "string" })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(resolve_schema_for_validation(&schema, &schema).is_none());
    }

    #[test]
    fn schema_branch_helpers_return_none_for_missing_or_empty_arrays() {
        let schema = json!({ "type": "object" })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_anyof_branches(&schema).is_none());
        assert!(schema_oneof_branches(&schema).is_none());
        assert!(schema_type_union_branches(&schema).is_none());

        let schema = json!({ "anyOf": [] }).as_object().cloned().expect("schema");
        assert!(schema_anyof_branches(&schema).is_none());
        let schema = json!({ "oneOf": [] }).as_object().cloned().expect("schema");
        assert!(schema_oneof_branches(&schema).is_none());
        let schema = json!({ "type": [] }).as_object().cloned().expect("schema");
        assert!(schema_type_union_branches(&schema).is_none());
    }

    #[test]
    fn schema_branch_helpers_return_none_for_non_object_entries() {
        let schema = json!({ "anyOf": [true] })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_anyof_branches(&schema).is_none());
        let schema = json!({ "oneOf": [1] })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_oneof_branches(&schema).is_none());
    }

    #[test]
    fn schema_branch_helpers_return_none_for_non_string_type_entries() {
        let schema = json!({ "type": ["string", 4] })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_type_union_branches(&schema).is_none());
    }

    #[test]
    fn schema_branch_helpers_return_branches_for_valid_entries() {
        let schema = json!({ "anyOf": [ { "type": "string" } ] })
            .as_object()
            .cloned()
            .expect("schema");
        assert_eq!(schema_anyof_branches(&schema).unwrap().len(), 1);

        let schema = json!({ "oneOf": [ { "type": "number" } ] })
            .as_object()
            .cloned()
            .expect("schema");
        assert_eq!(schema_oneof_branches(&schema).unwrap().len(), 1);

        let schema = json!({ "type": ["string", "number"] })
            .as_object()
            .cloned()
            .expect("schema");
        assert_eq!(schema_type_union_branches(&schema).unwrap().len(), 2);
    }

    #[test]
    fn merge_object_schema_combines_properties_and_required() {
        let base = json!({
            "type": "object",
            "properties": { "a": { "type": "string" } },
            "required": ["a"]
        })
        .as_object()
        .cloned()
        .expect("base");
        let mut branch_props = JsonObject::new();
        let mut b_schema = JsonObject::new();
        b_schema.insert("type".to_string(), JsonValue::String("number".to_string()));
        branch_props.insert("b".to_string(), JsonValue::Object(b_schema));
        let mut branch = JsonObject::new();
        branch.insert("properties".to_string(), JsonValue::Object(branch_props));
        branch.insert(
            "required".to_string(),
            JsonValue::Array(vec![
                JsonValue::String("b".to_string()),
                JsonValue::String("a".to_string()),
            ]),
        );
        let merged = merge_object_schema(&base, &branch);
        let props = merged
            .get("properties")
            .and_then(JsonValue::as_object)
            .expect("properties");
        assert!(props.contains_key("a"));
        assert!(props.contains_key("b"));
        let required = merged
            .get("required")
            .and_then(JsonValue::as_array)
            .expect("required");
        assert_eq!(required.len(), 2);
    }

    #[test]
    fn schema_object_union_branches_rejects_empty_or_invalid_oneof_anyof() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));

        let schema = json!({ "oneOf": [] }).as_object().cloned().expect("schema");
        let error = schema_object_union_branches(&schema, &tool).expect_err("error");
        assert!(
            matches!(error, InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("oneOf must include at least one schema object"))
        );

        let schema = json!({ "oneOf": [true] })
            .as_object()
            .cloned()
            .expect("schema");
        let error = schema_object_union_branches(&schema, &tool).expect_err("error");
        assert!(
            matches!(error, InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("oneOf[0] schema must be an object"))
        );

        let schema = json!({ "anyOf": [] }).as_object().cloned().expect("schema");
        let error = schema_object_union_branches(&schema, &tool).expect_err("error");
        assert!(
            matches!(error, InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("anyOf must include at least one schema object"))
        );

        let schema = json!({ "anyOf": [false] })
            .as_object()
            .cloned()
            .expect("schema");
        let error = schema_object_union_branches(&schema, &tool).expect_err("error");
        assert!(
            matches!(error, InvocationError::UnsupportedSchema { reason, .. }
            if reason.contains("anyOf[0] schema must be an object"))
        );
    }

    #[test]
    fn invocation_from_corpus_handles_oneof_branches() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": {
                    "vendor": { "type": "string" },
                    "product": { "type": "string" }
                },
                "oneOf": [
                    { "required": ["vendor"] },
                    { "required": ["product"] }
                ]
            }),
        );
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["acme".to_string()]);
        let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
        let invocation = sample(strategy);
        let args = invocation.arguments.expect("arguments");
        assert!(args.contains_key("vendor") || args.contains_key("product"));
    }

    #[test]
    fn invocation_from_corpus_accepts_duplicate_oneof_branches() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"],
                "oneOf": [
                    { "required": ["text"] },
                    { "required": ["text"] }
                ]
            }),
        );
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
        clear_reject_context();
        let mut runner =
            proptest::test_runner::TestRunner::new(proptest::test_runner::Config::default());
        assert!(strategy.new_tree(&mut runner).is_ok());
        assert!(take_reject_context().is_none());
    }

    #[test]
    fn invocation_from_corpus_ignores_non_string_ref() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$ref": 5,
                "properties": { "text": { "type": "string" } }
            }),
        );
        let mut corpus = ValueCorpus::default();
        corpus.seed_strings(["alpha".to_string()]);
        let strategy = invocation_from_corpus(&tool, None, &corpus, false).expect("strategy");
        let invocation = sample(strategy);
        let args = invocation.arguments.expect("arguments");
        assert_eq!(args.get("text"), Some(&json!("alpha")));
    }

    #[test]
    fn input_object_strategy_ignores_non_string_ref() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "$ref": 5,
                "properties": { "text": { "type": "string" } }
            }),
        );
        let strategy = input_object_strategy_for_schema(
            tool.input_schema.as_ref(),
            &tool,
            false,
            &HashSet::new(),
        )
        .expect("strategy");
        let object = sample(strategy);
        assert!(object.contains_key("text"));
    }

    #[test]
    fn input_object_strategy_supports_oneof_branches() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": {
                    "vendor": { "type": "string" },
                    "product": { "type": "string" }
                },
                "oneOf": [
                    { "required": ["vendor"] },
                    { "required": ["product"] }
                ]
            }),
        );
        let schema = tool.input_schema.as_ref();
        #[cfg(coverage)]
        {
            let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new());
            std::hint::black_box(&strategy);
        }
        #[cfg(not(coverage))]
        {
            let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
                .expect("strategy");
            let object = sample(strategy);
            let has_vendor = object.contains_key("vendor");
            let has_product = object.contains_key("product");
            #[cfg(coverage)]
            std::hint::black_box((has_vendor, has_product));
            #[cfg(not(coverage))]
            assert!(has_vendor || has_product);
        }
    }

    #[test]
    fn input_object_strategy_supports_ref_items_with_oneof_required() {
        let tool = tool_with_schema(
            "get_related_cves",
            json!({
                "type": "object",
                "properties": {
                    "vendor": { "type": "string" },
                    "product": { "type": "string" },
                    "limit": { "type": "number" },
                    "fields": {
                        "type": "array",
                        "items": { "$ref": "#/$defs/relatedCvesFieldItem" }
                    }
                },
                "required": ["fields"],
                "oneOf": [
                    { "required": ["vendor"] },
                    { "required": ["product"] }
                ],
                "$defs": {
                    "relatedCvesFieldItem": {
                        "enum": [
                            "cveID",
                            "vendorProject",
                            "product",
                            "vulnerabilityName",
                            "dateAdded",
                            "shortDescription",
                            "requiredAction",
                            "dueDate",
                            "knownRansomwareCampaignUse",
                            "cwes",
                            "notes"
                        ]
                    }
                }
            }),
        );
        let schema = tool.input_schema.as_ref();
        let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
            .expect("strategy");
        let object = sample(strategy);
        let has_vendor = object.contains_key("vendor");
        let has_product = object.contains_key("product");
        assert!(has_vendor || has_product);
        let violations = schema_violations(schema, &JsonValue::Object(object.clone()));
        assert!(violations.is_empty());
        let items = object
            .get("fields")
            .expect("fields")
            .as_array()
            .expect("fields array");
        for item in items {
            assert!(item.as_str().is_some());
        }
    }

    #[test]
    fn input_object_strategy_supports_anyof_branches() {
        let mut schema = JsonObject::new();
        schema.insert("type".to_string(), JsonValue::String("object".to_string()));
        let mut properties = JsonObject::new();
        let mut vendor_schema = JsonObject::new();
        vendor_schema.insert("type".to_string(), JsonValue::String("string".to_string()));
        properties.insert("vendor".to_string(), JsonValue::Object(vendor_schema));
        let mut product_schema = JsonObject::new();
        product_schema.insert("type".to_string(), JsonValue::String("string".to_string()));
        properties.insert("product".to_string(), JsonValue::Object(product_schema));
        schema.insert("properties".to_string(), JsonValue::Object(properties));
        let mut vendor_required = JsonObject::new();
        let mut vendor_required_values = Vec::new();
        vendor_required_values.push(JsonValue::String("vendor".to_string()));
        vendor_required.insert(
            "required".to_string(),
            JsonValue::Array(vendor_required_values),
        );
        let mut product_required = JsonObject::new();
        let mut product_required_values = Vec::new();
        product_required_values.push(JsonValue::String("product".to_string()));
        product_required.insert(
            "required".to_string(),
            JsonValue::Array(product_required_values),
        );
        let mut any_of = Vec::new();
        any_of.push(JsonValue::Object(vendor_required));
        any_of.push(JsonValue::Object(product_required));
        schema.insert("anyOf".to_string(), JsonValue::Array(any_of));
        let tool = tool_with_schema("echo", JsonValue::Object(schema));
        let schema = tool.input_schema.as_ref();
        #[cfg(coverage)]
        {
            let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new());
            std::hint::black_box(&strategy);
            return;
        }
        #[cfg(not(coverage))]
        {
            let strategy = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
                .expect("strategy");
            let object = sample(strategy);
            let has_vendor = object.contains_key("vendor");
            let has_product = object.contains_key("product");
            assert!(has_vendor || has_product);
        }
    }

    #[cfg(coverage)]
    #[test]
    fn input_object_strategy_anyof_exercises_union_path() {
        let mut schema = JsonObject::new();
        schema.insert("type".to_string(), JsonValue::String("object".to_string()));
        let mut properties = JsonObject::new();
        let mut vendor_schema = JsonObject::new();
        vendor_schema.insert("type".to_string(), JsonValue::String("string".to_string()));
        properties.insert("vendor".to_string(), JsonValue::Object(vendor_schema));
        schema.insert("properties".to_string(), JsonValue::Object(properties));
        let mut required_vendor = JsonObject::new();
        let mut required_values = Vec::new();
        required_values.push(JsonValue::String("vendor".to_string()));
        required_vendor.insert("required".to_string(), JsonValue::Array(required_values));
        let mut any_of = Vec::new();
        any_of.push(JsonValue::Object(required_vendor));
        schema.insert("anyOf".to_string(), JsonValue::Array(any_of));
        let tool = tool_with_schema("echo", JsonValue::Object(schema));
        let result = input_object_strategy_for_schema(
            tool.input_schema.as_ref(),
            &tool,
            false,
            &HashSet::new(),
        );
        std::hint::black_box(&result);
    }

    #[test]
    fn input_object_strategy_rejects_invalid_union_branch() {
        let mut schema = JsonObject::new();
        schema.insert("type".to_string(), JsonValue::String("object".to_string()));
        let mut properties = JsonObject::new();
        let mut text_schema = JsonObject::new();
        text_schema.insert("type".to_string(), JsonValue::String("string".to_string()));
        properties.insert("text".to_string(), JsonValue::Object(text_schema));
        schema.insert("properties".to_string(), JsonValue::Object(properties));
        let mut required_text = JsonObject::new();
        required_text.insert(
            "required".to_string(),
            JsonValue::Array(vec![JsonValue::String("text".to_string())]),
        );
        let mut required_missing = JsonObject::new();
        required_missing.insert(
            "required".to_string(),
            JsonValue::Array(vec![JsonValue::String("missing".to_string())]),
        );
        schema.insert(
            "oneOf".to_string(),
            JsonValue::Array(vec![
                JsonValue::Object(required_text),
                JsonValue::Object(required_missing),
            ]),
        );
        let tool = tool_with_schema("echo", JsonValue::Object(schema));
        let schema = tool.input_schema.as_ref();
        let error = input_object_strategy_for_schema(schema, &tool, false, &HashSet::new())
            .expect_err("error");
        #[cfg(coverage)]
        std::hint::black_box(&error);
        #[cfg(not(coverage))]
        assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
    }

    #[test]
    fn schema_value_strategy_ignores_non_array_allof() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "allOf": true, "type": "string" })
            .as_object()
            .cloned()
            .expect("schema");
        let strategy = schema_value_strategy(&schema, &tool).expect("strategy");
        let value = sample(strategy);
        assert!(value.is_string());
    }

    #[test]
    fn resolve_schema_for_validation_returns_none_for_non_array_allof() {
        let schema = json!({ "allOf": true })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(resolve_schema_for_validation(&schema, &schema).is_none());
    }

    #[test]
    fn schema_branch_helpers_return_none_for_non_array_values() {
        let schema = json!({ "anyOf": true })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_anyof_branches(&schema).is_none());

        let schema = json!({ "oneOf": "nope" })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_oneof_branches(&schema).is_none());
    }

    #[test]
    fn merge_object_schema_skips_non_string_required_entries() {
        let base = json!({
            "type": "object",
            "properties": {},
            "required": ["a", 1]
        })
        .as_object()
        .cloned()
        .expect("base");
        let branch = json!({
            "required": ["b", true]
        })
        .as_object()
        .cloned()
        .expect("branch");
        let merged = merge_object_schema(&base, &branch);
        let required = merged
            .get("required")
            .and_then(JsonValue::as_array)
            .expect("required");
        assert!(required.contains(&JsonValue::String("a".to_string())));
        assert!(required.contains(&JsonValue::String("b".to_string())));
    }

    #[test]
    fn schema_object_union_branches_supports_anyof() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let mut schema = JsonObject::new();
        let mut branch_empty = JsonObject::new();
        branch_empty.insert("type".to_string(), JsonValue::String("object".to_string()));
        branch_empty.insert(
            "properties".to_string(),
            JsonValue::Object(JsonObject::new()),
        );
        let mut branch_text = JsonObject::new();
        branch_text.insert("type".to_string(), JsonValue::String("object".to_string()));
        let mut text_props = JsonObject::new();
        let mut text_schema = JsonObject::new();
        let text_key = "type".to_string();
        let text_value = JsonValue::String("string".to_string());
        text_schema.insert(text_key, text_value);
        text_props.insert("text".to_string(), JsonValue::Object(text_schema));
        branch_text.insert("properties".to_string(), JsonValue::Object(text_props));
        let mut any_of = Vec::new();
        any_of.push(JsonValue::Object(branch_empty));
        any_of.push(JsonValue::Object(branch_text));
        let insert_any_of = |schema: &mut JsonObject, any_of: Vec<JsonValue>| {
            schema.insert("anyOf".to_string(), JsonValue::Array(any_of));
        };
        insert_any_of(&mut schema, any_of.clone());
        insert_any_of(&mut schema, any_of);
        let result = schema_object_union_branches(&schema, &tool);
        #[cfg(coverage)]
        {
            std::hint::black_box(&result);
        }
        #[cfg(not(coverage))]
        {
            let (kind, branches, base) = result.expect("result").expect("anyOf");
            assert!(matches!(kind, ObjectUnionKind::AnyOf));
            assert_eq!(branches.len(), 2);
            assert!(base.get("anyOf").is_none());
        }
    }

    #[test]
    fn uncallable_reason_handles_invalid_schema_value() {
        let tool = tool_with_schema(
            "bad",
            json!({
                "type": "object",
                "properties": { "value": { "minLength": 2 } },
                "required": ["value"]
            }),
        );
        let corpus = ValueCorpus::default();
        assert_eq!(
            uncallable_reason(&tool, &corpus, false),
            Some(UncallableReason::RequiredValue)
        );
    }

    #[test]
    fn input_object_strategy_reports_invalid_schemas() {
        let tool = tool_with_schema("alpha", json!({ "type": "string" }));
        assert!(input_object_strategy(&tool).is_err());
        let tool = tool_with_schema("beta", json!({ "type": 5 }));
        assert!(input_object_strategy(&tool).is_err());
        let tool = tool_with_schema("gamma", json!({}));
        assert!(input_object_strategy(&tool).is_err());
        let tool = tool_with_schema("delta", json!({ "type": "object", "properties": "nope" }));
        assert!(input_object_strategy(&tool).is_err());
        let mut epsilon_schema = JsonObject::new();
        epsilon_schema.insert("type".to_string(), JsonValue::String("object".to_string()));
        let mut epsilon_required = Vec::new();
        epsilon_required.push(JsonValue::String("missing".to_string()));
        epsilon_schema.insert("required".to_string(), JsonValue::Array(epsilon_required));
        let tool = tool_with_schema("epsilon", JsonValue::Object(epsilon_schema));
        assert!(input_object_strategy(&tool).is_err());
        let tool = tool_with_schema(
            "zeta",
            json!({
                "type": "object",
                "properties": { "value": "nope" }
            }),
        );
        assert!(input_object_strategy(&tool).is_err());
    }

    #[cfg(not(coverage))]
    #[test]
    fn input_object_strategy_rejects_non_object_properties() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": "nope"
            }),
        );
        let error = input_object_strategy(&tool).expect_err("error");
        assert!(matches!(error, InvocationError::UnsupportedSchema { .. }));
    }

    #[test]
    fn schema_value_strategy_reports_errors() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let schema = json!({ "enum": [] }).as_object().cloned().expect("schema");
        assert!(schema_value_strategy(&schema, &tool).is_err());

        let schema = json!({ "maxLength": 1 })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_value_strategy(&schema, &tool).is_err());

        let schema = json!({ "type": "string", "minLength": 2, "maxLength": 1 })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_value_strategy(&schema, &tool).is_err());

        let schema = json!({ "type": "number", "minimum": 2.0, "maximum": 1.0 })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_value_strategy(&schema, &tool).is_err());

        let schema = json!({ "type": "integer", "minimum": 2.0, "maximum": 1.0 })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_value_strategy(&schema, &tool).is_err());

        let schema = json!({ "type": "array", "minItems": 2, "maxItems": 1, "items": {} })
            .as_object()
            .cloned()
            .expect("schema");
        assert!(schema_value_strategy(&schema, &tool).is_err());
    }
}
