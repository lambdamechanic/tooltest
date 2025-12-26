//! Proptest-based tool invocation generation driven by MCP schemas.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashSet;
use std::fmt;

use nonempty::NonEmpty;
use proptest::prelude::*;
use regex::Regex;
use rmcp::model::{JsonObject, Tool};
use serde_json::{Number, Value as JsonValue};

use crate::{StateMachineConfig, ToolInvocation, ToolPredicate};

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

pub(crate) fn state_machine_sequence_strategy(
    tools: &[Tool],
    predicate: Option<&ToolPredicate>,
    config: &StateMachineConfig,
    len_range: std::ops::RangeInclusive<usize>,
) -> Result<BoxedStrategy<Vec<ToolInvocation>>, InvocationError> {
    validate_state_machine_tools(tools)?;
    let mut corpus = ValueCorpus::default();
    corpus.seed_numbers(config.seed_numbers.clone());
    corpus.seed_strings(config.seed_strings.clone());

    let mut strategies = Vec::new();
    for tool in tools {
        if let Some(strategy) = invocation_from_corpus(tool, predicate, &corpus) {
            strategies.push(strategy);
        }
    }

    if strategies.is_empty() {
        return Ok(Just(Vec::new()).boxed());
    }

    let invocation = proptest::strategy::Union::new(strategies).boxed();
    Ok(proptest::collection::vec(invocation, len_range).boxed())
}

/// Builds a strategy that yields tool invocations with inputs that violate exactly one schema rule.
pub(crate) fn invalid_invocation_strategy(
    tools: &[Tool],
    predicate: Option<&ToolPredicate>,
) -> Result<BoxedStrategy<ToolInvocation>, InvocationError> {
    let mut strategies = Vec::new();
    for tool in tools {
        let tool_name = tool.name.clone();
        let predicate_name = tool.name.to_string();
        let arguments = invalid_input_object_strategy(tool)?;
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
) -> Option<BoxedStrategy<ToolInvocation>> {
    let schema = tool.input_schema.as_ref();
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

    let required_keys = schema
        .get("required")
        .and_then(JsonValue::as_array)
        .map(|required| {
            required
                .iter()
                .filter_map(JsonValue::as_str)
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();

    let mut property_strategies = Vec::with_capacity(properties.len());
    for (name, schema_value) in properties {
        let schema_object = schema_value.as_object()?;
        let required = required_keys.contains(name.as_str());
        match property_strategy_from_corpus(schema_object, required, corpus, tool) {
            PropertyOutcome::Include(strategy) => {
                property_strategies.push((name.clone(), strategy));
            }
            PropertyOutcome::Omit => {}
            PropertyOutcome::MissingRequired => return None,
        }
    }

    let mut strategy: BoxedStrategy<Vec<(String, JsonValue)>> = Just(Vec::new()).boxed();
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
    let predicate = predicate.cloned();
    Some(
        strategy
            .prop_filter_map("predicate rejected tool input", move |entries| {
                let mut map = JsonObject::new();
                for (name, value) in entries {
                    map.insert(name, value);
                }
                let allowed = if let Some(predicate) = &predicate {
                    let input = JsonValue::Object(map.clone());
                    let predicate_name = tool_name.to_string();
                    predicate(&predicate_name, &input)
                } else {
                    true
                };
                if !allowed {
                    return None;
                }
                Some(ToolInvocation {
                    name: tool_name.clone(),
                    arguments: Some(map),
                })
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
                    PropertyOutcome::MissingRequired
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
                    PropertyOutcome::MissingRequired
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
                    PropertyOutcome::MissingRequired
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

pub(crate) fn uncallable_reason(tool: &Tool, corpus: &ValueCorpus) -> Option<UncallableReason> {
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
                (!has_match).then_some(UncallableReason::String)
            }
            Some(SchemaType::Integer) => {
                let has_match = corpus
                    .integers()
                    .iter()
                    .map(|value| JsonValue::Number(Number::from(*value)))
                    .any(|value| schema_violations(schema_object, &value).is_empty());
                (!has_match).then_some(UncallableReason::Integer)
            }
            Some(SchemaType::Number) => {
                let has_match = corpus
                    .numbers()
                    .iter()
                    .map(|value| JsonValue::Number(value.clone()))
                    .any(|value| schema_violations(schema_object, &value).is_empty());
                (!has_match).then_some(UncallableReason::Number)
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

fn input_object_strategy(tool: &Tool) -> Result<BoxedStrategy<JsonObject>, InvocationError> {
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
                reason: "inputSchema required must reference known properties".to_string(),
            });
        }
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
        property_strategies.push((name.clone(), strategy));
    }

    let mut strategy: BoxedStrategy<Vec<(String, JsonValue)>> = Just(Vec::new()).boxed();
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
            map
        })
        .boxed())
}

fn invalid_input_object_strategy(
    tool: &Tool,
) -> Result<BoxedStrategy<JsonObject>, InvocationError> {
    let valid_inputs = input_object_strategy(tool)?;

    let schema = tool.input_schema.clone();
    let schema_for_filter = schema.clone();
    Ok(valid_inputs
        .prop_filter_map("must have a viable invalid mutation", move |args| {
            let value = JsonValue::Object(args.clone());
            let constraints = applicable_constraints(schema_for_filter.as_ref(), &value);
            let viable = constraints
                .into_iter()
                .filter_map(|constraint| {
                    mutate_to_violate_constraint(&value, &constraint)
                        .map(|mutated| (constraint, mutated))
                })
                .collect::<Vec<_>>();
            NonEmpty::from_vec(viable)
        })
        .prop_flat_map(move |viable| {
            let schema = schema.clone();
            let viable: Vec<_> = viable.into();
            proptest::sample::select(viable)
                .prop_filter_map(
                    "must violate exactly one schema constraint",
                    move |(constraint, mutated)| {
                        let violations = schema_violations(schema.as_ref(), &mutated);
                        let is_valid = violations.len() == 1 && violations[0] == constraint;
                        is_valid
                            .then_some(mutated)
                            .and_then(|mutated| match mutated {
                                JsonValue::Object(map) => Some(map),
                                _ => None,
                            })
                    },
                )
                .boxed()
        })
        .boxed())
}

fn schema_value_strategy(
    schema: &JsonObject,
    tool: &Tool,
) -> Result<BoxedStrategy<JsonValue>, InvocationError> {
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

    let schema_type = schema
        .get("type")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| InvocationError::UnsupportedSchema {
            tool: tool.name.to_string(),
            reason: "schema type must be a string".to_string(),
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

pub(crate) fn applicable_constraints(schema: &JsonObject, value: &JsonValue) -> Vec<Constraint> {
    let mut constraints = Vec::new();
    let mut path = Vec::new();
    collect_constraints(schema, value, &mut path, &mut constraints);
    constraints
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

fn collect_constraints(
    schema: &JsonObject,
    value: &JsonValue,
    path: &mut Vec<PathSegment>,
    constraints: &mut Vec<Constraint>,
) {
    if let Some(const_value) = schema.get("const") {
        constraints.push(Constraint {
            path: nonempty_path(path),
            kind: ConstraintKind::Const(const_value.clone()),
        });
    }

    if let Some(JsonValue::Array(values)) = schema.get("enum") {
        constraints.push(Constraint {
            path: nonempty_path(path),
            kind: ConstraintKind::Enum(values.clone()),
        });
    }

    if let Some(JsonValue::String(schema_type)) = schema.get("type") {
        constraints.push(Constraint {
            path: nonempty_path(path),
            kind: ConstraintKind::Type(schema_type.clone()),
        });
    }

    if let JsonValue::String(_) = value {
        if let Some(JsonValue::String(schema_type)) = schema.get("type") {
            if schema_type != "string" {
                return;
            }
        }
        if let Some(min_length) = schema.get("minLength").and_then(JsonValue::as_u64) {
            constraints.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::MinLength(min_length as usize),
            });
        }
        if let Some(max_length) = schema.get("maxLength").and_then(JsonValue::as_u64) {
            constraints.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::MaxLength(max_length as usize),
            });
        }
        if let Some(JsonValue::String(pattern)) = schema.get("pattern") {
            if !pattern.is_empty() {
                constraints.push(Constraint {
                    path: nonempty_path(path),
                    kind: ConstraintKind::Pattern(pattern.clone()),
                });
            }
        }
    }

    if let JsonValue::Number(_) = value {
        if let Some(minimum) = schema.get("minimum").and_then(JsonValue::as_f64) {
            constraints.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::Minimum(minimum),
            });
        }
        if let Some(maximum) = schema.get("maximum").and_then(JsonValue::as_f64) {
            constraints.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::Maximum(maximum),
            });
        }
    }

    if let JsonValue::Array(items) = value {
        if let Some(min_items) = schema.get("minItems").and_then(JsonValue::as_u64) {
            constraints.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::MinItems(min_items as usize),
            });
        }
        if let Some(max_items) = schema.get("maxItems").and_then(JsonValue::as_u64) {
            constraints.push(Constraint {
                path: nonempty_path(path),
                kind: ConstraintKind::MaxItems(max_items as usize),
            });
        }
        if let Some(JsonValue::Object(item_schema)) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                path.push(PathSegment::Index(index));
                collect_constraints(item_schema, item, path, constraints);
                path.pop();
            }
        }
    }

    if let JsonValue::Object(map) = value {
        if let Some(JsonValue::Array(required)) = schema.get("required") {
            for required_key in required.iter().filter_map(JsonValue::as_str) {
                if map.contains_key(required_key) {
                    constraints.push(Constraint {
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
                        collect_constraints(property_schema, property_value, path, constraints);
                        path.pop();
                    }
                }
            }
        }
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
                    collect_violations(item_schema, item, path, violations);
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
                            collect_violations(property_schema, property_value, path, violations);
                            path.pop();
                        }
                    }
                }
            }
        }
        _ => {}
    }
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

pub(crate) fn mutate_to_violate_constraint(
    value: &JsonValue,
    constraint: &Constraint,
) -> Option<JsonValue> {
    let mut mutated = value.clone();
    match &constraint.kind {
        ConstraintKind::Const(const_value) => {
            let replacement = different_value(const_value);
            set_value_at_path(&mut mutated, &constraint.path, replacement)?;
        }
        ConstraintKind::Enum(values) => {
            let replacement = value_not_in_enum(values);
            set_value_at_path(&mut mutated, &constraint.path, replacement)?;
        }
        ConstraintKind::Type(schema_type) => {
            let replacement = mismatched_type_value(schema_type);
            set_value_at_path(&mut mutated, &constraint.path, replacement)?;
        }
        ConstraintKind::MinLength(min_length) => {
            if *min_length == 0 {
                return None;
            }
            let replacement = JsonValue::String("".to_string());
            set_value_at_path(&mut mutated, &constraint.path, replacement)?;
        }
        ConstraintKind::MaxLength(max_length) => {
            let replacement = JsonValue::String("a".repeat(max_length + 1));
            set_value_at_path(&mut mutated, &constraint.path, replacement)?;
        }
        ConstraintKind::Pattern(pattern) => {
            let replacement = non_matching_string(pattern)?;
            set_value_at_path(
                &mut mutated,
                &constraint.path,
                JsonValue::String(replacement),
            )?;
        }
        ConstraintKind::Minimum(minimum) => {
            let replacement = JsonValue::from(minimum - 1.0);
            set_value_at_path(&mut mutated, &constraint.path, replacement)?;
        }
        ConstraintKind::Maximum(maximum) => {
            let replacement = JsonValue::from(maximum + 1.0);
            set_value_at_path(&mut mutated, &constraint.path, replacement)?;
        }
        ConstraintKind::MinItems(min_items) => {
            if *min_items == 0 {
                return None;
            }
            let array = get_value_at_path_mut(&mut mutated, &constraint.path)?.as_array_mut()?;
            let target_len = min_items.saturating_sub(1);
            array.truncate(target_len);
        }
        ConstraintKind::MaxItems(max_items) => {
            let array = get_value_at_path_mut(&mut mutated, &constraint.path)?.as_array_mut()?;
            let next_len = max_items.saturating_add(1);
            while array.len() < next_len {
                let value = array
                    .first()
                    .cloned()
                    .unwrap_or_else(|| JsonValue::String("extra".to_string()));
                array.push(value);
            }
        }
        ConstraintKind::Required(required_key) => {
            let object = get_value_at_path_mut(&mut mutated, &constraint.path)?.as_object_mut()?;
            object.remove(required_key);
        }
    }
    Some(mutated)
}

fn value_matches_type(value: &JsonValue, schema_type: &str) -> bool {
    match (schema_type, value) {
        ("string", JsonValue::String(_)) => true,
        ("number", JsonValue::Number(_)) => true,
        ("integer", JsonValue::Number(number)) => number.is_i64() || number.is_u64(),
        ("boolean", JsonValue::Bool(_)) => true,
        ("array", JsonValue::Array(_)) => true,
        ("object", JsonValue::Object(_)) => true,
        _ => false,
    }
}

fn different_value(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::String(text) => JsonValue::String(format!("{text}x")),
        JsonValue::Number(number) => {
            let value = number.as_f64().unwrap_or(0.0);
            JsonValue::from(value + 1.0)
        }
        JsonValue::Bool(flag) => JsonValue::Bool(!flag),
        JsonValue::Null => JsonValue::Bool(true),
        JsonValue::Array(items) => {
            let mut next = items.clone();
            next.push(JsonValue::Null);
            JsonValue::Array(next)
        }
        JsonValue::Object(map) => {
            let mut next = map.clone();
            next.insert("extra".to_string(), JsonValue::Bool(true));
            JsonValue::Object(next)
        }
    }
}

fn value_not_in_enum(values: &[JsonValue]) -> JsonValue {
    let primary = JsonValue::String("not_in_enum".to_string());
    if !values.contains(&primary) {
        return primary;
    }
    let mut suffix = 0;
    loop {
        let candidate = JsonValue::String(format!("not_in_enum_{suffix}"));
        if !values.contains(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn mismatched_type_value(schema_type: &str) -> JsonValue {
    match schema_type {
        "string" => JsonValue::from(42),
        "number" | "integer" => JsonValue::String("not-a-number".to_string()),
        "boolean" => JsonValue::String("not-bool".to_string()),
        "array" => JsonValue::String("not-array".to_string()),
        "object" => JsonValue::String("not-object".to_string()),
        _ => JsonValue::Null,
    }
}

fn non_matching_string(pattern: &str) -> Option<String> {
    let regex = Regex::new(pattern).ok()?;
    let candidates = ["", "x", "invalid", "!!!", "123"];
    for candidate in candidates {
        if !regex.is_match(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn set_value_at_path(
    value: &mut JsonValue,
    path: &NonEmpty<PathSegment>,
    replacement: JsonValue,
) -> Option<()> {
    let target = get_value_at_path_mut(value, path)?;
    *target = replacement;
    Some(())
}

fn get_value_at_path_mut<'a>(
    value: &'a mut JsonValue,
    path: &NonEmpty<PathSegment>,
) -> Option<&'a mut JsonValue> {
    let mut current = value;
    let segments = std::iter::once(&path.head).chain(path.tail.iter());
    for segment in segments {
        match segment {
            PathSegment::Root => {}
            PathSegment::Key(key) => {
                current = current.as_object_mut()?.get_mut(key)?;
            }
            PathSegment::Index(index) => {
                current = current.as_array_mut()?.get_mut(*index)?;
            }
        }
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::Tool;
    use serde_json::json;
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
    fn invocation_from_corpus_handles_missing_properties() {
        let tool = tool_with_schema("alpha", json!({ "type": "object", "properties": "nope" }));
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus(&tool, None, &corpus).is_none());

        let tool = tool_with_schema("beta", json!({ "type": "object", "required": ["missing"] }));
        assert!(invocation_from_corpus(&tool, None, &corpus).is_none());

        let tool = tool_with_schema("gamma", json!({ "type": "object" }));
        let strategy = invocation_from_corpus(&tool, None, &corpus).expect("strategy");
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
        assert!(invocation_from_corpus(&tool, None, &corpus).is_none());
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
        assert!(invocation_from_corpus(&tool, None, &corpus).is_none());
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
        let strategy = invocation_from_corpus(&tool, None, &corpus).expect("strategy");
        let invocation = sample(strategy);
        assert_eq!(invocation.arguments, Some(JsonObject::new()));
    }

    #[test]
    fn invocation_from_corpus_rejects_missing_required_values() {
        let tool = tool_with_schema(
            "echo",
            json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
        );
        let corpus = ValueCorpus::default();
        assert!(invocation_from_corpus(&tool, None, &corpus).is_none());
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
        let strategy = invocation_from_corpus(&tool, Some(&predicate), &corpus).expect("strategy");
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
        let missing = property_strategy_from_corpus(&schema, true, &corpus, &tool);
        assert!(outcome_is_missing_required(&missing));
        assert!(!outcome_is_omit(&missing));

        let omitted = property_strategy_from_corpus(&schema, false, &corpus, &tool);
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
        let integer_required = property_strategy_from_corpus(&integer_schema, true, &corpus, &tool);
        assert!(outcome_is_missing_required(&integer_required));
        assert!(!outcome_is_omit(&integer_required));

        let integer_optional =
            property_strategy_from_corpus(&integer_schema, false, &corpus, &tool);
        assert!(!outcome_is_missing_required(&integer_optional));
        assert!(outcome_is_omit(&integer_optional));

        let number_required = property_strategy_from_corpus(&number_schema, true, &corpus, &tool);
        assert!(outcome_is_missing_required(&number_required));
        assert!(!outcome_is_omit(&number_required));

        let number_optional = property_strategy_from_corpus(&number_schema, false, &corpus, &tool);
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
        let outcome = property_strategy_from_corpus(&string_schema, true, &corpus, &tool);
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
        let outcome = property_strategy_from_corpus(&number_schema, true, &corpus, &tool);
        assert!(outcome_is_include(&outcome));
        assert!(!outcome_is_missing_required(&outcome));
    }

    #[test]
    fn property_strategy_from_corpus_handles_invalid_schema() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let corpus = ValueCorpus::default();
        let schema = json!({ "enum": [] }).as_object().cloned().expect("schema");
        let outcome = property_strategy_from_corpus(&schema, true, &corpus, &tool);
        assert!(outcome_is_missing_required(&outcome));
        assert!(!outcome_is_include(&outcome));
    }

    #[test]
    fn property_strategy_from_corpus_handles_schema_value_strategy_results() {
        let tool = tool_with_schema("echo", json!({ "type": "object" }));
        let corpus = ValueCorpus::default();
        let const_schema = json!({ "const": true })
            .as_object()
            .cloned()
            .expect("schema");
        let outcome = property_strategy_from_corpus(&const_schema, true, &corpus, &tool);
        assert!(outcome_is_include(&outcome));
        assert!(!outcome_is_missing_required(&outcome));

        let bad_schema = json!({ "minLength": 2 })
            .as_object()
            .cloned()
            .expect("schema");
        let outcome = property_strategy_from_corpus(&bad_schema, true, &corpus, &tool);
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
            uncallable_reason(&string_tool, &corpus),
            Some(UncallableReason::String)
        );
        assert_eq!(
            uncallable_reason(&integer_tool, &corpus),
            Some(UncallableReason::Integer)
        );
        assert_eq!(
            uncallable_reason(&number_tool, &corpus),
            Some(UncallableReason::Number)
        );
        assert_eq!(
            uncallable_reason(&required_tool, &corpus),
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
        assert_eq!(uncallable_reason(&tool, &corpus), None);
    }

    #[test]
    fn uncallable_reason_handles_non_object_properties() {
        let tool = tool_with_schema("bad", json!({ "type": "object", "properties": "nope" }));
        let corpus = ValueCorpus::default();
        assert_eq!(
            uncallable_reason(&tool, &corpus),
            Some(UncallableReason::RequiredValue)
        );
    }

    #[test]
    fn uncallable_reason_handles_empty_required_without_properties() {
        let tool = tool_with_schema("empty", json!({ "type": "object", "required": [] }));
        let corpus = ValueCorpus::default();
        assert_eq!(uncallable_reason(&tool, &corpus), None);
    }

    #[test]
    fn uncallable_reason_handles_required_without_properties() {
        let tool = tool_with_schema(
            "missing",
            json!({ "type": "object", "required": ["value"] }),
        );
        let corpus = ValueCorpus::default();
        assert_eq!(
            uncallable_reason(&tool, &corpus),
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
            uncallable_reason(&string_tool, &corpus),
            Some(UncallableReason::String)
        );
        assert_eq!(
            uncallable_reason(&number_tool, &corpus),
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
            uncallable_reason(&tool, &corpus),
            Some(UncallableReason::RequiredValue)
        );
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
            uncallable_reason(&tool, &corpus),
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
        let tool = tool_with_schema(
            "epsilon",
            json!({ "type": "object", "required": ["missing"] }),
        );
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
