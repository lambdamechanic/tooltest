//! Proptest-based tool invocation generation driven by MCP schemas.
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use jsonschema::draft202012;
use jsonschema::error::{TypeKind, ValidationError, ValidationErrorKind};
use nonempty::NonEmpty;
use proptest::prelude::*;
use regex::Regex;
use rmcp::model::{JsonObject, Tool};
use serde_json::Value as JsonValue;

use crate::{ToolInvocation, ToolPredicate};

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
            let value = JsonValue::Object(args);
            let constraints = applicable_constraints(schema_for_filter.as_ref(), &value);
            let viable = constraints
                .into_iter()
                .filter_map(|constraint| {
                    mutate_to_violate_constraint(&value, &constraint)
                        .map(|mutated| (constraint, mutated))
                })
                .collect::<Vec<_>>();
            (!viable.is_empty()).then_some(viable)
        })
        .prop_flat_map(move |viable| {
            let schema = schema.clone();
            proptest::sample::select(viable).prop_filter_map(
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
                let strategy = proptest::string::string_regex(&pattern).map_err(|err| {
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
    let schema_value = JsonValue::Object(schema.clone());
    let mut violations = match draft202012::new(&schema_value) {
        Ok(validator) => validator
            .iter_errors(value)
            .filter_map(|error| constraint_from_error(&error))
            .collect(),
        Err(error) => constraint_from_error(&error).into_iter().collect(),
    };

    collect_invalid_pattern_violations(schema, value, &mut Vec::new(), &mut violations);
    violations
}

fn constraint_from_error(error: &ValidationError<'_>) -> Option<Constraint> {
    let kind = match &error.kind {
        ValidationErrorKind::Constant { expected_value } => {
            ConstraintKind::Const(expected_value.clone())
        }
        ValidationErrorKind::Enum { options } => {
            ConstraintKind::Enum(options.as_array().cloned().unwrap_or_default())
        }
        ValidationErrorKind::Type { kind } => ConstraintKind::Type(type_kind_label(kind)),
        ValidationErrorKind::MinLength { limit } => ConstraintKind::MinLength(*limit as usize),
        ValidationErrorKind::MaxLength { limit } => ConstraintKind::MaxLength(*limit as usize),
        ValidationErrorKind::Pattern { pattern } => ConstraintKind::Pattern(pattern.clone()),
        ValidationErrorKind::Minimum { limit } => {
            ConstraintKind::Minimum(limit.as_f64().unwrap_or(0.0))
        }
        ValidationErrorKind::Maximum { limit } => {
            ConstraintKind::Maximum(limit.as_f64().unwrap_or(0.0))
        }
        ValidationErrorKind::MinItems { limit } => ConstraintKind::MinItems(*limit as usize),
        ValidationErrorKind::MaxItems { limit } => ConstraintKind::MaxItems(*limit as usize),
        ValidationErrorKind::Required { property } => {
            ConstraintKind::Required(property.as_str().unwrap_or_default().to_string())
        }
        _ => return None,
    };

    let path = path_from_pointer(error.instance_path.as_str());
    Some(Constraint {
        path: nonempty_path(&path),
        kind,
    })
}

fn type_kind_label(kind: &TypeKind) -> String {
    match kind {
        TypeKind::Single(value) => value.to_string(),
        TypeKind::Multiple(values) => (*values)
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("|"),
    }
}

fn collect_invalid_pattern_violations(
    schema: &JsonObject,
    value: &JsonValue,
    path: &mut Vec<PathSegment>,
    violations: &mut Vec<Constraint>,
) {
    if let JsonValue::String(_) = value {
        if let Some(JsonValue::String(schema_type)) = schema.get("type") {
            if schema_type != "string" {
                return;
            }
        }
        if let Some(JsonValue::String(pattern)) = schema.get("pattern") {
            if Regex::new(pattern).is_err() {
                violations.push(Constraint {
                    path: nonempty_path(path),
                    kind: ConstraintKind::Pattern(pattern.clone()),
                });
            }
        }
    }

    match value {
        JsonValue::Array(items) => {
            if let Some(JsonValue::Object(item_schema)) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    path.push(PathSegment::Index(index));
                    collect_invalid_pattern_violations(item_schema, item, path, violations);
                    path.pop();
                }
            }
        }
        JsonValue::Object(map) => {
            if let Some(JsonValue::Object(properties)) = schema.get("properties") {
                for (name, property_schema) in properties {
                    if let Some(property_value) = map.get(name) {
                        if let Some(property_schema) = property_schema.as_object() {
                            path.push(PathSegment::Key(name.clone()));
                            collect_invalid_pattern_violations(
                                property_schema,
                                property_value,
                                path,
                                violations,
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
