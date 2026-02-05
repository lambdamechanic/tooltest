use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{CallToolResult, CorpusReport, CoverageReport, Tool, ToolInvocation};
/// Severity levels for lint findings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LintLevel {
    Error,
    Warning,
    Disabled,
}

impl LintLevel {
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

/// Phases in which lints are evaluated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LintPhase {
    List,
    Response,
    Run,
}

/// Definition of a lint instance.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LintDefinition {
    pub id: String,
    pub phase: LintPhase,
    pub level: LintLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<JsonValue>,
}

impl LintDefinition {
    pub fn new(id: impl Into<String>, phase: LintPhase, level: LintLevel) -> Self {
        Self {
            id: id.into(),
            phase,
            level,
            params: None,
        }
    }

    pub fn with_params(mut self, params: JsonValue) -> Self {
        self.params = Some(params);
        self
    }
}

/// A lint finding emitted during evaluation.
#[derive(Clone, Debug)]
pub struct LintFinding {
    pub message: String,
    pub details: Option<JsonValue>,
}

impl LintFinding {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: JsonValue) -> Self {
        self.details = Some(details);
        self
    }
}

/// Context for list-phase lint evaluation.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ListLintContext<'a> {
    pub tools: &'a [Tool],
}

/// Context for response-phase lint evaluation.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ResponseLintContext<'a> {
    pub tool: &'a Tool,
    pub invocation: &'a ToolInvocation,
    pub response: &'a CallToolResult,
}

/// Context for run-phase lint evaluation.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RunLintContext<'a> {
    pub coverage: Option<&'a CoverageReport>,
    pub corpus: Option<&'a CorpusReport>,
}

/// Trait for implementing lint checks.
pub trait LintRule: Send + Sync {
    fn definition(&self) -> &LintDefinition;

    fn check_list(&self, _context: &ListLintContext<'_>) -> Vec<LintFinding> {
        Vec::new()
    }

    fn check_response(&self, _context: &ResponseLintContext<'_>) -> Vec<LintFinding> {
        Vec::new()
    }

    fn check_run(&self, _context: &RunLintContext<'_>) -> Vec<LintFinding> {
        Vec::new()
    }
}

/// Collection of configured lint rules.
#[derive(Clone, Default)]
pub struct LintSuite {
    rules: Vec<Arc<dyn LintRule>>,
}

impl LintSuite {
    pub fn new(rules: Vec<Arc<dyn LintRule>>) -> Self {
        Self { rules }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub(crate) fn rules(&self) -> &[Arc<dyn LintRule>] {
        &self.rules
    }
}

pub(crate) struct LintPhases {
    pub(crate) list: Vec<Arc<dyn LintRule>>,
    pub(crate) response: Vec<Arc<dyn LintRule>>,
    pub(crate) run: Vec<Arc<dyn LintRule>>,
}

impl LintPhases {
    pub(crate) fn from_suite(suite: &LintSuite) -> Self {
        let mut list = Vec::new();
        let mut response = Vec::new();
        let mut run = Vec::new();
        for rule in suite.rules() {
            if rule.definition().level.is_disabled() {
                continue;
            }
            match rule.definition().phase {
                LintPhase::List => list.push(Arc::clone(rule)),
                LintPhase::Response => response.push(Arc::clone(rule)),
                LintPhase::Run => run.push(Arc::clone(rule)),
            }
        }
        Self {
            list,
            response,
            run,
        }
    }
}
