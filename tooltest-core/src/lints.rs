use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;
use serde_json::json;

use crate::coverage_filter::is_coverage_tool_eligible;
use crate::output_schema::compile_output_schema;
pub use crate::schema_dialect::DEFAULT_JSON_SCHEMA_DIALECT;
use crate::schema_dialect::{
    normalize_schema_id, DRAFT4_HTTP, DRAFT4_HTTPS, DRAFT6_HTTP, DRAFT6_HTTPS, DRAFT7_HTTP,
    DRAFT7_HTTPS,
};
use crate::{
    CoverageRule, LintDefinition, LintFinding, LintLevel, LintPhase, LintRule, ListLintContext,
    ResponseLintContext, RunLintContext,
};

fn schema_id_from_object(schema: &crate::JsonObject) -> Option<&str> {
    schema.get("$schema").and_then(|value| value.as_str())
}

/// Lint: checks the raw tools/list count against a configured maximum.
#[derive(Clone, Debug)]
pub struct MaxToolsLint {
    definition: LintDefinition,
    max_tools: usize,
}

impl MaxToolsLint {
    pub fn new(definition: LintDefinition, max_tools: usize) -> Self {
        Self {
            definition,
            max_tools,
        }
    }
}

impl LintRule for MaxToolsLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_list(&self, context: &ListLintContext<'_>) -> Vec<LintFinding> {
        if context.raw_tool_count <= self.max_tools {
            return Vec::new();
        }
        let message = format!(
            "tools/list returned {} tools (max {})",
            context.raw_tool_count, self.max_tools
        );
        vec![LintFinding::new(message).with_details(json!({
            "count": context.raw_tool_count,
            "max": self.max_tools,
        }))]
    }
}

/// Lint: enforces a minimum MCP protocol version based on initialize response.
#[derive(Clone, Debug)]
pub struct McpSchemaMinVersionLint {
    definition: LintDefinition,
    min_version: NaiveDate,
    min_version_raw: String,
}

impl McpSchemaMinVersionLint {
    pub fn new(definition: LintDefinition, min_version: impl Into<String>) -> Result<Self, String> {
        let min_version_raw = min_version.into();
        let min_version =
            NaiveDate::parse_from_str(&min_version_raw, "%Y-%m-%d").map_err(|_| {
                format!("invalid minimum protocol version '{min_version_raw}'; expected YYYY-MM-DD")
            })?;
        Ok(Self {
            definition,
            min_version,
            min_version_raw,
        })
    }
}

impl LintRule for McpSchemaMinVersionLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_list(&self, context: &ListLintContext<'_>) -> Vec<LintFinding> {
        let Some(protocol_version) = context.protocol_version else {
            return vec![LintFinding::new("server did not report protocolVersion")];
        };
        let trimmed = protocol_version.trim();
        if trimmed.is_empty() {
            return vec![LintFinding::new("server reported an empty protocolVersion")];
        }
        let parsed = match NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
            Ok(parsed) => parsed,
            Err(_) => {
                return vec![LintFinding::new(format!(
                    "server protocolVersion '{trimmed}' is not YYYY-MM-DD"
                ))
                .with_details(json!({
                    "reported": trimmed,
                    "expected_format": "YYYY-MM-DD",
                }))];
            }
        };
        if parsed < self.min_version {
            return vec![LintFinding::new(format!(
                "server protocolVersion '{trimmed}' is below minimum {}",
                self.min_version_raw
            ))
            .with_details(json!({
                "reported": trimmed,
                "minimum": self.min_version_raw,
            }))];
        }
        Vec::new()
    }
}

/// Lint: validates tool schema dialects against an allowlist.
#[derive(Clone, Debug)]
pub struct JsonSchemaDialectCompatLint {
    definition: LintDefinition,
    allowlist: HashSet<String>,
}

impl JsonSchemaDialectCompatLint {
    pub fn new(definition: LintDefinition, allowlist: impl IntoIterator<Item = String>) -> Self {
        let allowlist = allowlist
            .into_iter()
            .map(|entry| normalize_schema_id(&entry).to_string())
            .collect();
        Self {
            definition,
            allowlist,
        }
    }

    fn check_schema(
        &self,
        tool_name: &str,
        schema: &crate::JsonObject,
        label: &str,
    ) -> Option<LintFinding> {
        let declared = schema_id_from_object(schema)
            .map(normalize_schema_id)
            .unwrap_or_else(|| normalize_schema_id(DEFAULT_JSON_SCHEMA_DIALECT));
        if self.allowlist.contains(declared) {
            return None;
        }
        Some(
            LintFinding::new(format!(
                "tool '{}' {label} schema declares unsupported dialect '{declared}'",
                tool_name
            ))
            .with_details(json!({
                "tool": tool_name,
                "schema": declared,
                "schema_label": label,
            })),
        )
    }
}

impl LintRule for JsonSchemaDialectCompatLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_list(&self, context: &ListLintContext<'_>) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for tool in context.tools {
            if let Some(finding) =
                self.check_schema(tool.name.as_ref(), tool.input_schema.as_ref(), "input")
            {
                findings.push(finding);
            }
            if let Some(schema) = tool.output_schema.as_ref() {
                if let Some(finding) =
                    self.check_schema(tool.name.as_ref(), schema.as_ref(), "output")
                {
                    findings.push(finding);
                }
            }
        }
        findings
    }
}

/// Lint: reports `$defs` usage with legacy JSON Schema drafts.
#[derive(Clone, Debug)]
pub struct JsonSchemaKeywordCompatLint {
    definition: LintDefinition,
}

impl JsonSchemaKeywordCompatLint {
    pub fn new(definition: LintDefinition) -> Self {
        Self { definition }
    }

    fn is_legacy_schema_id(schema_id: &str) -> bool {
        matches!(
            schema_id,
            DRAFT7_HTTP | DRAFT7_HTTPS | DRAFT6_HTTP | DRAFT6_HTTPS | DRAFT4_HTTP | DRAFT4_HTTPS
        )
    }

    fn check_schema(
        &self,
        tool_name: &str,
        schema: &crate::JsonObject,
        label: &str,
    ) -> Option<LintFinding> {
        if !schema.contains_key("$defs") {
            return None;
        }
        let declared = schema_id_from_object(schema)
            .map(normalize_schema_id)
            .unwrap_or(DEFAULT_JSON_SCHEMA_DIALECT);
        if !Self::is_legacy_schema_id(declared) {
            return None;
        }
        Some(
            LintFinding::new(format!(
                "tool '{}' {label} schema declares {declared} but uses '$defs'; draft-07 and earlier use 'definitions'",
                tool_name
            ))
            .with_details(json!({
                "tool": tool_name,
                "schema": declared,
                "schema_label": label,
                "keyword": "$defs",
            })),
        )
    }
}

impl LintRule for JsonSchemaKeywordCompatLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_list(&self, context: &ListLintContext<'_>) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for tool in context.tools {
            if let Some(finding) =
                self.check_schema(tool.name.as_ref(), tool.input_schema.as_ref(), "input")
            {
                findings.push(finding);
            }
            if let Some(schema) = tool.output_schema.as_ref() {
                if let Some(finding) =
                    self.check_schema(tool.name.as_ref(), schema.as_ref(), "output")
                {
                    findings.push(finding);
                }
            }
        }
        findings
    }
}

/// Lint: reports output schemas that fail to compile.
#[derive(Clone, Debug)]
pub struct OutputSchemaCompileLint {
    definition: LintDefinition,
}

impl OutputSchemaCompileLint {
    pub fn new(definition: LintDefinition) -> Self {
        Self { definition }
    }
}

impl LintRule for OutputSchemaCompileLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_list(&self, context: &ListLintContext<'_>) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for tool in context.tools {
            let Some(schema) = tool.output_schema.as_ref() else {
                continue;
            };
            if let Err(error) = compile_output_schema(schema.as_ref()) {
                findings.push(
                    LintFinding::new(format!(
                        "tool '{}' output schema failed to compile",
                        tool.name.as_ref()
                    ))
                    .with_details(json!({
                        "tool": tool.name.as_ref(),
                        "error": error,
                    })),
                );
            }
        }
        findings
    }
}

/// Lint: enforces a maximum structuredContent byte size per response.
#[derive(Clone, Debug)]
pub struct MaxStructuredContentBytesLint {
    definition: LintDefinition,
    max_bytes: usize,
    serialize: fn(&serde_json::Value) -> Result<Vec<u8>, serde_json::Error>,
}

impl MaxStructuredContentBytesLint {
    pub fn new(definition: LintDefinition, max_bytes: usize) -> Self {
        Self {
            definition,
            max_bytes,
            serialize: serde_json::to_vec
                as fn(&serde_json::Value) -> Result<Vec<u8>, serde_json::Error>,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_serializer(
        definition: LintDefinition,
        max_bytes: usize,
        serialize: fn(&serde_json::Value) -> Result<Vec<u8>, serde_json::Error>,
    ) -> Self {
        Self {
            definition,
            max_bytes,
            serialize,
        }
    }
}

impl LintRule for MaxStructuredContentBytesLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_response(&self, context: &ResponseLintContext<'_>) -> Vec<LintFinding> {
        let Some(value) = context.response.structured_content.as_ref() else {
            return Vec::new();
        };
        let size = match (self.serialize)(value) {
            Ok(encoded) => encoded.len(),
            Err(error) => {
                return vec![LintFinding::new(format!(
                    "tool '{}' structuredContent failed to serialize",
                    context.tool.name.as_ref()
                ))
                .with_details(json!({
                    "tool": context.tool.name.as_ref(),
                    "error": error.to_string(),
                }))];
            }
        };
        if size <= self.max_bytes {
            return Vec::new();
        }
        vec![LintFinding::new(format!(
            "tool '{}' structuredContent is {size} bytes (max {})",
            context.tool.name.as_ref(),
            self.max_bytes
        ))
        .with_details(json!({
            "tool": context.tool.name.as_ref(),
            "size": size,
            "max": self.max_bytes,
        }))]
    }
}

/// Lint: reports missing structuredContent when an output schema exists.
#[derive(Clone, Debug)]
pub struct MissingStructuredContentLint {
    definition: LintDefinition,
}

impl MissingStructuredContentLint {
    pub fn new(definition: LintDefinition) -> Self {
        Self { definition }
    }
}

impl LintRule for MissingStructuredContentLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_response(&self, context: &ResponseLintContext<'_>) -> Vec<LintFinding> {
        if context.tool.output_schema.is_some() && context.response.structured_content.is_none() {
            return vec![LintFinding::new(format!(
                "tool '{}' returned no structuredContent for output schema",
                context.tool.name.as_ref()
            ))
            .with_details(json!({
                "tool": context.tool.name.as_ref(),
            }))];
        }
        Vec::new()
    }
}

/// Lint: enforces coverage validation rules at run completion.
#[derive(Clone, Debug)]
pub struct CoverageLint {
    definition: LintDefinition,
    rules: Vec<CoverageRule>,
}

impl CoverageLint {
    pub fn new(definition: LintDefinition, rules: Vec<CoverageRule>) -> Result<Self, String> {
        if definition.phase != LintPhase::Run {
            return Err("coverage lint must be configured for run phase".to_string());
        }
        for rule in &rules {
            if let CoverageRule::PercentCalled { min_percent } = rule {
                if !min_percent.is_finite() || *min_percent < 0.0 || *min_percent > 100.0 {
                    return Err(format!(
                        "coverage lint min_percent out of range: {min_percent}"
                    ));
                }
            }
        }
        Ok(Self { definition, rules })
    }

    pub fn rules(&self) -> &[CoverageRule] {
        &self.rules
    }

    fn effective_rules(&self) -> Vec<CoverageRule> {
        if self.rules.is_empty() {
            vec![CoverageRule::PercentCalled { min_percent: 100.0 }]
        } else {
            self.rules.clone()
        }
    }
}

impl LintRule for CoverageLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_run(&self, context: &RunLintContext<'_>) -> Vec<LintFinding> {
        let Some(coverage) = context.coverage else {
            return Vec::new();
        };
        let eligible: Vec<String> = coverage
            .counts
            .keys()
            .filter(|name| {
                is_coverage_tool_eligible(
                    name.as_str(),
                    context.coverage_allowlist,
                    context.coverage_blocklist,
                )
            })
            .cloned()
            .collect();

        let uncallable: HashSet<&str> = coverage
            .warnings
            .iter()
            .map(|warning| warning.tool.as_str())
            .collect();
        let callable: Vec<String> = eligible
            .into_iter()
            .filter(|name| !uncallable.contains(name.as_str()))
            .collect();

        let counts: HashMap<&str, u64> = coverage
            .counts
            .iter()
            .map(|(name, count)| (name.as_str(), *count))
            .collect();

        let mut findings = Vec::new();
        for rule in self.effective_rules() {
            match rule {
                CoverageRule::MinCallsPerTool { min } => {
                    let mut violations = Vec::new();
                    for tool in &callable {
                        let count = *counts.get(tool.as_str()).unwrap_or(&0);
                        if count < min {
                            violations.push(json!({ "tool": tool, "count": count }));
                        }
                    }
                    if !violations.is_empty() {
                        findings.push(
                            LintFinding::new("coverage rule min_calls_per_tool failed")
                                .with_code("coverage_validation_failed")
                                .with_details(json!({
                                    "rule": "min_calls_per_tool",
                                    "min": min,
                                    "violations": violations,
                                })),
                        );
                    }
                }
                CoverageRule::NoUncalledTools => {
                    let uncalled: Vec<String> = callable
                        .iter()
                        .filter(|tool| *counts.get(tool.as_str()).unwrap_or(&0) == 0)
                        .cloned()
                        .collect();
                    if !uncalled.is_empty() {
                        findings.push(
                            LintFinding::new("coverage rule no_uncalled_tools failed")
                                .with_code("coverage_validation_failed")
                                .with_details(json!({
                                    "rule": "no_uncalled_tools",
                                    "uncalled": uncalled,
                                })),
                        );
                    }
                }
                CoverageRule::PercentCalled { min_percent } => {
                    let denom = callable.len() as f64;
                    if denom == 0.0 {
                        continue;
                    }
                    let called = callable
                        .iter()
                        .filter(|tool| *counts.get(tool.as_str()).unwrap_or(&0) > 0)
                        .count() as f64;
                    let percent = (called / denom) * 100.0;
                    if percent < min_percent {
                        findings.push(
                            LintFinding::new("coverage rule percent_called failed")
                                .with_code("coverage_validation_failed")
                                .with_details(json!({
                                    "rule": "percent_called",
                                    "min_percent": min_percent,
                                    "percent": percent,
                                    "called": called,
                                    "eligible": denom,
                                })),
                        );
                    }
                }
            }
        }

        findings
    }
}

/// Lint: fails the run when any failure occurred.
#[derive(Clone, Debug)]
pub struct NoCrashLint {
    definition: LintDefinition,
}

impl NoCrashLint {
    pub fn new(definition: LintDefinition) -> Result<Self, String> {
        if definition.phase != LintPhase::Run {
            return Err("no_crash lint must be configured for run phase".to_string());
        }
        if definition.level != LintLevel::Error {
            return Err("no_crash lint must be configured at error level".to_string());
        }
        Ok(Self { definition })
    }
}

impl LintRule for NoCrashLint {
    fn definition(&self) -> &LintDefinition {
        &self.definition
    }

    fn check_run(&self, context: &RunLintContext<'_>) -> Vec<LintFinding> {
        if matches!(context.outcome, crate::RunOutcome::Failure(_)) {
            return vec![LintFinding::new("run failed")];
        }
        Vec::new()
    }
}
