use std::sync::Arc;

use crate::lint::{
    LintDefinition, LintFinding, LintLevel, LintPhase, LintPhases, LintRule, ListLintContext,
    ResponseLintContext, RunLintContext,
};
use crate::{RunFailure, RunWarning, RunWarningCode};

#[derive(Clone, Debug)]
struct LintError {
    lint_id: String,
    message: String,
}

fn phase_label(phase: LintPhase) -> &'static str {
    match phase {
        LintPhase::List => "list",
        LintPhase::Response => "response",
        LintPhase::Run => "run",
    }
}

fn make_failure(phase: LintPhase, errors: &[LintError]) -> RunFailure {
    if let Some(error) = errors.first().filter(|_| errors.len() == 1) {
        RunFailure::new(format!(
            "lint {} failed during {} phase: {}",
            error.lint_id,
            phase_label(phase),
            error.message
        ))
    } else {
        let ids = errors
            .iter()
            .map(|error| error.lint_id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        RunFailure::new(format!(
            "lint errors during {} phase: {}",
            phase_label(phase),
            ids
        ))
    }
}

fn lint_warning(definition: &LintDefinition, finding: &LintFinding) -> RunWarning {
    RunWarning {
        code: RunWarningCode::Lint,
        message: format!("lint {}: {}", definition.id, finding.message),
        tool: None,
    }
}

fn lint_error(definition: &LintDefinition, finding: &LintFinding) -> LintError {
    LintError {
        lint_id: definition.id.clone(),
        message: finding.message.clone(),
    }
}

fn evaluate_phase<F>(
    phase: LintPhase,
    lints: &[Arc<dyn LintRule>],
    mut check: F,
    warnings: &mut Vec<RunWarning>,
) -> Option<RunFailure>
where
    F: FnMut(&dyn LintRule) -> Vec<LintFinding>,
{
    let mut errors = Vec::new();
    for lint in lints {
        let definition = lint.definition();
        let findings = check(lint.as_ref());
        if findings.is_empty() {
            continue;
        }
        match definition.level {
            LintLevel::Warning => {
                for finding in findings {
                    warnings.push(lint_warning(definition, &finding));
                }
            }
            LintLevel::Error => {
                for finding in findings {
                    errors.push(lint_error(definition, &finding));
                }
            }
            LintLevel::Disabled => {}
        }
    }
    if errors.is_empty() {
        None
    } else {
        Some(make_failure(phase, &errors))
    }
}

pub(super) fn lint_phases(lints: &crate::LintSuite) -> LintPhases {
    LintPhases::from_suite(lints)
}

pub(super) fn evaluate_list_phase(
    lints: &[Arc<dyn LintRule>],
    context: &ListLintContext<'_>,
    warnings: &mut Vec<RunWarning>,
) -> Option<RunFailure> {
    evaluate_phase(
        LintPhase::List,
        lints,
        |lint| lint.check_list(context),
        warnings,
    )
}

pub(super) fn evaluate_response_phase(
    lints: &[Arc<dyn LintRule>],
    context: &ResponseLintContext<'_>,
    warnings: &mut Vec<RunWarning>,
) -> Option<RunFailure> {
    evaluate_phase(
        LintPhase::Response,
        lints,
        |lint| lint.check_response(context),
        warnings,
    )
}

pub(super) fn evaluate_run_phase(
    lints: &[Arc<dyn LintRule>],
    context: &RunLintContext<'_>,
    warnings: &mut Vec<RunWarning>,
) -> Option<RunFailure> {
    evaluate_phase(
        LintPhase::Run,
        lints,
        |lint| lint.check_run(context),
        warnings,
    )
}
