//! MCP sequence runner with default and declarative assertions.

mod assertions;
mod coverage;
mod execution;
mod transport;

#[cfg(test)]
#[path = "../../tests/internal/runner_unit_tests.rs"]
mod tests;

pub use execution::{run_with_session, RunnerOptions};
pub use transport::{run_http, run_stdio};

#[cfg(test)]
use crate::generator::UncallableReason;
#[cfg(test)]
use assertions::{
    apply_default_assertions, apply_response_assertions, apply_sequence_assertions,
    attach_failure_reason, attach_response, evaluate_checks, AssertionPayloads,
};
#[cfg(test)]
use coverage::{map_uncallable_reason, CoverageTracker};
#[cfg(test)]
use execution::{
    build_output_validators, collect_schema_keyword_warnings, collect_schema_warnings,
    validate_tools, FailureContext,
};
#[cfg(test)]
use jsonschema::draft202012;
