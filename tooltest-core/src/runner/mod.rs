//! MCP sequence runner with default and declarative assertions.
#![deny(clippy::expect_used, clippy::unwrap_used)]

mod assertions;
mod coverage;
mod execution;
mod linting;
mod pre_run;
mod prepare;
mod result;
mod schema;
mod state_machine;
mod transport;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "../../tests/internal/runner_unit_tests.rs"]
mod tests;

pub use execution::{run_with_session, RunnerOptions};
pub use transport::{run_http, run_stdio};
