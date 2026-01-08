//! MCP sequence runner with default and declarative assertions.

mod assertions;
mod coverage;
mod execution;
mod pre_run;
mod prepare;
mod result;
mod schema;
mod state_machine;
mod transport;

#[cfg(test)]
#[path = "../../tests/internal/runner_unit_tests.rs"]
mod tests;

pub use execution::{run_with_session, RunnerOptions};
pub use transport::{run_http, run_stdio};
