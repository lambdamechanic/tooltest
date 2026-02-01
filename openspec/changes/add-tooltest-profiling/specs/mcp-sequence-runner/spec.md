## ADDED Requirements
### Requirement: Optional profiling output
The system SHALL provide a `tooltest-prof` wrapper that runs the installed `tooltest` binary under the `flamegraph` command. When `TOOLTEST_PROFILE_PATH` is set to a non-empty path, the wrapper SHALL write the generated flamegraph SVG to that path. Profiling MUST be available for both CLI and MCP entry points via argument passthrough. When `TOOLTEST_PROFILE_TOOLTEST_PATH` is set to an executable path, the wrapper SHALL use that tooltest binary instead of resolving `tooltest` from `PATH`.

#### Scenario: Profiling enabled writes output
- **WHEN** `TOOLTEST_PROFILE_PATH` is set to a writable path
- **THEN** the run completes and a flamegraph SVG is written to that path

#### Scenario: Default output path
- **WHEN** `TOOLTEST_PROFILE_PATH` is unset or empty
- **THEN** the wrapper runs tooltest with flamegraph's default output path

#### Scenario: Profiling path is invalid
- **WHEN** `TOOLTEST_PROFILE_PATH` is set to a path that cannot be created or written
- **THEN** the wrapper fails with an error before executing sequences

#### Scenario: CLI entry point profiling
- **WHEN** a CLI run executes via `tooltest-prof` with `TOOLTEST_PROFILE_PATH` set
- **THEN** the CLI run produces a flamegraph SVG at the configured path

#### Scenario: MCP entry point profiling
- **WHEN** an MCP tool invocation executes via `tooltest-prof` with `TOOLTEST_PROFILE_PATH` set
- **THEN** the MCP run produces a flamegraph SVG at the configured path

#### Scenario: Override tooltest binary path
- **WHEN** `TOOLTEST_PROFILE_TOOLTEST_PATH` is set to an executable path
- **THEN** the wrapper runs that tooltest binary under flamegraph
