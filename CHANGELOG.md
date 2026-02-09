# Changelog

## [Unreleased]

## [0.4.1](https://github.com/lambdamechanic/tooltest/compare/tooltest-v0.4.0...tooltest-v0.4.1) - 2026-02-09

### Other

- Merge pull request #124 from lambdamechanic/changelog-backfill-0.4.0

No unreleased changes yet.

## [0.4.0] - 2026-02-09

This release includes changes from both `tooltest` (CLI + MCP server wrapper) and `tooltest-core` (runner library).

### tooltest

#### Added

- `tooltest mcp`: run tooltest as an MCP server exposing:
  - the `tooltest` tool (shared `TooltestInput` input schema; `RunResult` structured output)
  - the `tooltest-fix-loop` prompt and `tooltest://guides/fix-loop` resource
- `tooltest config default`: print the built-in `tooltest.toml` lint configuration template.
- `--trace-all <PATH>`: emit per-case traces to a JSON lines file (includes a `trace_all_v1` header).
- Trace debugging flags: `--full-trace`, `--show-uncallable`, and `--uncallable-limit <N>`.
- `tooltest-prof` flamegraph wrapper plus `scripts/tooltest-prof-build` helper (optional install via
  `TOOLTEST_INSTALL_DEBUG_TOOLS=1` in `install.sh`).

#### Changed

- Tool results with `isError = true` are allowed by default and no longer fail runs; pass
  `--in-band-error-forbidden` to restore the previous behavior.
- Tools with output schemas now emit a configurable lint warning when `structuredContent` is missing (instead
  of failing the run). Output schema validation still fails the run when `structuredContent` is present but invalid.
- Default `--max-sequence-len` increased to 20.
- CLI now uses the shared `tooltest-core::TooltestInput` configuration type (also used by MCP mode), including
  lint config loading from `tooltest.toml`.

#### Fixed

- Prevent MCP stdio mode hangs in tests.
- Harden trace-all output file writing and improve uncallable trace formatting.

#### Internal

- Refactor CLI into modules; split MCP implementation into `tooltest/src/mcp/*`.

### tooltest-core

#### Added

- Lint framework with configurable phases (`list`, `response`, `run`) and severity (`error`, `warning`, `disabled`).
- `tooltest.toml` lint configuration loading (repo discovery up to git root, home fallback, then built-in defaults).
- Built-in lints:
  - `no_crash` (run-phase, error)
  - `mcp_schema_min_version` (list-phase, warning)
  - `missing_structured_content` (response-phase, warning)
  - `output_schema_compile` (list-phase, warning)
  - `json_schema_keyword_compat` (list-phase, warning)
  - optional/disabled by default: `coverage`, `max_tools`, `max_structured_content_bytes`, `json_schema_dialect_compat`
- Shared `TooltestInput` schema (serde + `JsonSchema`) for CLI and MCP tool usage.
- Trace streaming via `TraceSink`, plus compact/full trace support.
- Coverage report enhancements: track unsuccessful tool calls (`isError = true`) and record last N uncallable tool calls
  (inputs/outputs/errors + timestamps).
- Session I/O debug logging (target: `tooltest.io_logs`).

#### Changed

- **BREAKING:** `RunConfig`, `RunnerOptions`, `StdioConfig`, and `HttpConfig` now enforce invariants by construction.
  Struct-literal construction is no longer supported; use `new(...)` / builder methods.
- **BREAKING:** `StateMachineConfig.coverage_rules` was removed; coverage validation is now the `coverage` run lint.
- **BREAKING:** Tool results with `isError = true` are allowed by default. Set
  `RunConfig::with_in_band_error_forbidden(true)` to fail on in-band tool errors.
- **BREAKING:** Missing `structuredContent` for tools with output schemas is now a configurable lint warning (the
  `missing_structured_content` response lint) instead of a hard failure.
- **BREAKING:** Tool validation helpers were simplified: `validation::validate_tool` / `validate_tools` and related bulk
  validation types were removed. Use `list_tools_*` helpers plus lints instead.
- Lint warnings now use `RunWarningCode` values prefixed with `lint.`; legacy `missing_structured_content` warning helpers
  are deprecated.
- MCP schema validation now honors `SchemaConfig.version` and reports unsupported versions as errors.
- Coverage is suppressed when runs fail due to "positive errors" (for example, forbidden in-band tool errors or pre-run
  hook failures) to avoid misleading coverage output.

#### Fixed

- Harden JSON Schema union branch generation (`anyOf`/`oneOf`) and improve generator diagnostics.
- Improve trace/coverage reporting and uncallable trace capture.

#### Internal

- Type-safety hardening (deny `unwrap`/`expect` in non-test builds), expanded tests, and CI improvements.
