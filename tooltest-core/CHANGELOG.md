# Changelog

## [Unreleased]

### Added

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

### Changed

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

### Fixed

- Harden JSON Schema union branch generation (`anyOf`/`oneOf`) and improve generator diagnostics.
- Improve trace/coverage reporting and uncallable trace capture.

### Internal

- Type-safety hardening (deny `unwrap`/`expect` in non-test builds), expanded tests, and CI improvements.

## [0.3.0](https://github.com/lambdamechanic/tooltest/compare/tooltest-core-v0.2.0...tooltest-core-v0.3.0) - 2026-01-14

### Other

- Merge pull request #54 from lambdamechanic/tooltest-suz

## [0.2.0](https://github.com/lambdamechanic/tooltest/compare/tooltest-core-v0.1.0...tooltest-core-v0.2.0) - 2026-01-14

### Other

- Merge pull request #52 from lambdamechanic/tooltest-6wn

## [0.1.0](https://github.com/lambdamechanic/tooltest/releases/tag/tooltest-core-v0.1.0) - 2026-01-05

### Other

- Merge pull request #38 from lambdamechanic/readme-tooltest-skill
- Initial tooltest-core release.
