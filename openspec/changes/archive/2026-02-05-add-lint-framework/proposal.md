# Change: Add configurable lint framework for MCP runs

## Why
Tooltest needs a structured way to encode MCP lint checks and configure their severity without adding new CLI flags. A lint framework enables incremental checks (schema compatibility, response size limits, tool-count caps, etc.) while keeping current behavior intact by default.

## What Changes
- Introduce a lint framework with per-lint `level` (error/warning/disabled) driven by a TOML config file.
- Define a TOML schema with `version` and `[[lints]]` entries (unknown lint IDs are configuration errors).
- Load lint config from `tooltest.toml` found by upward search to the git root, falling back to `~/.config/tooltest.toml` (repo config replaces home config). If neither exists, use a built-in default `tooltest.toml` embedded in the library.
- Expose the embedded default `tooltest.toml` via `tooltest config default` so users can generate their own config (with comments).
- Differentiate lint phases: list-tools (pre-run), response-scoped (per tools/call), and run-scoped (post-run aggregate).
- Collect all lint findings within each phase; list-phase error findings stop the run before any tool calls.
- Add initial lints: minimum MCP schema version, JSON Schema dialect compatibility (default allowlist includes older drafts), max tools count (raw list-tools), max structuredContent bytes per response, and missing structuredContent when an output schema exists.
- Migrate coverage rules into the coverage lint configuration (rather than state-machine config).
- Enforce fixed severity for `no_crash` (error-only).
- Default protocolVersion lint level is warning.
- Surface lint warnings in run results.
- Remove the legacy `validate_tools` workflow in favor of normal run flow plus linting.

## Impact
- Affected specs: `specs/mcp-sequence-runner/spec.md`
- Affected code: tooltest config loading, run preparation/execution, validation, and public summaries.
- Docs: document `tooltest.toml` lint configuration.
