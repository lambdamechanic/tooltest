## Context
Tooltest already performs multiple checks (schema validation, output validation, coverage validation) but these are embedded in the runner and not configurable. We need a lint framework that can encode these checks, set their severity, and separate list-only checks from per-response and run-aggregate checks.

## Goals / Non-Goals
- Goals:
  - Provide a lint model with explicit phases and configurable severity.
  - Load lint configuration from TOML files only (no new CLI flags).
  - Preserve current behavior by default using a shipped lint config (e.g., `no_crash` + `coverage`).
  - Make it easy to add future lints (pagination, annotation semantics, cancellation, etc.).
- Non-Goals:
  - Implement every lint in the long-term backlog now.
  - Change the existing MCP run/validation semantics unless dictated by lint levels.

## Decisions
- Configuration discovery:
  - Search upward from the current working directory to the git root for `tooltest.toml`.
  - If found, use it and ignore `~/.config/tooltest.toml` (replace, no merge).
  - Otherwise, use `~/.config/tooltest.toml` when present.
  - If no file exists, use a built-in default `tooltest.toml` embedded in the library.
- Configuration schema:
  - Top-level `version` (defaults to `1` when omitted).
  - `[[lints]]` array with required `id` and `level`.
  - Optional `[lints.params]` table for lint-specific parameters.
  - Unknown lint IDs, invalid parameter types, or invalid `level` values are configuration errors.
  - Duplicate lint IDs are configuration errors.
- Lint model:
  - Each lint has an id, phase, severity (`error|warning|disabled`), and parameters.
  - Lint evaluation returns zero or more findings that map to `RunWarning` or `RunFailure` depending on severity.
  - Some lints have fixed severity (e.g., `no_crash` is error-only); configuring a different level is a config error.
- Evaluation semantics:
  - Collect all findings within a phase and aggregate warnings across phases.
  - List-phase error findings stop the run before any tools/call.
  - Response-phase error findings stop the run after the offending response.
  - Run-phase lints evaluate after execution completes.
  - Lint warnings include structured codes and lint ids for machine parsing.
- Phases:
  - `list` lints run after tools/list is parsed and validated, before any tool calls.
  - `response` lints run per tools/call response (structuredContent size, etc.).
  - `run` lints run after the run finishes with access to aggregate data (coverage, corpus, trace).
- Default behavior:
  - The built-in `tooltest.toml` encodes current behavior.
  - A `no_crash` lint at error level preserves current failure behavior.
  - A `coverage` lint uses coverage rules from lint config and can be warning or error.
  - The default JSON Schema dialect allowlist includes 2020-12, 2019-09, draft-07, draft-06, and draft-04.
  - The MCP protocol version lint is warning-level by default.
  - A missing-structuredContent lint is warning-level by default to match current behavior.
  - Default config includes all supported lints; non-defaults are disabled with sensible params and commented for easy activation.
- StructuredContent size:
  - Size is computed as UTF-8 byte length of JSON serialization of `structuredContent`.

- Default config visibility:
  - The embedded `tooltest.toml` includes explanatory comments.
  - The CLI exposes `tooltest config default` to emit the default config so users can generate their own file.

## Alternatives Considered
- Add CLI flags for each lint: rejected to keep configuration centralized and avoid flag explosion.
- Merge repo and home configs: rejected to prevent surprising overrides; repo config should fully define lint behavior for a project.

## Risks / Trade-offs
- Introducing lint phases requires refactoring the runner to expose list/response/run hooks.
- Mapping existing failures into a `no_crash` lint must preserve failure codes/details to avoid regressions.
- Removing coverage rules from state-machine config requires updates to input parsing and docs.
- MCP protocol version format is specified as a string in the spec; lint comparison assumes YYYY-MM-DD.
- The missing-structuredContent lint should be response-phase and uses output-schema presence as its trigger.
- The legacy `tooltest_core::validation::validate_tools` workflow can be removed; schema-based invocation generation remains for lenient-sourcing.

## Migration Plan
- Add lint framework behind default config so existing runs behave the same.
- Add `tooltest.toml` in repo with default lint settings.
- Update docs to describe configuration and lint phases.

## Open Questions
- None.
