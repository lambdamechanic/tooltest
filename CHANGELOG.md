# Changelog

## [Unreleased]

## [0.4.1](https://github.com/lambdamechanic/tooltest/compare/tooltest-v0.4.0...tooltest-v0.4.1) - 2026-02-09

### Other

- Merge pull request #122 from lambdamechanic/mcp-fix-loop-prompt

### Added

- `tooltest.toml` lint configuration and a lint framework with phases (`list`, `response`, `run`).
- `tooltest mcp`: run tooltest as an MCP server exposing the `tooltest` tool plus fix-loop prompt/resource defaults.
- `tooltest-prof` flamegraph wrapper plus `scripts/tooltest-prof-build` helper (optional install via `TOOLTEST_INSTALL_DEBUG_TOOLS=1`).
- Per-case trace capture via `--trace-all`, plus `--full-trace` and uncallable-tool trace support (`--show-uncallable`).

### Changed

- Tool results with `isError = true` are allowed by default and no longer fail runs; use `--in-band-error-forbidden` to
  preserve the previous behavior. Static output schema validation still applies.
- Missing `structuredContent` for tools with output schemas is now reported as a configurable lint warning instead of a
  hard failure.
- Coverage validation defaults to 100% tool coverage when enabled with no explicit rules configured.
