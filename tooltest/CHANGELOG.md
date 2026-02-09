# Changelog

## [Unreleased]

### Added

- `tooltest mcp`: run tooltest as an MCP server exposing:
  - the `tooltest` tool (shared `TooltestInput` input schema; `RunResult` structured output)
  - the `tooltest-fix-loop` prompt and `tooltest://guides/fix-loop` resource
- `tooltest config default`: print the built-in `tooltest.toml` lint configuration template.
- `--trace-all <PATH>`: emit per-case traces to a JSON lines file (includes a `trace_all_v1` header).
- Trace debugging flags: `--full-trace`, `--show-uncallable`, and `--uncallable-limit <N>`.
- `tooltest-prof` flamegraph wrapper plus `scripts/tooltest-prof-build` helper (optional install via
  `TOOLTEST_INSTALL_DEBUG_TOOLS=1` in `install.sh`).

### Changed

- Tool results with `isError = true` are allowed by default and no longer fail runs; pass
  `--in-band-error-forbidden` to restore the previous behavior.
- Tools with output schemas now emit a configurable lint warning when `structuredContent` is missing (instead
  of failing the run). Output schema validation still fails the run when `structuredContent` is present but invalid.
- Default `--max-sequence-len` increased to 20.
- CLI now uses the shared `tooltest-core::TooltestInput` configuration type (also used by MCP mode), including
  lint config loading from `tooltest.toml`.

### Fixed

- Prevent MCP stdio mode hangs in tests.
- Harden trace-all output file writing and improve uncallable trace formatting.

### Internal

- Refactor CLI into modules; split MCP implementation into `tooltest/src/mcp/*`.

## [0.3.0](https://github.com/lambdamechanic/tooltest/compare/tooltest-v0.2.0...tooltest-v0.3.0) - 2026-01-14

### Other

- Merge pull request #54 from lambdamechanic/tooltest-suz

## [0.2.0](https://github.com/lambdamechanic/tooltest/compare/tooltest-v0.1.0...tooltest-v0.2.0) - 2026-01-14

### Other

- Merge pull request #52 from lambdamechanic/tooltest-6wn

## [0.1.0](https://github.com/lambdamechanic/tooltest/releases/tag/tooltest-v0.1.0) - 2026-01-05

### Other

- Merge pull request #38 from lambdamechanic/readme-tooltest-skill
- Initial tooltest release.
