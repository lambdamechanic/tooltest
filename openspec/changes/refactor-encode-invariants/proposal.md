# Change: Refactor to Encode Invariants by Construction

## Why
`tooltest-core` currently exposes several public configuration types that can be constructed in invalid states (e.g. `cases = 0`, `uncallable_limit = 0`, empty stdio command, invalid HTTP URL, inverted sequence length range). These invalid states are only reliably rejected by CLI/MCP validation helpers or surface later as brittle runtime assumptions.

This change makes those states unrepresentable (or rejected at construction/deserialization), and removes a few runner/generator assumptions that required `.expect(...)`.

## What Changes
- **Config invariants**: tighten public configuration types so invalid states are rejected at construction and deserialization.
  - `cases >= 1`
  - `uncallable_limit >= 1`
  - sequence length range `min >= 1` and `min <= max`
  - stdio command is non-empty
  - HTTP URL parses and has a host
- **Runner safety**: add a typed `SessionDriver` tool-call API returning `CallToolResult` and refactor the state-machine runner to construct `TraceEntry` explicitly instead of relying on `TraceEntry` shape invariants.
- **Generator safety**: use `nonempty::NonEmpty` for oneOf/anyOf/type-union branch lists so “empty but assumed non-empty” states are eliminated and unreachable `expect(...)` calls can be removed.
- **Lint enforcement**: deny `clippy::unwrap_used` / `clippy::expect_used` in the runner module to prevent regressions.

Breaking changes are explicitly acceptable for this change when they improve safety/misuse-resistance.

## Impact
- Affected specs: `mcp-sequence-runner`
- Affected code (expected): `tooltest-core/src/lib.rs`, `tooltest-core/src/input.rs`, `tooltest-core/src/session.rs`, `tooltest-core/src/runner/*`, `tooltest-core/src/generator/mod.rs`, `README.md`, `CHANGELOG.md`

