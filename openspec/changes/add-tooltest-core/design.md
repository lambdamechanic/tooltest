## Context
Tooltest is a new Rust-based MCP testing tool with no existing code. It must execute valid MCP sessions against stdio or HTTP endpoints, generating tool invocations from MCP schema data at runtime, enforcing MCP validity, and exposing a reusable core for Node/Python wrappers.

## Goals / Non-Goals
- Goals:
  - Provide a core Rust library that drives MCP sessions and generates valid tool invocation sequences.
  - Support stdio and HTTP MCP transports with a common session interface.
  - Provide a stable FFI boundary for Node (napi) and Python (pyo3) packages to consume.
- Non-Goals:
  - Designing the Node/Python wrapper APIs in this change.
  - Implementing UI, reporting, or advanced fuzzing controls beyond the initial generator.

## Decisions
- Decision: Use a Rust workspace with a core library crate and a dedicated FFI crate.
  - Rationale: Keeps the core pure-Rust while allowing bindings to target a small, stable ABI.
- Decision: Model MCP sessions as a stateful driver that enforces initialization before any generated calls.
  - Rationale: Ensures MCP validity regardless of generator output.
- Decision: Generate tool calls via a property-based generator constrained by MCP tool schemas at runtime, pinning to schema version 2025-11-25 (JSON Schema draft 2020-12) by default while allowing a configured version to be selected.
  - Rationale: Keeps validation truthful to supported versions while leaving room to add versions later.
- Decision: Use default proptest assertions that validate response schemas and transport-level correctness, with optional user-supplied declarative assertions on responses or sequences for FFI compatibility.
  - Rationale: Ensures baseline safety while allowing custom validation.
- Decision: Abstract transports behind a minimal trait with stdio and HTTP implementations, including optional configurable HTTP auth token support.
  - Rationale: Common session logic with pluggable transport.
- Decision: Use the `rmcp` SDK for JSON-RPC/MCP protocol request and error types in the core runner.
  - Rationale: Aligns the core with the canonical protocol implementation and reduces drift.
- Decision: Use `rmcp` client/session and transport APIs instead of maintaining a custom session driver.
  - Rationale: Leverages the official SDK for MCP session flow and transport framing.
- Decision: Expose napi and pyo3 bindings via a small FFI crate.
  - Rationale: Aligns with target ecosystems while keeping core logic in Rust.

## Risks / Trade-offs
- FFI design may need iteration to satisfy both Node (napi) and Python (pyo3) ecosystems.
- Schema-to-generator fidelity depends on MCP schema specifics (tool input/output constraints).

## Migration Plan
- Greenfield: no migration required. Introduce core and FFI packages in a new workspace.

## Open Questions
- What initialization parameters should be configurable (capabilities, client info), and how are they provided?
