## ADDED Requirements
### Requirement: Core Library API Surface
The system SHALL expose a Rust library API for configuring a run, selecting transport, and executing a generated MCP sequence with a tool predicate callback.

#### Scenario: Single-shot run through core API
- **WHEN** a caller provides endpoint configuration and a tool predicate
- **THEN** the core API runs the sequence and returns results

### Requirement: FFI Predicate Callback
The system SHALL allow Node (napi) and Python (pyo3) callers to supply a predicate callback that receives the tool name and input object.

#### Scenario: Predicate callback invoked
- **WHEN** the generator evaluates a candidate tool call
- **THEN** the predicate callback is invoked with the tool name and input object

### Requirement: Declarative Assertions for FFI
The system SHALL accept custom assertions as a JSON-based declarative DSL suitable for FFI transport rather than raw callbacks.

#### Scenario: Declarative assertions provided
- **WHEN** a caller supplies declarative assertion rules in JSON form
- **THEN** the core evaluates them over tool name, input, and output

#### Scenario: Client-side typed helpers
- **WHEN** Node or Python bindings expose helpers for assertions
- **THEN** they serialize to the JSON DSL accepted by the core

### Requirement: Stable FFI Boundary
The system SHALL provide a stable, minimal FFI boundary suitable for Node (napi) and Python (pyo3) wrappers.

#### Scenario: FFI entrypoints are available
- **WHEN** bindings are generated
- **THEN** the FFI exposes functions to start a run and retrieve results
