## ADDED Requirements
### Requirement: MCP Session Initialization
The system SHALL perform an MCP initialization call before any generated tool invocation is sent to an endpoint.

#### Scenario: Initialization precedes tool calls
- **WHEN** a run is started
- **THEN** the initialization call is sent before any tool invocation

### Requirement: Transport Support
The system SHALL support MCP sessions over stdio and HTTP endpoints.

#### Scenario: Stdio transport selected
- **WHEN** a stdio command is provided
- **THEN** the session uses stdio for MCP request/response exchange

#### Scenario: HTTP transport selected
- **WHEN** an HTTP MCP endpoint is provided
- **THEN** the session uses HTTP for MCP request/response exchange

### Requirement: rmcp Session Driver
The system SHALL use the `rmcp` SDK session/client APIs to drive MCP initialization and tool calls instead of maintaining a custom session driver.

#### Scenario: rmcp session handles initialization
- **WHEN** a run is started
- **THEN** the MCP initialization handshake is dispatched via rmcp session/client APIs

#### Scenario: rmcp session handles tool calls
- **WHEN** a tool invocation is generated
- **THEN** the MCP call is executed through rmcp session/client APIs

### Requirement: rmcp Transport Usage
The system SHALL use `rmcp` transport implementations for stdio and HTTP exchanges.

#### Scenario: rmcp stdio transport selected
- **WHEN** a stdio command is provided
- **THEN** the session uses rmcp stdio transport primitives for request/response exchange

#### Scenario: rmcp HTTP transport selected
- **WHEN** an HTTP MCP endpoint is provided
- **THEN** the session uses rmcp HTTP transport primitives for request/response exchange

### Requirement: HTTP Authorization Header
The system SHALL accept an optional configurable HTTP auth header for MCP endpoints.

#### Scenario: Auth header applied to HTTP requests
- **WHEN** an HTTP auth header name and value are configured
- **THEN** each HTTP request includes that header

### Requirement: Schema-Based Invocation Generation
The system SHALL generate a sequence of tool invocations that conform to MCP tool schemas retrieved at runtime from the MCP endpoint.

#### Scenario: Generated calls conform to schema
- **WHEN** MCP tool schemas are available at runtime
- **THEN** each generated invocation validates against its schema before dispatch

### Requirement: MCP Tool Schema Definitions
The system SHALL interpret MCP tool schemas according to the MCP protocol schema version 2025-11-25 (JSON Schema draft 2020-12) by default, and MAY support additional versions when explicitly configured, including the following exact structures for 2025-11-25:

- `Tool` objects require `name` and `inputSchema`, and MAY include `description`, `annotations`, `execution`, `icons`, `title`, and `outputSchema`.
- `inputSchema` and `outputSchema` are JSON Schema objects with required `type: "object"`, optional `$schema: string`, optional `properties: object`, and optional `required: string[]`.
- `outputSchema` defaults to JSON Schema draft 2020-12 when `$schema` is absent and is restricted to a root `type: "object"`.
- `tools/list` returns a `ListToolsResult` with required `tools: Tool[]` and optional `nextCursor`.

#### Scenario: Tool schema parsing
- **WHEN** tools are fetched from `tools/list`
- **THEN** `Tool` objects and their `inputSchema`/`outputSchema` are parsed using the MCP schema definitions above

#### Scenario: Unsupported schema version
- **WHEN** the server advertises a newer MCP schema version than the configured set
- **THEN** the run fails with a schema version mismatch error

### Requirement: Tool Eligibility Filtering
The system SHALL apply a user-supplied predicate callback over tool names and candidate inputs to determine which tools are eligible for generated calls.

#### Scenario: Predicate filters eligible tools
- **WHEN** the predicate excludes a tool name
- **THEN** no generated invocation targets that tool

#### Scenario: Predicate allows a subset
- **WHEN** the predicate allows only a subset of tools
- **THEN** generated invocations target only that subset

#### Scenario: Predicate inspects inputs
- **WHEN** the predicate evaluates a tool name and generated input object
- **THEN** the tool is eligible only if the predicate returns true

### Requirement: Default Runtime Assertions
The system SHALL apply default assertions that validate response output schemas and transport-level correctness (no crashes or invalid HTTP status codes).

#### Scenario: Output schema validation
- **WHEN** a tool response is received
- **THEN** `structuredContent`, when present, is validated against the tool `outputSchema`

#### Scenario: Transport correctness
- **WHEN** an HTTP response is received
- **THEN** the status code is 200

### Requirement: Custom Assertion Hooks
The system SHALL allow optional user-supplied assertions over responses or entire sequences.

#### Scenario: Response assertion
- **WHEN** a response-level assertion is provided
- **THEN** it is evaluated against each response with access to tool name, input, and output

#### Scenario: Sequence assertion
- **WHEN** a sequence-level assertion is provided
- **THEN** it is evaluated after the run completes

### Requirement: MCP Call Shapes
The system SHALL form tool calls and parse results according to the MCP protocol schema version 2025-11-25:

- `tools/call` requests are JSON-RPC 2.0 objects with `method: "tools/call"` and `params` containing required `name: string`, optional `arguments: object`, optional `_meta.progressToken`, and optional `task`.
- `tools/call` results are `CallToolResult` objects with required `content: ContentBlock[]`, optional `structuredContent: object`, optional `isError: boolean`, and optional `_meta`.

#### Scenario: CallToolRequest formation
- **WHEN** a tool invocation is dispatched
- **THEN** the request matches the MCP `CallToolRequest` schema

#### Scenario: CallToolResult parsing
- **WHEN** a tool invocation response is received
- **THEN** the response is parsed as an MCP `CallToolResult`

### Requirement: rmcp Protocol Types
The system SHALL use the `rmcp` SDK protocol types for JSON-RPC requests and error payloads in the core session driver.

#### Scenario: rmcp request shaping
- **WHEN** the session driver dispatches MCP requests
- **THEN** request payloads are constructed from `rmcp` JSON-RPC request types

#### Scenario: rmcp error parsing
- **WHEN** a JSON-RPC error response is received
- **THEN** the error payload is parsed into `rmcp` error data structures

### Requirement: MCP Validity Enforcement
The system SHALL ensure that all emitted requests form a valid MCP session sequence.

#### Scenario: Valid ordering enforced
- **WHEN** generated invocations are produced
- **THEN** the session enforces MCP-valid ordering and required handshakes

### Requirement: Rustprop Minimization and Trace
The system SHALL return a minimized failing sequence from proptest alongside the full execution trace of calls.

#### Scenario: Minimized failure
- **WHEN** proptest finds a counterexample
- **THEN** the result includes the minimized sequence that reproduces the issue

#### Scenario: Full trace returned
- **WHEN** a run completes
- **THEN** the result includes the full trace of generated calls and responses
