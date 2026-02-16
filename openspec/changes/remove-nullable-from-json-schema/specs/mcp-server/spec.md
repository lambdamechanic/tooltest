## ADDED Requirements

### Requirement: JSON Schema 2020-12 Compliance
The MCP server's tool schemas SHALL conform to JSON Schema 2020-12 without using non-standard keywords like `nullable`.

#### Scenario: No nullable keyword in inputSchema
- **WHEN** a client requests tools/list from the MCP server
- **THEN** the inputSchema does not contain the `nullable` keyword

#### Scenario: No nullable keyword in outputSchema
- **WHEN** a client requests tools/list from the MCP server
- **THEN** the outputSchema does not contain the `nullable` keyword

#### Scenario: Strict JSON Schema validators accept schemas
- **WHEN** a strict JSON Schema 2020-12 validator parses the tool schemas
- **THEN** no validation errors are reported

### Requirement: Null Type Representation
Nullable types in MCP tool schemas SHALL be represented using JSON Schema 2020-12 idioms such as `anyOf` with `{"const": null}` or `{"type": ["<type>", "null"]}`.

#### Scenario: Nullable optional fields use anyOf
- **WHEN** a tool schema includes a nullable optional field
- **THEN** the field uses `anyOf: [{"$ref": "..."}, {"const": null}]` or `type: ["<type>", "null"]` without the `nullable` keyword

### Requirement: Non-Standard Keyword Lint
The system SHALL provide a list-phase lint that reports non-standard keywords (e.g., `nullable`) in schemas that declare JSON Schema 2020-12.

#### Scenario: Nullable keyword in 2020-12 schema reported
- **WHEN** a tool schema declares `$schema: https://json-schema.org/draft/2020-12/schema` and contains `nullable`
- **THEN** the lint emits a warning or failure based on its configured level

#### Scenario: Nullable keyword in legacy schema not reported
- **WHEN** a tool schema declares a legacy `$schema` (draft-07 or earlier) and contains `nullable`
- **THEN** the lint does not report a finding

#### Scenario: Dogfooding catches nullable before fix
- **WHEN** the lint is implemented and enabled in tooltest's own config
- **THEN** running tooltest against itself reports `nullable` findings in inputSchema and outputSchema

#### Scenario: Dogfooding passes after fix
- **WHEN** the `nullable` keywords are removed from inputSchema and outputSchema
- **THEN** running tooltest against itself reports no `nullable` findings

### Requirement: Upstream Compatibility
The tooltest project SHALL track and contribute fixes to rmcp for JSON Schema 2020-12 compliance.

#### Scenario: Upstream issue filed
- **WHEN** this change is implemented
- **THEN** an issue is filed on modelcontextprotocol/rust-sdk documenting the `nullable` incompatibility
