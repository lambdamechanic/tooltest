## MODIFIED Requirements
### Requirement: MCP Tool Listing and Schema Validation
The system SHALL validate `tools/list` payloads against the official MCP schema for protocol version 2025-11-25 before generating invocations.

#### Scenario: Tool schema validation failure
- **WHEN** a `tools/list` payload does not conform to the MCP schema
- **THEN** the run fails with an error outcome

#### Scenario: Validation uses MCP schema constraints only
- **WHEN** tool schemas include a `$schema` value permitted by the MCP schema
- **THEN** validation succeeds without imposing stricter constraints

#### Scenario: Schema version configuration does not block validation
- **WHEN** a caller supplies a schema version configuration
- **THEN** validation still follows the official MCP schema for protocol version 2025-11-25

### Requirement: MCP Call Tool Request Validation
The system SHALL validate tools/call request parameters against the MCP schema before parsing them.

#### Scenario: Invalid call tool request payload
- **WHEN** a tools/call request payload does not conform to the MCP schema
- **THEN** parsing fails with a schema validation error
