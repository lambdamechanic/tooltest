## MODIFIED Requirements
### Requirement: Default Assertions
The system SHALL apply default assertions that fail the run on MCP protocol error responses, schema-invalid responses, and, when configured, on tool result error responses.

#### Scenario: MCP protocol error responses fail the run
- **WHEN** a tool response indicates an MCP protocol error response
- **THEN** the run fails with an error outcome

#### Scenario: Tool result error responses fail when forbidden
- **WHEN** a tool response contains a tool result with `isError = true` and in-band errors are forbidden
- **THEN** the run fails with an error outcome

#### Scenario: Tool result error responses do not fail when allowed
- **WHEN** a tool response contains a tool result with `isError = true` and in-band errors are allowed
- **THEN** the run continues without an error outcome
- **THEN** assertions still evaluate against the response
- **THEN** the error response is excluded from coverage counts

#### Scenario: Server crash fails the run
- **WHEN** the MCP server crashes during execution
- **THEN** the run fails with an error outcome

#### Scenario: MCP schema-invalid responses fail the run
- **WHEN** a tool response violates the configured MCP schema
- **THEN** the run fails with an error outcome

#### Scenario: Tool output schema violations fail the run
- **WHEN** structured output does not conform to the declared output schema
- **THEN** the run fails with an error outcome

#### Scenario: Missing structured output fails the run
- **WHEN** a tool response omits structured output for a tool with an output schema
- **THEN** the run fails with an error outcome
