## Requirements
### Requirement: MCP Tool Listing and Schema Validation
The system SHALL list MCP tools from a configured session and validate them against the configured MCP schema version before generating invocations.

#### Scenario: Tool listing failure
- **WHEN** listing tools from the MCP session fails
- **THEN** the run fails with an error outcome

#### Scenario: Tool schema validation failure
- **WHEN** listed tools do not conform to the configured MCP schema
- **THEN** the run fails with an error outcome

### Requirement: Proptest-Based Invocation Generation
The system SHALL generate tool invocation sequences using proptest strategies derived from MCP tool schemas and a configurable sequence length range.

#### Scenario: Sequence length respects configuration
- **WHEN** a run is configured with a sequence length range
- **THEN** generated sequences contain a number of invocations within that range

#### Scenario: Tool predicate filters invocations
- **WHEN** a tool predicate is supplied
- **THEN** only tools accepted by the predicate are eligible for sequence generation

### Requirement: Run Entry Points
The system SHALL provide entry points to run sequences against stdio, HTTP, or pre-initialized MCP sessions.

#### Scenario: Stdio entry point
- **WHEN** the caller invokes the stdio entry point
- **THEN** the run connects via stdio and executes a generated sequence

#### Scenario: HTTP entry point
- **WHEN** the caller invokes the HTTP entry point
- **THEN** the run connects via HTTP and executes a generated sequence

#### Scenario: Session entry point
- **WHEN** the caller invokes the session entry point
- **THEN** the run uses the provided session to execute a generated sequence

### Requirement: Default Assertions
The system SHALL apply default assertions that fail the run when a tool response is an error or when structured output violates the declared output schema.

#### Scenario: Error responses fail the run
- **WHEN** a tool response indicates an error
- **THEN** the run fails with an error outcome

#### Scenario: Missing structured output fails the run
- **WHEN** a tool response omits structured output for a tool with an output schema
- **THEN** the run fails with an error outcome

#### Scenario: Structured output schema violations fail the run
- **WHEN** structured output does not conform to the declared output schema
- **THEN** the run fails with an error outcome

### Requirement: Assertion DSL
The system SHALL support response-scoped and sequence-scoped assertion rules that compare JSON Pointer selections against expected values.

#### Scenario: Response assertions evaluate per tool response
- **WHEN** response assertion rules are provided
- **THEN** each tool response is evaluated against matching response rules

#### Scenario: Sequence assertions evaluate after execution
- **WHEN** sequence assertion rules are provided
- **THEN** the full sequence payload is evaluated after the sequence completes

#### Scenario: Assertion pointer mismatch fails the run
- **WHEN** an assertion pointer does not match the expected value
- **THEN** the run fails with an error outcome

### Requirement: Run Results
The system SHALL return a run result containing the outcome, trace of invocations and responses, and a minimized failing sequence when proptest finds a failure.

#### Scenario: Successful run returns trace
- **WHEN** a run completes without assertion failures
- **THEN** the result includes a success outcome and the trace of invocations and responses

#### Scenario: Failing run returns minimized sequence
- **WHEN** a proptest case fails
- **THEN** the result includes a failure outcome and a minimized failing sequence
