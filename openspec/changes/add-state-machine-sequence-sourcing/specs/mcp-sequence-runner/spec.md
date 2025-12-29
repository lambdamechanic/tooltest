## RENAMED Requirements
- FROM: `### Requirement: Proptest-Based Invocation Generation`
- TO: `### Requirement: State-Machine Invocation Generation`

## MODIFIED Requirements
### Requirement: State-Machine Invocation Generation
The system SHALL generate tool invocation sequences using the state-machine generator derived from MCP tool schemas and a configurable sequence length range. The system SHALL NOT expose a legacy generator mode for sequence generation.

#### Scenario: Sequence length respects configuration
- **WHEN** a run is configured with a sequence length range
- **THEN** generated sequences contain a number of invocations within that range

#### Scenario: Tool predicate filters invocations
- **WHEN** a tool predicate is supplied
- **THEN** only tools accepted by the predicate are eligible for sequence generation

#### Scenario: Legacy generator mode is unavailable
- **WHEN** a caller configures a run
- **THEN** the system uses the state-machine generator without exposing a legacy mode toggle

## ADDED Requirements
### Requirement: State-Machine Output Mining
The system SHALL mine structured tool outputs during state-machine runs and update the state corpus used for subsequent invocation generation.

#### Scenario: Tool output updates corpus
- **WHEN** a tool response returns structured output containing strings or numbers
- **THEN** subsequent state-machine steps may use those mined values as inputs

#### Scenario: Tool output keys are mined
- **WHEN** a tool response returns structured output containing object keys
- **THEN** the keys are mined into the state corpus as strings

#### Scenario: Nested outputs are mined
- **WHEN** a tool response returns structured output with nested arrays or objects
- **THEN** strings, numbers, and keys are mined recursively from nested values

### Requirement: Uniform State Sourcing
The system SHALL select values uniformly from the deduped state corpus for the required primitive type when generating state-machine inputs.

#### Scenario: Uniform selection for string inputs
- **WHEN** multiple strings are available in the state corpus
- **THEN** state-machine generation selects among them with uniform probability

### Requirement: State-Aware Callability
The system SHALL recompute callable tools for each state-machine step based on the current state corpus and tool input schemas.

#### Scenario: Tool becomes callable after mining
- **WHEN** a tool requires a value that is missing before a step
- **AND** a prior tool response mines that value into the state
- **THEN** the tool becomes callable in later steps

#### Scenario: Lenient sourcing bypasses missing corpus values
- **WHEN** lenient sourcing is enabled and a required value is missing from the state corpus
- **THEN** the generator may fall back to schema-based value generation for that input

### Requirement: Sequential State-Machine Generation
The system SHALL generate state-machine sequences using explicit state transitions and the current state corpus to select tools and inputs.

#### Scenario: Sequence terminates when no tools are callable
- **WHEN** no tools are callable under the current state
- **THEN** the generator yields an empty tail for the remaining steps

#### Scenario: Minimum length cannot be satisfied
- **WHEN** the configured minimum sequence length cannot be reached due to no callable tools
- **THEN** the generator fails the run

### Requirement: State Reference Resolution
The system SHALL resolve state references into concrete invocation arguments before issuing tool calls.

#### Scenario: Resolved invocation matches schema
- **WHEN** a tool invocation is generated from state references
- **THEN** the resolved arguments MUST satisfy the tool input schema

### Requirement: Inline Value Generation
The system SHALL generate boolean, null, and enum inputs directly from schema constraints without requiring mined state values.

#### Scenario: Enum values are generated without mining
- **WHEN** a tool input uses an enum schema constraint
- **THEN** state-machine generation selects from the enum values without requiring prior tool outputs
