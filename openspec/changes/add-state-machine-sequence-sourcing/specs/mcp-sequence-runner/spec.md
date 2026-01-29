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

#### Scenario: Tool selection per step
- **WHEN** generating each step in the sequence
- **THEN** the generator selects a single callable tool to invoke for that step based on the current corpus state

#### Scenario: New corpus values unlock tools
- **WHEN** a tool response adds values to the corpus
- **THEN** subsequent steps consider newly callable tools during selection

#### Scenario: Nested outputs are mined
- **WHEN** a tool response returns structured output with nested arrays or objects
- **THEN** strings, numbers, and keys are mined recursively from nested values

### Requirement: Deterministic Corpus Ordering
The system SHALL preserve deterministic insertion ordering for corpus values.

#### Scenario: Stable index selection
- **WHEN** the state-machine selects a corpus value by index
- **THEN** the index maps to a consistent value across the run

#### Scenario: Seeded values define initial ordering
- **WHEN** caller-provided seed values are supplied in a specific order
- **THEN** the corpus preserves that order before appending mined values

#### Scenario: Deterministic traversal for mining
- **WHEN** mining `structured_content` to extend the corpus
- **THEN** traversal uses array index order and lexicographically sorted object keys to produce deterministic insertion ordering

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

### Requirement: Callable Tool Eligibility
The system SHALL treat a tool as callable only when all required inputs can be generated, using corpus-derived values for numbers and strings and existing schema-driven generation for other types.

#### Scenario: Missing required corpus values makes tool uncallable
- **WHEN** a required number, integer, or string input cannot be satisfied from the corpus
- **THEN** the tool is excluded from selection as uncallable

#### Scenario: Callability recomputed after each step
- **WHEN** a tool response adds new corpus values
- **THEN** callability is recomputed before selecting the next tool

#### Scenario: Optional corpus-backed fields may be omitted
- **WHEN** an optional number or string field lacks corpus values
- **THEN** the generator may omit the field to keep the tool callable

#### Scenario: Non-number/string required fields use schema generators
- **WHEN** a required field is not a number or string
- **THEN** the generator uses existing schema-derived strategies to populate it

### Requirement: Tool Coverage Reporting
The system SHALL track tool call counts during state-machine runs based on successful tool responses and report coverage warnings for tools that could not be called, excluding tools outside configured allowlists or inside configured blocklists.

#### Scenario: Uncallable tool warning
- **WHEN** a tool cannot be invoked during a state-machine run because no valid input can be generated from the corpus
- **THEN** the run output includes a warning identifying the uncalled tool and one of the structured reason codes: `missing_string`, `missing_integer`, `missing_number`, or `missing_required_value`

#### Scenario: Uncallable tools are skipped
- **WHEN** a tool cannot be invoked because the corpus lacks required values
- **THEN** the generator excludes that tool from selection and continues with callable tools

#### Scenario: Error responses do not count as coverage
- **WHEN** a tool call yields an error response
- **THEN** the tool is not counted as called for coverage purposes

#### Scenario: Allowlist and blocklist exemptions
- **WHEN** a tool is excluded by a provided allowlist or blocklist
- **THEN** coverage warnings do not include that tool

#### Scenario: Warnings are emitted after the run
- **WHEN** a state-machine run completes
- **THEN** uncallable tool warnings are emitted based on callability with the final corpus state

#### Scenario: Coverage allowlist and blocklist do not affect selection
- **WHEN** allowlist or blocklist settings are provided for coverage
- **THEN** tool selection continues to use the existing predicate filtering only

### Requirement: Coverage Validation Hooks
The system SHALL allow callers of the state-machine generator mode to supply coverage validation rules that inspect tool call counts.

#### Scenario: Coverage rules applied
- **WHEN** coverage validation rules are provided for a state-machine run
- **THEN** the tool call count mapping is evaluated against those rules

#### Scenario: Percentage coverage uses eligible tools
- **WHEN** coverage rules compute a percentage of tools called
- **THEN** the denominator includes tools eligible after allowlist/blocklist filtering and excludes tools that are uncallable due to corpus limits

#### Scenario: Coverage warnings are non-fatal
- **WHEN** coverage warnings are emitted without validation failures
- **THEN** the run outcome remains successful

#### Scenario: Coverage validation failures fail the run
- **WHEN** a coverage validation rule fails
- **THEN** the run outcome is a failure with a structured coverage validation reason

#### Scenario: Coverage validation failure reason includes code and details
- **WHEN** a coverage validation failure is reported
- **THEN** the failure reason includes a stable code identifier and a structured detail payload describing the violated rule
