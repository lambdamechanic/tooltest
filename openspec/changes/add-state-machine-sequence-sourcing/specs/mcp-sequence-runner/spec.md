## ADDED Requirements
### Requirement: State-Machine Sequence Generation
The system SHALL support a proptest-state-machine generator that produces sequences of MCP tool calls against a configured MCP session.

#### Scenario: State-machine generator is enabled
- **WHEN** a run is configured to use the state-machine generator
- **THEN** tool invocations are produced by a proptest-state-machine model

#### Scenario: Tool selection per step
- **WHEN** generating each step in the sequence
- **THEN** the generator selects a single callable tool to invoke for that step based on the current corpus state

#### Scenario: New corpus values unlock tools
- **WHEN** a tool response adds values to the corpus
- **THEN** subsequent steps consider newly callable tools during selection

#### Scenario: No callable tools ends the run
- **WHEN** no callable tools remain for the next step
- **THEN** the state-machine run ends without error

### Requirement: Response-Sourced Value Corpus
The system SHALL maintain a shared corpus of numbers and strings that is seeded by caller-provided values and updated after each successful tool call by mining numbers and strings from MCP `structured_content` responses, including all object keys and values at any nesting depth, and storing integers only when the numeric value is integral.

#### Scenario: Seeded values available at start
- **WHEN** the caller provides initial numbers and strings
- **THEN** the corpus includes those values before any tool call is generated

#### Scenario: Response values extend the corpus
- **WHEN** a successful tool response includes numbers or strings in `structured_content`
- **THEN** those values are added to the corpus for later generations

#### Scenario: Response keys extend the corpus
- **WHEN** a successful tool response includes object keys in `structured_content`
- **THEN** those keys are added to the string corpus for later generations

#### Scenario: Integer corpus only stores integral numbers
- **WHEN** a numeric value mined from `structured_content` is not integral
- **THEN** it is not added to the integer corpus

#### Scenario: Error responses do not extend the corpus
- **WHEN** a tool response is an error
- **THEN** its `structured_content` is not mined into the corpus

### Requirement: Corpus-Only Number/String Generation
The system SHALL generate all numbers and strings used in tool inputs exclusively from the shared corpus, selecting integer values only from an integer corpus when an input schema requires `integer`.

#### Scenario: Tool input generation uses corpus values
- **WHEN** a generated tool input requires a number or string
- **THEN** the value is selected from the corpus instead of being generated randomly

#### Scenario: Integer inputs use integer corpus
- **WHEN** a generated tool input requires an integer
- **THEN** the value is selected from the integer corpus

### Requirement: Deterministic Corpus Indexing
The system SHALL store corpus values with set semantics and deterministic, insertion-ordered indexing to support stable selection by index.

#### Scenario: Duplicate values are de-duplicated
- **WHEN** a mined number or string already exists in the corpus
- **THEN** the corpus does not add a duplicate entry

#### Scenario: Stable index selection
- **WHEN** the state-machine selects a corpus value by index
- **THEN** the index maps to a consistent value across the run

#### Scenario: Seeded values define initial ordering
- **WHEN** caller-provided seed values are supplied in a specific order
- **THEN** the corpus preserves that order before appending mined values

#### Scenario: Deterministic traversal for mining
- **WHEN** mining `structured_content` to extend the corpus
- **THEN** traversal uses array index order and lexicographically sorted object keys to produce deterministic insertion ordering

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

### Requirement: Unified Test Entry Point
The system SHALL provide a single entry point for tests that allows callers to choose between the existing generator and the state-machine generator.

#### Scenario: Caller selects generator mode
- **WHEN** a caller specifies the generator mode
- **THEN** the run uses the selected generator for sequence generation

#### Scenario: Default generator mode is legacy
- **WHEN** a caller does not specify a generator mode
- **THEN** the run uses the existing generator by default

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

#### Scenario: Coverage validation warnings are structured
- **WHEN** coverage validation rules emit warnings without failures
- **THEN** the run output includes structured coverage warning details

#### Scenario: Coverage validation failure reason includes code and details
- **WHEN** a coverage validation failure is reported
- **THEN** the failure reason includes a stable code identifier and a structured detail payload describing the violated rule
