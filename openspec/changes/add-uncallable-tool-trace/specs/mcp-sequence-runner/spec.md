## ADDED Requirements
### Requirement: Uncallable tool trace reporting
The system SHALL optionally report the last N calls per tool for tools with zero successful calls, including tools that were never invoked, when a run is invoked with `--show-uncallable`. The per-tool call limit SHALL be configurable via `--uncallable-limit <N>`.

#### Scenario: Uncallable trace includes last N calls
- **WHEN** a tool has zero successes
- **AND** the run is invoked with `--show-uncallable`
- **THEN** the run output includes the last N calls for that tool, including input, output, error, and RFC3339 timestamps, in both human output and result JSON

#### Scenario: Uncallable trace includes never-invoked tools
- **WHEN** a tool is never invoked
- **AND** the run is invoked with `--show-uncallable`
- **THEN** the run output includes an entry for that tool with an empty list of calls recorded

#### Scenario: Uncallable trace omitted by default
- **WHEN** a run fails only due to coverage validation warnings or thresholds
- **AND** `--show-uncallable` is not set
- **THEN** the run output omits failure trace entries

#### Scenario: Uncallable trace ordering
- **WHEN** multiple tools qualify for uncallable trace output
- **AND** the run is invoked with `--show-uncallable`
- **THEN** the tools are listed in alphabetical order

### Requirement: Coverage validation
The system SHALL evaluate coverage thresholds for tool invocation success counts and report a coverage validation failure when any threshold is unmet.

#### Scenario: Coverage validation failure
- **WHEN** a run completes without a positive error
- **AND** one or more coverage thresholds are unmet
- **THEN** the run fails with a coverage validation failure

## MODIFIED Requirements
### Requirement: Run Results
The system SHALL include failure traces only when a positive error causes the run to fail; coverage-only failures shall omit trace output by default unless the uncallable trace flag is set. Positive errors are assertion failures, schema validation errors (including JSON-RPC errors), and crashes; tool responses with `isError: true` are not positive errors and do not count as successes.

#### Scenario: Coverage-only failure omits trace
- **WHEN** a run fails solely due to coverage validation
- **THEN** the result omits trace details unless the uncallable trace flag is enabled

#### Scenario: Positive error suppresses coverage output
- **WHEN** a run fails with a positive error
- **THEN** coverage validation output is omitted
