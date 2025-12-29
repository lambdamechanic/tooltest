## ADDED Requirements
### Requirement: Corpus Debug Output
When enabled for state-machine runs, the system SHALL emit a JSON dump of the final state-machine corpus after the run completes.

#### Scenario: Corpus dump disabled by default
- **WHEN** corpus debug output is not enabled
- **THEN** no corpus dump is emitted

#### Scenario: Corpus dump emitted when enabled
- **WHEN** corpus debug output is enabled and the run completes (success or failure)
- **THEN** the final corpus is emitted as JSON
- **AND** in human-readable output mode the corpus dump is written to stderr
- **AND** in JSON output mode the corpus dump is embedded in the JSON output

### Requirement: Corpus Delta Logging
When enabled, the system SHALL log newly mined corpus values after each tool response during state-machine runs.

#### Scenario: Delta logging disabled by default
- **WHEN** corpus delta logging is not enabled
- **THEN** no per-response corpus logs are emitted

#### Scenario: Delta logging records new values only
- **WHEN** corpus delta logging is enabled and a tool response is processed
- **THEN** only newly added corpus values are logged for that response
- **AND** delta logs are written to stderr in a human-readable format
