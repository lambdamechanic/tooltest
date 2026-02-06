## ADDED Requirements
### Requirement: Validated Configuration
The system SHALL reject invalid run configuration values before issuing any tool calls. Configuration invariants MUST be enforced at construction and during deserialization so invalid states are not representable through the public API.

#### Scenario: Cases must be nonzero
- **WHEN** a run is configured with `cases = 0`
- **THEN** configuration creation fails with a configuration error

#### Scenario: Sequence length range must be valid
- **WHEN** a run is configured with a sequence length range where `min < 1` or `min > max`
- **THEN** configuration creation fails with a configuration error

#### Scenario: Uncallable limit must be nonzero
- **WHEN** a run is configured with `uncallable_limit = 0`
- **THEN** configuration creation fails with a configuration error

#### Scenario: Stdio command must be non-empty
- **WHEN** a stdio run is configured with an empty/whitespace command
- **THEN** configuration creation fails with a configuration error

#### Scenario: HTTP URL must be valid
- **WHEN** an HTTP run is configured with a URL that does not parse or is missing a host
- **THEN** configuration creation fails with a configuration error

