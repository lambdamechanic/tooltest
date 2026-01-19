## ADDED Requirements
### Requirement: CLI stdio command parsing
The system SHALL accept a shell-style command line for stdio runs via `--command`, parsing it into an executable and argument list, and SHALL NOT expose a separate `--arg` flag.

#### Scenario: Quoted arguments are preserved
- **WHEN** a stdio run is invoked with quoted arguments in `--command`
- **THEN** the parsed argv preserves the quoted segments as single arguments

#### Scenario: Invalid command line fails the run
- **WHEN** the provided `--command` cannot be parsed into argv
- **THEN** the CLI reports an error and does not start the run
