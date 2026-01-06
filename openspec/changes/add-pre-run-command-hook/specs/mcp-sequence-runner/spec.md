## ADDED Requirements
### Requirement: Pre-Run Command Hook
The system SHALL support an optional command hook that executes before each proptest case.

#### Scenario: Pre-run command executes per case
- **WHEN** a run is configured with a pre-run command
- **THEN** the command executes once before each proptest case

#### Scenario: Pre-run command failure
- **WHEN** the pre-run command exits non-zero
- **THEN** the run fails with an error outcome

#### Scenario: Pre-run command captures output
- **WHEN** the pre-run command runs
- **THEN** stdout and stderr are captured for reporting
