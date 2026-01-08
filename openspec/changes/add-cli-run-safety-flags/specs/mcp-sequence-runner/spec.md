## ADDED Requirements
### Requirement: Tool Allowlist and Blocklist Filtering
The system SHALL allow callers to filter eligible tools by name using allowlist and blocklist settings; these filters only affect tool eligibility for invocation generation.

#### Scenario: Allowlist restricts eligible tools
- **WHEN** an allowlist is provided
- **THEN** only tools named in the allowlist are eligible for invocation generation

#### Scenario: Blocklist excludes tools
- **WHEN** a blocklist is provided
- **THEN** tools named in the blocklist are excluded from invocation generation

#### Scenario: Filters remove all tools
- **WHEN** allowlist and blocklist settings leave no eligible tools
- **THEN** the run fails with a no-eligible-tools failure

#### Scenario: Allowlist and blocklist matching is exact
- **WHEN** allowlist or blocklist entries are provided
- **THEN** only exact, case-sensitive tool name matches are considered eligible or excluded

### Requirement: Pre-Run Hook Execution
The system SHALL optionally execute a configured pre-run command (shell string) before each generated sequence, including shrink/minimization cases, and before tool schema validation.

#### Scenario: Pre-run hook runs before each case
- **WHEN** a pre-run hook command is configured
- **THEN** the command executes once before each generated sequence, including shrink/minimization cases

#### Scenario: Pre-run hook failure fails the run
- **WHEN** the pre-run hook exits with a non-zero status
- **THEN** the run fails with a distinct failure code and includes the exit code, stdout, stderr, and signal in structured failure details

#### Scenario: Pre-run hook inherits stdio environment
- **WHEN** the run is configured to use a stdio MCP endpoint with env or cwd settings
- **THEN** the pre-run hook executes with the same env and cwd
