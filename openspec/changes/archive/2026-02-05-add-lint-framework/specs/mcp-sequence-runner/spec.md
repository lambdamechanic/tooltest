## ADDED Requirements
### Requirement: Lint Configuration Loading
The system SHALL load lint configuration from TOML files. It SHALL search upward from the current working directory to the git root for `tooltest.toml`; if found, it SHALL use that file and ignore any home configuration. If no repo file is found, it SHALL use `~/.config/tooltest.toml` when present. If no file is found, it SHALL fall back to a built-in default `tooltest.toml` embedded in the library.

#### Scenario: Repo config overrides home config
- **WHEN** both a repo `tooltest.toml` and `~/.config/tooltest.toml` exist
- **THEN** the repo config is used and the home config is ignored

#### Scenario: Missing config file
- **WHEN** no repo or home config file exists
- **THEN** the built-in default `tooltest.toml` is used

### Requirement: Lint Configuration Schema
The system SHALL accept lint configuration with a top-level `version` (defaulting to `1` when omitted) and a `[[lints]]` array. Each lint entry SHALL include `id` and `level`, and MAY include a `[lints.params]` table for lint-specific parameters. Unknown lint IDs or invalid parameter types SHALL cause a configuration error.

#### Scenario: Unknown lint id fails config
- **WHEN** a lint entry specifies an unknown `id`
- **THEN** configuration loading fails with a configuration error

#### Scenario: Duplicate lint ids fail config
- **WHEN** lint entries include duplicate `id` values
- **THEN** configuration loading fails with a configuration error

#### Scenario: Invalid level fails config
- **WHEN** a lint entry specifies a `level` outside `error|warning|disabled`
- **THEN** configuration loading fails with a configuration error

#### Scenario: Missing version defaults to 1
- **WHEN** `version` is omitted
- **THEN** the configuration is interpreted as version `1`

### Requirement: Default Config Exposure
The system SHALL expose the built-in default `tooltest.toml` via a `tooltest config default` CLI subcommand so users can generate their own config file, and the default config SHALL include explanatory comments.

#### Scenario: Default config can be emitted
- **WHEN** a user invokes `tooltest config default`
- **THEN** the system returns the built-in `tooltest.toml` contents with comments intact

### Requirement: Default Config Contents
The built-in default `tooltest.toml` SHALL include a JSON Schema dialect allowlist containing JSON Schema 2020-12, 2019-09, draft-07, draft-06, and draft-04. It SHALL enable `no_crash` at `error` level, set the MCP protocol version lint to `warning` level by default, and enable `missing_structured_content` at `warning` level. It SHALL include entries for all supported lints, with lints that are not enabled by default set to `disabled`, populated with sensible default parameters, and commented for easy activation.

#### Scenario: Default allowlist includes older drafts
- **WHEN** the default config is emitted
- **THEN** the JSON Schema dialect allowlist includes 2020-12, 2019-09, draft-07, draft-06, and draft-04 identifiers

#### Scenario: Default lint levels
- **WHEN** the default config is emitted
- **THEN** `no_crash` is `error`, `mcp_schema_min_version` is `warning`, and `missing_structured_content` is `warning`

#### Scenario: Default config includes disabled lints
- **WHEN** the default config is emitted
- **THEN** supported lints that are not enabled by default are present with `level = "disabled"` and commented for easy activation

### Requirement: Lint Severity and Findings
The system SHALL represent each lint with a configurable severity level of `error`, `warning`, or `disabled`. Lints set to `error` SHALL fail runs/validations when violated. Lints set to `warning` SHALL emit warnings without failing the run. Disabled lints SHALL be skipped. Fixed-severity lints (such as `no_crash`) SHALL be error-only; configuring them with any non-`error` level SHALL be rejected as a configuration error.

#### Scenario: Warning-level lint does not fail the run
- **WHEN** a configured lint with level `warning` is violated during a run
- **THEN** the run completes with a warning recorded and a non-failure outcome

#### Scenario: Error-level lint fails the run
- **WHEN** a configured lint with level `error` is violated during a run
- **THEN** the run fails with a structured failure

#### Scenario: Fixed-severity lint configured as warning
- **WHEN** a fixed-severity lint is configured with a non-`error` level
- **THEN** the configuration is rejected with a configuration error

### Requirement: Lint Evaluation Semantics
The system SHALL collect all lint findings within a phase and aggregate warnings across phases. If any error-level lint fires during list-phase evaluation, the run SHALL fail before any tools/call is issued. If any error-level lint fires during response-phase evaluation, the run SHALL fail after that response. Run-phase lints SHALL evaluate after execution completes.

#### Scenario: List-phase lint error stops run
- **WHEN** a list-phase lint produces an error-level finding
- **THEN** the run fails before any tools/call is executed

### Requirement: Lint Phases
The system SHALL support lint phases to distinguish when checks are evaluated:
- list-phase lints run after tools/list parsing and before any tool calls
- response-phase lints run per tools/call response
- run-phase lints run after the run completes using aggregate data

#### Scenario: List-phase lints run before tool calls
- **WHEN** a run starts and tools/list is parsed
- **THEN** list-phase lints are evaluated before any tools/call is issued

### Requirement: Max Tools Lint
The system SHALL provide a list-phase lint that checks the raw tools/list count against a configured maximum.

#### Scenario: Max tools limit exceeded
- **WHEN** tools/list returns more tools than the configured maximum
- **THEN** the lint emits a warning or failure based on its configured level

### Requirement: MCP Schema Minimum Version Lint
The system SHALL provide a list-phase lint that verifies the server’s MCP protocol/schema version meets a configured minimum. If the server does not report a version, the lint SHALL emit a violation.

#### Scenario: MCP schema version below minimum
- **WHEN** the server reports an MCP schema/protocol version lower than the configured minimum
- **THEN** the lint emits a warning or failure based on its configured level

### Requirement: MCP Schema Version Comparison
The system SHALL compare MCP protocol versions using the `initialize` response `protocolVersion` value. If the reported version cannot be parsed as a date-formatted version (YYYY-MM-DD), the lint SHALL emit a violation.

#### Scenario: Unparseable protocol version
- **WHEN** the server reports a protocol version that is not in YYYY-MM-DD format
- **THEN** the lint emits a warning or failure based on its configured level

### Requirement: JSON Schema Dialect Compatibility Lint
The system SHALL provide a list-phase lint that validates tool input/output `$schema` values against a configured allowlist. If `$schema` is omitted, the system SHALL treat it as JSON Schema 2020-12.

#### Scenario: Unsupported schema dialect
- **WHEN** a tool input/output schema declares a `$schema` not in the configured allowlist
- **THEN** the lint emits a warning or failure based on its configured level

### Requirement: StructuredContent Size Lint
The system SHALL provide a response-phase lint that checks the size of `structuredContent` per response against a configured byte limit. When `structuredContent` is absent, the size SHALL be treated as zero.

#### Scenario: StructuredContent exceeds maximum
- **WHEN** a tools/call response includes `structuredContent` whose serialized JSON byte size exceeds the configured maximum
- **THEN** the lint emits a warning or failure based on its configured level

### Requirement: Coverage Lint
The system SHALL provide a run-phase lint that evaluates configured coverage rules from the lint configuration against the run’s coverage data. Coverage rules SHALL be configured as an array of rule objects with a `rule` discriminator and associated parameters.

#### Scenario: Coverage rules fail
- **WHEN** coverage data violates configured coverage rules
- **THEN** the lint emits a warning or failure based on its configured level

#### Scenario: Coverage rules configured as objects
- **WHEN** the coverage lint is configured
- **THEN** its `rules` are an array of objects like `{ rule = "min_calls_per_tool", min = 1 }` or `{ rule = "percent_called", min_percent = 90.0 }`

#### Scenario: Coverage rule variants
- **WHEN** coverage rules are specified
- **THEN** supported `rule` values are `min_calls_per_tool` (requires `min`), `no_uncalled_tools` (no params), and `percent_called` (requires `min_percent`)

### Requirement: Run Result Warnings
The system SHALL surface lint warnings and existing run warnings in run results.

#### Scenario: Run results include warnings
- **WHEN** a run completes with lint warnings or run warnings
- **THEN** the run result includes those warnings

### Requirement: Lint Warning Encoding
The system SHALL emit structured warning codes for lint findings and include the lint id in warning details.

#### Scenario: Lint warning includes lint id
- **WHEN** a lint emits a warning
- **THEN** the warning includes a structured lint code and the lint id in its details

### Requirement: Remove State-Machine Coverage Rules
The system SHALL remove `coverage_rules` from the state-machine configuration and rely solely on coverage lint configuration.

#### Scenario: Coverage rules only configured via lint
- **WHEN** coverage rules are configured
- **THEN** they are specified only in the coverage lint configuration

### Requirement: No-Crash Lint
The system SHALL provide a run-phase `no_crash` lint that observes all run failure signals (including session/transport errors and runtime panics) and fails the run.

#### Scenario: No-crash lint fires on runtime failure
- **WHEN** a run encounters any failure condition
- **THEN** the `no_crash` lint emits a failure based on its fixed error level

### Requirement: Missing StructuredContent Lint
The system SHALL provide a response-phase `missing_structured_content` lint that triggers when a tool defines an output schema but the response omits `structuredContent`.

#### Scenario: Missing structuredContent reported
- **WHEN** a tool with an output schema returns no `structuredContent`
- **THEN** the lint emits a warning or failure based on its configured level

### Requirement: Remove Legacy Validate-Tools API
The system SHALL remove the legacy `tooltest_core::validation::validate_tools` API and related validation workflow from the codebase, retaining schema-based invocation generators needed for lenient sourcing.

#### Scenario: Legacy validation API removed
- **WHEN** the codebase is built
- **THEN** the legacy validate-tools validation workflow is no longer present
