## ADDED Requirements
### Requirement: JSON Schema Keyword Compatibility Lint
The system SHALL provide a list-phase lint that reports when tool input or output schemas use
`$defs` while declaring a JSON Schema draft that predates `$defs` (draft-07, draft-06, or draft-04).

#### Scenario: Legacy draft uses $defs
- **WHEN** a tool input or output schema declares draft-07, draft-06, or draft-04 and includes `$defs`
- **THEN** the lint emits a warning or failure based on its configured level

## MODIFIED Requirements
### Requirement: Default Config Contents
The built-in default `tooltest.toml` SHALL include a JSON Schema dialect allowlist containing JSON
Schema 2020-12, 2019-09, draft-07, draft-06, and draft-04. It SHALL enable `no_crash` at `error`
level, set the MCP protocol version lint to `warning` level by default, and enable
`missing_structured_content` and `json_schema_keyword_compat` at `warning` level. It SHALL include
entries for all supported lints, with lints that are not enabled by default set to `disabled`,
populated with sensible default parameters, and commented for easy activation.

#### Scenario: Default allowlist includes older drafts
- **WHEN** the default config is emitted
- **THEN** the JSON Schema dialect allowlist includes 2020-12, 2019-09, draft-07, draft-06, and draft-04 identifiers

#### Scenario: Default lint levels
- **WHEN** the default config is emitted
- **THEN** `no_crash` is `error`, `mcp_schema_min_version` is `warning`, and `missing_structured_content` and `json_schema_keyword_compat` are `warning`

#### Scenario: Default config includes disabled lints
- **WHEN** the default config is emitted
- **THEN** supported lints that are not enabled by default are present with `level = "disabled"` and commented for easy activation
