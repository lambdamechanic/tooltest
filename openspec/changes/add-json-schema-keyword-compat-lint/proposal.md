# Change: Add JSON Schema Keyword Compatibility Lint

## Why
Schema keyword compatibility warnings are currently emitted as run warnings. Converting them to a
lint allows configurable severity and consistent lint reporting.

## What Changes
- Add a list-phase lint `json_schema_keyword_compat` for `$defs` usage with draft-07/06/04 schemas.
- Remove the legacy run warning emitted for `$defs` with older schema drafts.
- Enable the new lint at `warning` level in the default lint configuration.

## Impact
- Affected specs: `mcp-sequence-runner`
- Affected code: `tooltest-core` lints, lint config, runner schema warnings, default configs
