# Change: Update CLI command parsing for stdio runs

## Why
The current stdio CLI requires a single executable plus repeated `--arg` flags, which is awkward for users and incompatible with common shell command line usage.

## What Changes
- Accept a full shell-style command line in `--command` for stdio runs and parse it into argv.
- Remove the `--arg` flag from the stdio CLI.
- Update help text and validation to reflect the new parsing behavior.
- Add a gated stdio integration test that exercises Playwright MCP directly via `npx -y @playwright/mcp@latest`.
- **BREAKING**: `--arg` is removed; users must include arguments in `--command`.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: tooltest CLI argument parsing and stdio configuration
