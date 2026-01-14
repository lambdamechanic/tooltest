# Change: Add in-band error handling flag

## Why
In-band MCP error responses currently fail runs, which makes it hard to continue testing tool behavior that returns expected errors. We need an opt-in flag to preserve the current failure behavior while allowing non-fatal in-band errors by default.

## What Changes
- Add CLI flag `--in-band-error-forbidden` to preserve current behavior of failing runs on MCP error responses.
- Default behavior treats in-band MCP error responses as non-fatal unless the server crashes or responses are schema-invalid.
- In-band error responses remain excluded from coverage counts.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: CLI arg parsing, runner assertion handling, coverage tracking, tests
