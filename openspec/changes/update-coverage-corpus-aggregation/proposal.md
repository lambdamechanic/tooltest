# Change: Aggregate corpus across cases for coverage

## Why
Coverage warnings currently derive from the final case's corpus, which can miss data mined earlier. This can incorrectly flag tools as uncallable even when prior cases discovered valid inputs.

## What Changes
- Aggregate corpus mining across all cases in a run for final coverage computation.
- Ensure coverage warnings consider the aggregated corpus for callability checks.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: state-machine runner coverage tracking and run result aggregation
