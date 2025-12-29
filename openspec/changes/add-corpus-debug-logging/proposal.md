# Change: Add corpus debug logging

## Why
Debugging state-machine generation needs visibility into the current corpus and what new values are mined at each step.

## What Changes
- Add a CLI flag to emit a JSON dump of the final corpus at the end of a run.
- Add a CLI flag to log incremental corpus additions per tool response.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: tooltest-core runner/coverage tracking, tooltest-cli args, output formatting
