# Change: Add pre-run command hook for sequence runs
Status: Approved

## Why
Some MCP servers depend on external state that must be reset between cases. A pre-run command hook allows tooltest to restore that state before each proptest case, improving determinism.

## What Changes
- Add an optional CLI flag that accepts a JSON array (argv) to run before each proptest case.
- Fail the run when the command exits non-zero and surface stdout/stderr for debugging.
- Apply the hook to stdio, HTTP, and session entry points.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: tooltest CLI args, tooltest-core runner execution
