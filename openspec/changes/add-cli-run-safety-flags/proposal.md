# Change: Add CLI safety controls for tool selection and pre-run hooks

## Why
Tooltest needs a safe way to avoid destructive tools and a repeatable way to reset MCP state between cases.

## What Changes
- Add CLI flags to allowlist or blocklist tools by name, mapping to existing tool predicates.
- Add an optional pre-run command hook (shell string) that executes before each generated case, including shrink/minimization cases, and runs before validation.
- Update CLI and run results to surface pre-run hook failures with structured details (exit code, stdout, stderr, signal) and a distinct failure code.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: tooltest-core runner execution, tooltest CLI parsing
