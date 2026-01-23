# Change: Add uncallable tool trace output

## Why
Coverage validation failures currently surface a trace entry that does not correspond to the specific call failure, making it difficult to understand failure modes for tools that never succeeded. We need targeted trace output for tools that repeatedly fail and remain uncalled.

## What Changes
- Add a `--show-uncallable` flag to include targeted trace output for tools that have zero successful calls, including tools that were never invoked.
- Add a `--uncallable-limit <N>` flag to configure how many calls per tool to include.
- Update trace output to only include failure traces when a positive error is the reason for failure; omit the trace by default otherwise.
- Positive errors are assertion errors, schema validation errors (including JSON-RPC), and crashes. Tool responses with `isError: true` are not positive errors and do not count as successes.
- When coverage validation is the only failure mode, include the last N calls per tool (configurable by flag), surfaced alongside the coverage validation failure details.
- Include input, output, error, and RFC3339 timestamps for each included call. Output is emitted in both the human output and run result JSON.
- Order tools alphabetically in the uncallable trace output.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: CLI flags, run result formatting, coverage validation reporting
