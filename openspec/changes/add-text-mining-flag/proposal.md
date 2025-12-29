# Change: Add text mining flag for state corpus

## Why
Tool runs that only emit textual content cannot seed the state-machine corpus, limiting reachable tools in strict mode.

## What Changes
- Add a CLI flag to enable mining of textual outputs into the state corpus.
- Parse text content into whitespace-delimited tokens and classify as numbers or strings for corpus seeding.
- Update the kev-mcp local tooltest harness to enable the flag and increase max sequence length.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: tooltest-core runner/coverage tracking, tooltest-cli args, kev-mcp tooltest harness
