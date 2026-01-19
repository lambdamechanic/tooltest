## 1. Implementation
- [x] 1.1 Remove `--arg` from stdio CLI options and parse `--command` into argv using shell-style splitting.
- [x] 1.2 Update stdio config construction to use the parsed argv and ensure errors are surfaced with helpful messages.
- [x] 1.3 Update CLI tests for stdio command parsing, including quoted arguments.
- [x] 1.4 Add a gated stdio integration test that runs the Smithery CLI via `npx @smithery/cli@latest run @microsoft/playwright-mcp`.
- [x] 1.5 Update README/docs and blog references to show the new `--command` usage.

## 2. Validation
- [x] 2.1 Run relevant CLI and stdio tests.
