## 1. Proposal readiness
- [ ] Review README “Agent-assisted fix loop prompt” for MCP adaptation content.
- [ ] Identify the existing stdio test server to use for tooltest-on-tooltest testing.

## 2. Shared tooltest input type
- [ ] Define a public tooltest input type in `tooltest-core` that captures tooltest run configuration and target transport.
- [ ] Add conversion helpers to derive `RunConfig` and `RunnerOptions` from the shared input type.
- [ ] Ensure the shared input is nested and mirrors CLI required/optional fields.

## 3. CLI integration
- [ ] Update CLI parsing to populate the shared tooltest input type and execute runs from it.
- [ ] Ensure `tooltest stdio` and `tooltest http` remain backwards compatible.

## 4. MCP server implementation
- [ ] Add `tooltest mcp` subcommand with `--stdio` default and `--http --bind <addr>` option.
- [ ] Implement MCP server exposing a `tooltest` tool that accepts the shared input type.
- [ ] Add static MCP prompt `tooltest-fix-loop` with MCP tool instructions.
- [ ] Provide default handlers for tools/list, prompts/list, and prompts/get responses.

## 5. Tests and validation
- [ ] Add a test that validates prompt listing and prompt content for `tooltest-fix-loop`.
- [ ] Add a test that runs tooltest via MCP against the stdio test server (tooltest-on-tooltest).
- [ ] Configure the MCP tool smoke test to run 50 cases without custom sequence lengths.
- [ ] Run relevant test suites (tooltest, tooltest-core) and ensure CI coverage expectations are met.
