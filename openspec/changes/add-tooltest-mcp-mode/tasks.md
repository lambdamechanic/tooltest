## 0. Dependencies / sequencing
- [ ] 1.1 → 4.4, 4.5, 5.1, 5.2, 6.1 (prompt/resource content before implementation, tests, and skill update)
- [ ] 1.2 → 5.3 (stdio test server identified before MCP tooltest-on-tooltest test)
- [ ] 2 → 3 (CLI integration depends on shared input type)
- [ ] 2 → 4 (MCP tool schema depends on shared input type)
- [ ] 4.1-4.7 → 5.1-5.7 (tests depend on MCP server implementation)
- [ ] 4.4, 4.5 → 5.1, 5.2 (prompt/resource tests depend on prompt/resource implementation)

## 1. Proposal readiness
- [ ] Draft MCP prompt/resource content as a static literal with tool subset guidance (default max 50, smaller recommended).
- [ ] Identify the existing stdio test server to use for tooltest-on-tooltest testing.

## 2. Shared tooltest input type
- [ ] Define a public tooltest input type in `tooltest-core` that captures tooltest run configuration and target transport.
- [ ] Add conversion helpers to derive `RunConfig` and `RunnerOptions` from the shared input type.
- [ ] Ensure the shared input is nested and mirrors CLI required/optional fields with defaults matching CLI defaults.
- [ ] Validate HTTP targets as full URLs (scheme + host) and align validation errors with CLI behavior.
- [ ] Define `state_machine_config` as a structured object matching `tooltest_core::StateMachineConfig`.
- [ ] Use JSON object maps for stdio `env` and pre-run hook `env`.
- [ ] Require explicit `target` in MCP input and reject top-level `stdio` shorthand.

## 3. CLI integration
- [ ] Update CLI parsing to populate the shared tooltest input type and execute runs from it.
- [ ] Ensure `tooltest stdio` and `tooltest http` remain backwards compatible.

## 4. MCP server implementation
- [ ] Add `tooltest mcp` subcommand with stdio-only transport (optional `--stdio` flag).
- [ ] Implement MCP server exposing a `tooltest` tool that accepts the shared input type and returns `RunResult` for tooltest completion outcomes.
- [ ] Surface unexpected tooltest errors as MCP/JSON-RPC errors.
- [ ] Mirror `RunResult` into `content` as JSON text and include it as `structuredContent` for MCP tool responses.
- [ ] Add static MCP prompt `tooltest-fix-loop` with tool subset guidance and MCP/CLI usage notes.
- [ ] Add a static MCP resource (default URI `tooltest://guides/fix-loop`) that mirrors the prompt content.
- [ ] Provide default handlers for tools/list, prompts/list, prompts/get, resources/list, and resources/read responses.

## 5. Tests and validation
- [ ] Add a test that validates prompt listing and prompt content for `tooltest-fix-loop`.
- [ ] Add a test that validates resources/list and resources/read for `tooltest://guides/fix-loop`, including `mimeType: text/plain`.
- [ ] Add a test that runs tooltest via MCP against the stdio test server (tooltest-on-tooltest).
- [ ] Add a test that asserts MCP tool responses include `structuredContent` RunResult and `content` as JSON text.
- [ ] Add a test that omits `target` or provides top-level `stdio` and asserts validation failure.
- [ ] Configure the MCP tool smoke test to run 50 cases without custom sequence lengths.
- [ ] Run relevant test suites (tooltest, tooltest-core) and ensure CI coverage expectations are met.

## 6. Skill update
- [ ] Update the `tooltest-fix-loop` skill with tool subset guidance, agent allowlist advice, and MCP/CLI invocation options.
