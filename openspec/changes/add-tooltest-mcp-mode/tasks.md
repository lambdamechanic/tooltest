## 0. Dependencies / sequencing
- [x] 1.1 → 4.4, 4.5, 5.1, 5.2, 6.1 (prompt/resource content before implementation, tests, and skill update)
- [x] 1.2 → 5.3 (stdio test server identified before MCP tooltest-on-tooltest test)
- [x] 2 → 3 (CLI integration depends on shared input type)
- [x] 2 → 4 (MCP tool schema depends on shared input type)
- [x] 4.1-4.7 → 5.1-5.7 (tests depend on MCP server implementation)
- [x] 4.4, 4.5 → 5.1, 5.2 (prompt/resource tests depend on prompt/resource implementation)

## 1. Proposal readiness
- [x] Draft MCP prompt/resource content as a static literal with tool subset guidance (default max 50, smaller recommended).
- [x] Identify the existing stdio test server to use for tooltest-on-tooltest testing.

## 2. Shared tooltest input type
- [x] Define a public tooltest input type in `tooltest-core` that captures tooltest run configuration and target transport.
- [x] Add conversion helpers to derive `RunConfig` and `RunnerOptions` from the shared input type.
- [x] Ensure the shared input is nested and mirrors CLI required/optional fields with defaults matching CLI defaults.
- [x] Validate HTTP targets as full URLs (scheme + host) and align validation errors with CLI behavior.
- [x] Define `state_machine_config` as a structured object matching `tooltest_core::StateMachineConfig`.
- [x] Use JSON object maps for stdio `env` and pre-run hook `env`.
- [x] Require explicit `target` in MCP input and reject top-level `stdio` shorthand.

## 3. CLI integration
- [x] Update CLI parsing to populate the shared tooltest input type and execute runs from it.
- [x] Ensure `tooltest stdio` and `tooltest http` remain backwards compatible.

## 4. MCP server implementation
- [x] Add `tooltest mcp` subcommand with stdio-only transport (optional `--stdio` flag).
- [x] Implement MCP server exposing a `tooltest` tool that accepts the shared input type and returns `RunResult` for tooltest completion outcomes.
- [x] Surface unexpected tooltest errors as MCP/JSON-RPC errors.
- [x] Mirror `RunResult` into `content` as JSON text and include it as `structuredContent` for MCP tool responses.
- [x] Add static MCP prompt `tooltest-fix-loop` with tool subset guidance and MCP/CLI usage notes.
- [x] Add a static MCP resource (default URI `tooltest://guides/fix-loop`) that mirrors the prompt content.
- [x] Provide default handlers for tools/list, prompts/list, prompts/get, resources/list, and resources/read responses.

## 5. Tests and validation
- [x] Add a test that validates prompt listing and prompt content for `tooltest-fix-loop`.
- [x] Add a test that validates resources/list and resources/read for `tooltest://guides/fix-loop`, including `mimeType: text/plain`.
- [x] Add a test that runs tooltest via MCP against the stdio test server (tooltest-on-tooltest).
- [x] Add a test that asserts MCP tool responses include `structuredContent` RunResult and `content` as JSON text.
- [x] Add a test that omits `target` or provides top-level `stdio` and asserts validation failure.
- [x] Configure the MCP tool smoke test to run 50 cases with min/max sequence length set to 1.
- [x] Run relevant test suites (tooltest, tooltest-core) and ensure CI coverage expectations are met.

## 6. Skill update
- [x] Update the `tooltest-fix-loop` skill with tool subset guidance, agent allowlist advice, and MCP/CLI invocation options.
