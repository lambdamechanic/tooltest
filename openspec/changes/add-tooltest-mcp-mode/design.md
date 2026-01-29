# Design: MCP mode for tooltest

## Overview
Introduce a new `tooltest mcp` subcommand that runs an MCP server exposing a single tool named `tooltest`. The tool accepts a shared input configuration type defined in `tooltest-core` so that both CLI and MCP execution paths rely on the same configuration structure, including shared validation semantics.

## CLI and MCP input unification
- Create a public, serializable configuration type in `tooltest-core` (e.g., `TooltestInput` or similar).
- The type contains the full set of tooltest options (cases, sequence length, state-machine config, filters, hooks, etc.) along with a transport selector for the target MCP server (stdio command config or full HTTP URL config).
- The CLI parser maps `tooltest` arguments into this shared type and then derives `RunConfig`/`RunnerOptions` from it.
- The MCP tool handler accepts the same type as the tool input payload and uses the same conversion path and validation semantics.
- Canonical MCP input uses snake_case field names that match CLI long flags (for example `tool_allowlist`, `min_sequence_len`) and represents transport as `target.stdio.command` or `target.http.url`.
- `state_machine_config` is a structured object matching `tooltest_core::StateMachineConfig`, and env fields use JSON object maps.
- MCP input requires an explicit `target` object (no top-level `stdio` shorthand).

## MCP server
- `tooltest mcp` starts an MCP server that exposes the `tooltest` tool.
- The MCP server transport is configured via `--stdio` (default) or `--http --bind <addr>` with explicit `--stdio` support and mutual exclusion between `--stdio` and `--http`.
- For `--http`, the server must bind to the provided address and expose the MCP endpoint at `/mcp`.
- The `tooltest` MCP tool returns `RunResult` in `structuredContent`, mirrors it as JSON text in `content`, and uses `isError=true` only for internal tooltest failures that cannot produce a `RunResult`.

## Prompts
- Add a static prompt to the MCP server named `tooltest-fix-loop`.
- The prompt is a static literal that includes guidance to select a small subset of related tools (suggest default max 50, recommend fewer) and notes that tooltest can be invoked via MCP or CLI with the same options.
- Add a static MCP resource (default URI `tooltest://guides/fix-loop`) with content matching the prompt to guide usage.

## Testing
- Add a test that requests the MCP prompt and asserts the prompt name and static content.
- Add a test that requests `resources/list` + `resources/read` and asserts the fix-loop resource content.
- Add an integration test that runs tooltest against itself (stdio test server) using the MCP tool path.

## Trade-offs
- Centralizing config in `tooltest-core` expands the public API but ensures consistency across CLI and MCP usage.
