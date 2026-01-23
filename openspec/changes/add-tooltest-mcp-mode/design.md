# Design: MCP mode for tooltest

## Overview
Introduce a new `tooltest mcp` subcommand that runs an MCP server exposing a single tool named `tooltest`. The tool accepts a shared input configuration type defined in `tooltest-core` so that both CLI and MCP execution paths rely on the same configuration structure.

## CLI and MCP input unification
- Create a public, serializable configuration type in `tooltest-core` (e.g., `TooltestInput` or similar).
- The type contains the full set of tooltest options (cases, sequence length, state-machine config, filters, hooks, etc.) along with a transport selector for the target MCP server (stdio command config or HTTP url config).
- The CLI parser maps `tooltest` arguments into this shared type and then derives `RunConfig`/`RunnerOptions` from it.
- The MCP tool handler accepts the same type as the tool input payload and uses the same conversion path.

## MCP server
- `tooltest mcp` starts an MCP server that exposes the `tooltest` tool.
- The MCP server transport is configured via `--stdio` (default) or `--http --bind <addr>`.
- For `--http`, the server must bind to the provided address and expose the MCP endpoint.

## Prompts
- Add a static prompt to the MCP server named `tooltest-fix-loop`.
- The prompt mirrors the README “Agent-assisted fix loop prompt” but replaces CLI usage with MCP tool invocation instructions.

## Testing
- Add a test that requests the MCP prompt and asserts the prompt name and static content.
- Add an integration test that runs tooltest against itself (stdio test server) using the MCP tool path.

## Trade-offs
- Centralizing config in `tooltest-core` expands the public API but ensures consistency across CLI and MCP usage.
