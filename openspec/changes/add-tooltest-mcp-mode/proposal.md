# Change: Add MCP mode to tooltest

## Why
Tooltest currently runs only as a CLI, which makes it harder to integrate with MCP-native workflows. Adding an MCP mode lets tooltest be invoked as a tool from MCP clients while keeping the CLI behavior consistent.

## What Changes
- Add a `tooltest mcp` subcommand that exposes tooltest as an MCP server.
- Support stdio-only transport for `tooltest mcp` (HTTP server mode is intentionally unsupported).
- Centralize tooltest input configuration into a public `tooltest-core` type shared by CLI and MCP modes.
- Return `RunResult` for tooltest completion outcomes; unexpected tooltest errors surface as MCP errors.
- Add an MCP prompt and static resource with fix-loop guidance (tool subset selection, CLI vs MCP usage).
- Add tests covering the MCP prompt/resource and running tooltest-against-tooltest via the stdio test server.

## Impact
- Affected specs: tooltest-mcp-mode (new), mcp-sequence-runner (indirect via shared config type and run result semantics).
- Affected code: `tooltest` CLI, MCP server entry point, shared config in `tooltest-core`, tests.
