# Change: Add MCP mode to tooltest

## Why
Tooltest currently runs only as a CLI, which makes it harder to integrate with MCP-native workflows. Adding an MCP mode lets tooltest be invoked as a tool from MCP clients while keeping the CLI behavior consistent.

## What Changes
- Add a `tooltest mcp` subcommand that exposes tooltest as an MCP server.
- Support explicit `--stdio` and `--http` transport modes (mutually exclusive), defaulting to stdio and requiring `--bind` for HTTP.
- Centralize tooltest input configuration into a public `tooltest-core` type shared by CLI and MCP modes.
- Return `RunResult` for tooltest completion outcomes; unexpected tooltest errors surface as MCP errors.
- Add an MCP prompt and static resource with MCP-specific fix-loop guidance (tool subset selection, MCP/CLI options).
- Add tests covering the MCP prompt/resource and running tooltest-against-tooltest via the stdio test server.

## Impact
- Affected specs: tooltest-mcp-mode (new), mcp-sequence-runner (indirect via shared config type and run result semantics).
- Affected code: `tooltest` CLI, MCP server entry point, shared config in `tooltest-core`, tests.
