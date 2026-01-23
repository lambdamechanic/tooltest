# Change: Add MCP mode to tooltest

## Why
Tooltest currently runs only as a CLI, which makes it harder to integrate with MCP-native workflows. Adding an MCP mode lets tooltest be invoked as a tool from MCP clients while keeping the CLI behavior consistent.

## What Changes
- Add a `tooltest mcp` subcommand that exposes tooltest as an MCP server.
- Support `--stdio` and `--http` transport modes for the MCP server, defaulting to stdio.
- Centralize tooltest input configuration into a public `tooltest-core` type shared by CLI and MCP modes.
- Add an MCP prompt that mirrors the README “fix loop” prompt, updated to call the MCP tool.
- Add tests covering the MCP prompt and running tooltest-against-tooltest via the stdio test server.

## Impact
- Affected specs: tooltest-mcp-mode (new), mcp-sequence-runner (indirect via shared config type).
- Affected code: `tooltest` CLI, MCP server entry point, shared config in `tooltest-core`, tests.
