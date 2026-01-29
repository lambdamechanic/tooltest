# Change: Add tooltest core package and MCP sequence runner

## Why
Tooltest needs a shared Rust core that can run valid MCP sequences against stdio or HTTP endpoints and serve as the foundation for the CLI.

## What Changes
- Create a Rust core library package that drives MCP sessions and generates tool invocations based on MCP schemas.
- Define MCP sequence generation behavior, including initialization, tool eligibility filtering, default assertions, and proptest minimization output.
- Include optional configurable HTTP auth token support for MCP endpoints.
- Adopt the `rmcp` SDK for JSON-RPC/MCP protocol types and error shapes in the core runner.
- **BREAKING**: Replace custom session and transport primitives with `rmcp` session/transport APIs.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: new Rust workspace packages (core library and CLI wrapper)
