# Change: Add tooltest core package and MCP sequence runner

## Why
Tooltest needs a shared Rust core that can run valid MCP sequences against stdio or HTTP endpoints while being consumable from Node and Python packages.

## What Changes
- Create a Rust core library package that drives MCP sessions and generates tool invocations based on MCP schemas.
- Add a minimal FFI surface so Node (napi) and Python (pyo3) wrappers can call into the core.
- Define MCP sequence generation behavior, including initialization, tool eligibility filtering, default assertions, and proptest minimization output.
- Include optional configurable HTTP auth header support for MCP endpoints.

## Impact
- Affected specs: mcp-sequence-runner, ffi-bindings
- Affected code: new Rust workspace packages (core library and FFI layer)
