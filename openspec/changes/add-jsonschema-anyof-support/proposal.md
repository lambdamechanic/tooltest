# Change: Add anyOf/union support for tool input schema generation

## Why
Some MCP servers define tool input schemas using `anyOf` or nullable unions (e.g. `string | null`). The current generator rejects these schemas, preventing state-machine runs against valid MCP servers.

## What Changes
- Add generator and constraint handling for `anyOf` (and type unions) in tool input schemas.
- Ensure schema validation and error reporting treat `anyOf` as supported when its branches are supported.
- Add tests for nullable and multi-branch unions.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: tooltest-core/src/generator.rs, tooltest-core/tests/*
