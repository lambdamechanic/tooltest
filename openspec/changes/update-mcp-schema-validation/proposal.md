## Why
Tool schema validation currently enforces constraints tighter than the upstream MCP specification (e.g., rejecting non‑2020‑12 $schema values). This blocks valid MCP servers and diverges from the official schema.

## What Changes
- Validate MCP payloads directly against the official MCP schema for the supported protocol version.
- Remove bespoke tool schema checks and schema version gating in parsing.
- Validate tools/call request params using MCP schema definitions.

## Impact
- Accepts valid MCP servers that advertise non‑2020‑12 $schema values in tool schemas.
- Parsing errors are driven by MCP schema conformance.
- Removes UnsupportedSchemaVersion/InvalidToolSchema errors from the API surface.
