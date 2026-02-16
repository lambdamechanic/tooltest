# Change: Remove `nullable` keyword from JSON Schema output

## Why
The tooltest MCP server produces JSON schemas that include the `nullable` keyword, which is not part of the JSON Schema 2020-12 specification. This causes compatibility issues with strict JSON Schema validators like mcporter, which reports: `"nullable" cannot be used without "type"`.

The `nullable` keyword is an OpenAPI 3.0 extension, not a JSON Schema keyword. When using JSON Schema 2020-12, nullable types should be represented using `{"type": ["string", "null"]}` or `anyOf`/`oneOf` patterns without the `nullable` keyword.

## Dogfooding Gap
The existing lints do NOT catch non-standard keywords:
- `json_schema_dialect_compat` only checks `$schema` values against an allowlist
- `json_schema_keyword_compat` only checks `$defs` usage in legacy schemas
- No lint validates that keywords are valid for the declared schema dialect

This change adds a lint to catch non-standard keywords in JSON Schema 2020-12.

## Upstream Status
Checked rmcp GitHub (modelcontextprotocol/rust-sdk):
- Current tooltest uses `rmcp = "0.12"`, latest is `0.15.0`
- PR #549 switched to `SchemaSettings::draft2020_12()` but **kept `AddNullable::default()`**
- The `nullable` issue is **NOT fixed** in newer rmcp versions
- No open issue exists about `nullable` being non-compliant with JSON Schema 2020-12

The fix requires changes in two places:
1. **Local**: `tooltest/src/mcp/schema.rs` generates inputSchema with `AddNullable`
2. **Upstream**: `rmcp::handler::server::common::schema_for_type()` generates outputSchema with `AddNullable`

## What Changes
- Remove the `AddNullable` transform from local schema generation in `tooltest/src/mcp/schema.rs`
- Add post-processing step to strip `nullable` keywords from outputSchema (workaround for rmcp upstream, documented as such)
- Add a lint (`json_schema_non_standard_keywords`) to catch non-standard keywords in JSON Schema 2020-12
- Enable the new lint in the repo's `tooltest.toml`
- File upstream issue with rmcp to remove `AddNullable` from JSON Schema 2020-12 generation

## Impact
- Affected specs: mcp-server (new capability spec)
- Affected code: `tooltest/src/mcp/schema.rs`, `tooltest/src/mcp/server.rs`, `tooltest-core/src/lints.rs`
- **Breaking change**: No - this makes the schemas more compliant, not less
- External tools: mcporter and other strict JSON Schema validators will now work with tooltest
- Upstream: New issue/PR to modelcontextprotocol/rust-sdk
