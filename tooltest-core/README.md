# tooltest-core

Internal crate providing the tooltest runner and MCP testing primitives.

This crate is primarily intended for tooltest's own use and may change without
notice. End users should install the `tooltest` CLI instead.

Run configuration supports optional tool-name filtering via `ToolNamePredicate`
and `RunConfig::with_tool_filter` for limiting which tools are eligible for
generation in core tests.

## Core API

The core API is built around `RunConfig`, `RunnerOptions`, and the transport helpers
`run_stdio`/`run_http`. The configuration holds schema settings, state-machine
generation options, and assertion rules.

```rust
use tooltest_core::{run_stdio, RunConfig, RunOutcome, RunnerOptions, StdioConfig};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let endpoint = StdioConfig::new("./path/to/server");
let config = RunConfig::new();
let options = RunnerOptions::default();

let result = run_stdio(&endpoint, &config, options).await;
assert!(matches!(result.outcome, RunOutcome::Success));
# Ok(())
# }
```

For custom transport workflows, use `SessionDriver` plus `run_with_session` to
reuse an existing MCP connection.

## Tool enumeration and validation helpers

The validation module provides helpers for listing tools with schema validation and
for bulk tool validation. The default per-tool case count is controlled by
`TOOLTEST_CASES_PER_TOOL` and can be overridden via `ToolValidationConfig`.

```rust
use tooltest_core::{
    list_tools_stdio, validate_tools, SchemaConfig, SessionDriver, StdioConfig, ToolValidationConfig,
};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let config = StdioConfig::new("./path/to/server");
let tools = list_tools_stdio(&config, &SchemaConfig::default()).await?;
println!("tool count: {}", tools.len());

let session = SessionDriver::connect_stdio(&config).await?;
let validation = ToolValidationConfig::new().with_cases_per_tool(10);
let summary = validate_tools(&session, &validation, None).await?;
println!("validated {} tools", summary.tools.len());
# Ok(())
# }
```

## JSON DSL

Assertions can be expressed as structured JSON for FFI use. The JSON DSL mirrors
the `AssertionSet`/`AssertionRule` types and uses RFC 6901 JSON Pointer strings
to select values.

Example JSON assertions:

```json
{
  "rules": [
    {
      "scope": "response",
      "rule": {
        "tool": "echo",
        "checks": [
          {
            "target": "structured_output",
            "pointer": "/status",
            "expected": "ok"
          }
        ]
      }
    }
  ]
}
```

When deserialized, the JSON payload maps directly to `AssertionSet`.

## Schema usage

Tooltest validates MCP payloads against the configured MCP schema version
(default: 2025-11-25) before generating invocations. Tool input schemas must be
objects; the state-machine generator derives tool calls from those schemas and
uses corpus values for required fields unless `lenient_sourcing` is enabled.

Tool output schemas are validated when structured output is present. If the tool
schema omits `$schema`, the output schema defaults to JSON Schema 2020-12.
Supported `$schema` values include drafts 2020-12, 2019-09, 7, 6, and 4.
