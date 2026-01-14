# tooltest-core

Internal crate providing the tooltest runner and MCP testing primitives.

This crate is primarily intended for tooltest's own use and may change without
notice. End users should install the `tooltest` CLI instead.

Run configuration supports optional tool-name filtering via `ToolNamePredicate`
and `RunConfig::with_tool_filter` for limiting which tools are eligible for
generation in core tests.
