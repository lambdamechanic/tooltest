---
name: tooltest-fix-loop
description: Use when running tooltest to validate MCP servers, interpret failures, and iterate fixes in this repo.
---

# Tooltest fix loop

You have access to this repository and can run commands.

Goal: make the repository's MCP server(s) conform to the MCP spec as exercised by tooltest.

Figure out how to start the MCP server from this repo (stdio or streamable HTTP).

Select a small, related subset of tools intended to be used together. Default to testing at most 50 tools at a time, and strongly prefer a smaller group. Use `--tool-allowlist` (or `tool_allowlist` in MCP input) to enforce this.

Run tooltest against it (examples below).

When tooltest reports failures, fix the underlying issues in the smallest reasonable patch.

Re-run tooltest and repeat until it exits 0.

If you see "state-machine generator failed to reach minimum sequence length", re-run with `--lenient-sourcing` or seed values in `--state-machine-config`.

If you need per-case traces for debugging, add `--trace-all /tmp/tooltest-traces.jsonl` (any writable path).

If you are invoking tooltest via the MCP tool instead of the CLI, pass the same options in the tool input.

Don't rename tools or change schemas unless required; prefer backward-compatible fixes.

Add/adjust tests if needed.

Commands (choose the right one):

CLI stdio (allowlist example): `tooltest stdio --command "<command that starts the repo's MCP server>" --tool-allowlist foo --tool-allowlist bar`

CLI http (allowlist example): `tooltest http --url "http://127.0.0.1:9000/mcp" --tool-allowlist foo --tool-allowlist bar`

MCP tool (allowlist example):

```json
{
  "target": { "stdio": { "command": "<command that starts the repo's MCP server>" } },
  "tool_allowlist": ["foo", "bar"]
}
```

Return a short summary of what you changed and why, plus the final passing tooltest output snippet.
