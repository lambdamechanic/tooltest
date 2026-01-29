---
name: tooltest-fix-loop
description: Use when running tooltest to validate MCP servers, interpret failures, and iterate fixes in this repo.
---

# Tooltest fix loop

## Goal

Make the repository's MCP server(s) conform to the MCP spec as exercised by tooltest.

## Workflow

- Figure out how to start the MCP server from this repo (stdio or streamable HTTP).
- Select a small, related subset of tools intended to be used together.
- Default to testing at most 50 tools and strongly prefer a smaller group.
- Use an allowlist to constrain the tool set (CLI: `--tool-allowlist`, MCP: `tool_allowlist`).
- Run tooltest via the CLI or the MCP tool; pass the same options in either path.
- Fix the smallest reasonable patch for any failures and re-run tooltest until it exits 0.

## Notes

- If you see "state-machine generator failed to reach minimum sequence length", re-run with `--lenient-sourcing` or seed values in `--state-machine-config`.
- For per-case traces, add `--trace-all /tmp/tooltest-traces.jsonl` (any writable path).
- Don't rename tools or change schemas unless required; prefer backward-compatible fixes.
- Add or adjust tests when needed.

## Commands (examples)

- CLI stdio (allowlist example): `tooltest stdio --command "<command that starts the repo's MCP server>" --tool-allowlist foo --tool-allowlist bar`
- CLI http (allowlist example): `tooltest http --url "http://127.0.0.1:9000/mcp" --tool-allowlist foo --tool-allowlist bar`
- MCP tool (allowlist example):

```json
{
  "target": { "stdio": { "command": "<command that starts the repo's MCP server>" } },
  "tool_allowlist": ["foo", "bar"]
}
```

## Reporting

- Return a short summary of what you changed and why.
- Include the final passing tooltest output snippet.
