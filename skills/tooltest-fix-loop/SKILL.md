---
name: tooltest-fix-loop
description: Use when running tooltest to validate MCP servers, interpret failures, and iterate fixes in this repo.
---

# Tooltest fix loop

## Run tooltest and iterate

- Identify how to start the repo’s MCP server (stdio or streamable HTTP).
- Run tooltest against it:
  - `tooltest stdio --command "<server start command>"`
  - `tooltest http --url "<server mcp url>"`
- Read the failure report, trace the failing tool call or protocol step, and fix the smallest viable patch.
- Re-run tooltest until it exits 0; keep tool names and schemas stable unless a spec violation requires change.

## Triage guidance

- Treat failures as either protocol handling, tool schema validation, or runtime behavior; fix in that order.
- Prefer backward-compatible fixes; add a regression test when a failure is deterministic or easy to reproduce.
- When the failure is intermittent, keep the smallest reproduction from the report and turn it into a test.

## Reporting

- Summarize the changes and why they address the specific tooltest failures.
- Include the final passing tooltest output snippet.
