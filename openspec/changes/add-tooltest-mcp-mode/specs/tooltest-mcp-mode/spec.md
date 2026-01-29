## ADDED Requirements

### Requirement: MCP server entry point
The system SHALL provide a `tooltest mcp` entry point that runs a tooltest MCP server with explicit transport selection.

#### Scenario: MCP stdio server defaults to stdio
- **WHEN** `tooltest mcp` is invoked without `--stdio` or `--http`
- **THEN** the MCP server starts using stdio transport

#### Scenario: MCP stdio server accepts explicit flag
- **WHEN** `tooltest mcp --stdio` is invoked
- **THEN** the MCP server starts using stdio transport

#### Scenario: MCP http server requires bind address
- **WHEN** `tooltest mcp --http` is invoked without `--bind`
- **THEN** the command fails with an argument error

#### Scenario: MCP http server binds to provided address
- **WHEN** `tooltest mcp --http --bind 127.0.0.1:9000` is invoked
- **THEN** the MCP server binds to `127.0.0.1:9000`

#### Scenario: MCP http server exposes /mcp endpoint
- **WHEN** `tooltest mcp --http --bind 127.0.0.1:9000` is invoked
- **THEN** the MCP server serves the MCP endpoint at `http://127.0.0.1:9000/mcp`

#### Scenario: MCP transport flags are mutually exclusive
- **WHEN** `tooltest mcp --stdio --http` is invoked
- **THEN** the command fails with an argument error

#### Scenario: MCP stdio server rejects bind address
- **WHEN** `tooltest mcp --stdio --bind 127.0.0.1:9000` is invoked
- **THEN** the command fails with an argument error

### Requirement: MCP tool for running tooltest
The MCP server SHALL expose a tool named `tooltest` that executes a tooltest run from a shared tooltest input payload and returns a `RunResult` for tooltest completion outcomes.

#### Scenario: MCP tool uses shared input type
- **WHEN** the MCP tool receives a tooltest input payload
- **THEN** the run configuration is derived from the shared tooltest input type used by the CLI

#### Scenario: MCP tool runs tooltest against a stdio server
- **WHEN** the MCP tool is invoked with a stdio target
- **THEN** tooltest runs against the stdio MCP endpoint and returns the run result

#### Scenario: MCP tool runs tooltest against an HTTP server
- **WHEN** the MCP tool is invoked with an HTTP target
- **THEN** tooltest runs against the HTTP MCP endpoint and returns the run result

#### Scenario: MCP tool returns RunResult on run failure
- **WHEN** a tooltest run fails due to assertion failures or tool errors
- **THEN** the MCP tool returns a `RunResult` with a failure outcome (not an MCP error)

#### Scenario: MCP tool returns RunResult on target connection failure
- **WHEN** the MCP target connection fails during a tooltest run
- **THEN** the MCP tool returns a `RunResult` with a failure outcome (not an MCP error)

#### Scenario: MCP tool reports internal tooltest errors
- **WHEN** tooltest fails unexpectedly before producing a `RunResult`
- **THEN** the MCP tool call fails with an MCP error (or JSON-RPC error)

#### Scenario: MCP tool returns RunResult in structuredContent
- **WHEN** the MCP tool completes and returns a `RunResult`
- **THEN** the MCP response sets `isError` to `false`, includes the `RunResult` in `structuredContent`, and sets `content` to the JSON string representation of `structuredContent`

#### Scenario: MCP tool smoke test
- **WHEN** the MCP tool runs against the stdio test server with 50 cases
- **THEN** the run completes without crashing and returns a `RunResult` payload

### Requirement: Shared tooltest input configuration
The system SHALL define a public tooltest input type in `tooltest-core` that is used by both CLI and MCP modes and preserves CLI semantics.

#### Scenario: CLI uses shared tooltest input type
- **WHEN** CLI arguments are parsed
- **THEN** the tooltest run is configured via the shared tooltest input type

#### Scenario: MCP tool uses shared tooltest input type
- **WHEN** the MCP tool receives input
- **THEN** it uses the same input type as the CLI to configure the run

#### Scenario: Shared input reflects CLI options
- **WHEN** the shared input type is defined
- **THEN** it includes fields corresponding to all CLI options (required and optional), structured into nested objects, with defaults matching the CLI defaults

#### Scenario: Shared input uses canonical JSON field names
- **WHEN** the shared input is serialized for MCP tool usage
- **THEN** it uses snake_case field names that match CLI long flags (for example `tool_allowlist`, `tool_blocklist`, `min_sequence_len`, `max_sequence_len`, `state_machine_config`, `pre_run_hook`, `trace_all`) and the transport is represented as `target.stdio.command` or `target.http.url`

#### Scenario: Shared input requires explicit target
- **WHEN** the MCP tool input omits `target`
- **THEN** the tool fails validation with an argument error

#### Scenario: Shared input rejects top-level stdio shorthand
- **WHEN** the MCP tool input includes a top-level `stdio` object outside of `target`
- **THEN** the tool fails validation with an argument error

#### Scenario: Shared input stdio env uses map form
- **WHEN** the shared input includes `target.stdio.env`
- **THEN** it is expressed as a JSON object mapping keys to values (not a list of `KEY=VALUE` strings)

#### Scenario: Shared input pre-run hook env uses map form
- **WHEN** the shared input includes `pre_run_hook.env`
- **THEN** it is expressed as a JSON object mapping keys to values (not a list of `KEY=VALUE` strings)

#### Scenario: Shared input state machine config uses structured object
- **WHEN** the shared input includes `state_machine_config`
- **THEN** it is a JSON object matching `tooltest_core::StateMachineConfig` fields (`seed_numbers`, `seed_strings`, `mine_text`, `dump_corpus`, `log_corpus_deltas`, `lenient_sourcing`, `coverage_allowlist`, `coverage_blocklist`, `coverage_rules`)

#### Scenario: HTTP targets use full URLs
- **WHEN** an HTTP target is configured in the shared input
- **THEN** the target URL is a full URL (scheme and host), matching CLI `--url` requirements

#### Scenario: Shared input validation matches CLI
- **WHEN** the shared input type is validated
- **THEN** required fields and validation errors match the CLI required arguments and error semantics for the same inputs

### Requirement: MCP prompt and resource for tooltest guidance
The MCP server SHALL provide a static prompt named `tooltest-fix-loop` and a static resource to guide tooltest usage.

#### Scenario: Prompt content is a static literal
- **WHEN** the MCP client requests `tooltest-fix-loop`
- **THEN** the prompt content is a static literal and does not rely on pulling content from `README.md`

#### Scenario: Prompt advises tool subset selection
- **WHEN** the MCP client requests `tooltest-fix-loop`
- **THEN** the prompt content instructs selecting a subset of tools intended to be used together and suggests a maximum of 50 tools, while strongly recommending a smaller group

#### Scenario: Prompt supports MCP and CLI usage
- **WHEN** the MCP client requests `tooltest-fix-loop`
- **THEN** the prompt content explains that tooltest can be invoked via the MCP tool or via the CLI, and to pass the same options in either path

#### Scenario: Prompt includes explicit allowlist examples
- **WHEN** the MCP client requests `tooltest-fix-loop`
- **THEN** the prompt content includes one CLI example using `--tool-allowlist` and one MCP example showing the same allowlist in the tool input

#### Scenario: Prompt literal text
- **WHEN** the MCP client requests `tooltest-fix-loop`
- **THEN** the prompt content equals:

```text
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

CLI stdio (allowlist example): tooltest stdio --command "<command that starts the repo's MCP server>" --tool-allowlist foo --tool-allowlist bar

CLI http (allowlist example): tooltest http --url "http://127.0.0.1:9000/mcp" --tool-allowlist foo --tool-allowlist bar

MCP tool (allowlist example):
{
  "target": { "stdio": { "command": "<command that starts the repo's MCP server>" } },
  "tool_allowlist": ["foo", "bar"]
}

Return a short summary of what you changed and why, plus the final passing tooltest output snippet.
```

#### Scenario: Resource appears in resource listing
- **WHEN** the MCP client requests `resources/list`
- **THEN** the response includes a resource with URI `tooltest://guides/fix-loop`, a description of its purpose, and `mimeType` set to `text/plain`

#### Scenario: Resource content is static
- **WHEN** the MCP client requests `resources/read` for `tooltest://guides/fix-loop`
- **THEN** the response includes static text content matching the `tooltest-fix-loop` prompt with `mimeType` set to `text/plain`

### Requirement: MCP capability defaults
The MCP server SHALL provide sensible defaults for standard MCP requests.

#### Scenario: tools/list returns the tooltest tool
- **WHEN** the MCP client requests `tools/list`
- **THEN** the response includes the `tooltest` tool with a description of its purpose and input schema

#### Scenario: prompts/list returns the fix loop prompt
- **WHEN** the MCP client requests `prompts/list`
- **THEN** the response includes `tooltest-fix-loop` with a description

#### Scenario: prompts/get returns the fix loop prompt content
- **WHEN** the MCP client requests `prompts/get` for `tooltest-fix-loop`
- **THEN** the response includes the static prompt content

#### Scenario: resources/list returns the fix loop resource
- **WHEN** the MCP client requests `resources/list`
- **THEN** the response includes `tooltest://guides/fix-loop` with a description and `mimeType` set to `text/plain`

#### Scenario: resources/read returns the fix loop resource content
- **WHEN** the MCP client requests `resources/read` for `tooltest://guides/fix-loop`
- **THEN** the response includes the static resource content with `mimeType` set to `text/plain`

#### Scenario: prompts/get unknown prompt follows standard behavior
- **WHEN** the MCP client requests `prompts/get` with an unknown prompt name
- **THEN** the server responds with the standard MCP error behavior for unknown prompts

#### Scenario: resources/read unknown URI follows standard behavior
- **WHEN** the MCP client requests `resources/read` with an unknown resource URI
- **THEN** the server responds with the standard MCP error behavior for unknown resources
