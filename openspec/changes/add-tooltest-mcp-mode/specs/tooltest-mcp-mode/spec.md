## ADDED Requirements

### Requirement: MCP server entry point
The system SHALL provide a `tooltest mcp` entry point that runs a tooltest MCP server.

#### Scenario: MCP stdio server defaults to stdio
- **WHEN** `tooltest mcp` is invoked without `--http`
- **THEN** the MCP server starts using stdio transport

#### Scenario: MCP http server requires bind address
- **WHEN** `tooltest mcp --http` is invoked without `--bind`
- **THEN** the command fails with an argument error

#### Scenario: MCP http server binds to provided address
- **WHEN** `tooltest mcp --http --bind 127.0.0.1:9000` is invoked
- **THEN** the MCP server binds to `127.0.0.1:9000`

### Requirement: MCP tool for running tooltest
The MCP server SHALL expose a tool named `tooltest` that executes a tooltest run from a shared tooltest input payload.

#### Scenario: MCP tool uses shared input type
- **WHEN** the MCP tool receives a tooltest input payload
- **THEN** the run configuration is derived from the shared tooltest input type used by the CLI

#### Scenario: MCP tool runs tooltest against a stdio server
- **WHEN** the MCP tool is invoked with a stdio target
- **THEN** tooltest runs against the stdio MCP endpoint and returns the run result

#### Scenario: MCP tool smoke test
- **WHEN** the MCP tool runs against the stdio test server with 50 cases
- **THEN** the run completes without crashing and returns a `RunResult` payload

### Requirement: Shared tooltest input configuration
The system SHALL define a public tooltest input type in `tooltest-core` that is used by both CLI and MCP modes.

#### Scenario: CLI uses shared tooltest input type
- **WHEN** CLI arguments are parsed
- **THEN** the tooltest run is configured via the shared tooltest input type

#### Scenario: MCP tool uses shared tooltest input type
- **WHEN** the MCP tool receives input
- **THEN** it uses the same input type as the CLI to configure the run

#### Scenario: Shared input reflects CLI options
- **WHEN** the shared input type is defined
- **THEN** it includes fields corresponding to all CLI options (required and optional), structured into nested objects

#### Scenario: Required fields match CLI requirements
- **WHEN** the shared input type is validated
- **THEN** required fields match the CLI required arguments and optional fields remain optional

### Requirement: MCP prompt for fix loop guidance
The MCP server SHALL provide a static prompt named `tooltest-fix-loop` that matches the README fix loop prompt with MCP tool usage.

#### Scenario: Prompt appears in prompt listing
- **WHEN** the MCP client requests the prompt list
- **THEN** the list includes `tooltest-fix-loop`

#### Scenario: Prompt content uses MCP tool
- **WHEN** the MCP client requests `tooltest-fix-loop`
- **THEN** the prompt content instructs invoking the `tooltest` MCP tool (not the CLI)

#### Scenario: Prompt text matches README body
- **WHEN** the prompt is rendered
- **THEN** it uses the text under “Paste this into your coding agent” from `README.md`, with CLI invocation replaced by MCP tool usage

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
