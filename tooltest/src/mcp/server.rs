use rmcp::handler::server::common::schema_for_type;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    AnnotateAble, CallToolRequestParam, CallToolResult, GetPromptRequestParam, GetPromptResult,
    JsonObject, ListPromptsResult, ListResourcesResult, ListToolsResult, PaginatedRequestParam,
    Prompt, PromptMessage, PromptMessageContent, PromptMessageRole, RawResource,
    ReadResourceRequestParam, ReadResourceResult, Resource, ResourceContents, Tool,
};
use rmcp::transport::stdio;
use rmcp::{ErrorData, RoleServer, ServiceExt};
use serde_json::{json, Value as JsonValue};

use super::{schema, transport, worker};

pub(super) const TOOLTEST_TOOL_NAME: &str = "tooltest";
pub(super) const TOOLTEST_TOOL_DESCRIPTION: &str =
    "Run tooltest against an MCP server using the shared tooltest input.";
pub(super) const TOOLTEST_FIX_LOOP_PROMPT_NAME: &str = "tooltest-fix-loop";
pub(super) const TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION: &str =
    "Guidance for iterating on tooltest failures in MCP servers.";
pub(super) const TOOLTEST_FIX_LOOP_RESOURCE_URI: &str = "tooltest://guides/fix-loop";
const TOOLTEST_FIX_LOOP_RESOURCE_NAME: &str = "tooltest-fix-loop";
const TOOLTEST_FIX_LOOP_RESOURCE_DESCRIPTION: &str =
    "Step-by-step guidance for running tooltest to fix MCP issues.";
pub(super) const TOOLTEST_FIX_LOOP_PROMPT: &str = r#"You have access to this repository and can run commands.
Goal: make the repository's MCP server(s) conform to the MCP spec as exercised by tooltest.

Figure out how to start the MCP server from this repo (stdio or streamable HTTP).

Select a small, related subset of tools intended to be used together. Default to testing at most 50 tools at a time, and strongly prefer a smaller group. Use `--tool-allowlist` (or `tool_allowlist` in MCP input) to enforce this.

Run tooltest against it and fix failures until it exits 0.

If you see "state-machine generator failed to reach minimum sequence length", re-run with `--lenient-sourcing` or seed values in `--state-machine-config`.

CLI usage (preferred when you can run commands):
- Use CLI-only flags for debugging, e.g. `--trace-all /tmp/tooltest-traces.jsonl`.
- Examples:
  CLI stdio (allowlist example): tooltest stdio --command "<command that starts the repo's MCP server>" --tool-allowlist foo --tool-allowlist bar
  CLI http (allowlist example): tooltest http --url "http://127.0.0.1:9000/mcp" --tool-allowlist foo --tool-allowlist bar

MCP tool usage (when you must call via MCP):
- Call the `tooltest` tool with the shared input schema.
- Only fields in the MCP input schema are accepted (CLI-only flags like `--json` and `--trace-all` are not supported).
- Example (allowlist):
{
  "target": { "stdio": { "command": "<command that starts the repo's MCP server>" } },
  "tool_allowlist": ["foo", "bar"]
}

Don't rename tools or change schemas unless required; prefer backward-compatible fixes.

Add/adjust tests if needed.

Return a short summary of what you changed and why, plus the final passing tooltest output snippet.
"#;

fn exit_immediately() -> bool {
    std::env::var_os("TOOLTEST_MCP_EXIT_IMMEDIATELY").is_some()
}

fn use_test_transport() -> bool {
    std::env::var_os("TOOLTEST_MCP_TEST_TRANSPORT").is_some()
}

#[derive(Clone, Default)]
pub(super) struct McpServer;

impl McpServer {
    pub(super) fn new() -> Self {
        Self
    }
}

impl ServerHandler for McpServer {
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListToolsResult {
            tools: vec![tooltest_tool()],
            ..Default::default()
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_
    {
        let name = request.name;
        let arguments = request.arguments;
        async move {
            if name.as_ref() != TOOLTEST_TOOL_NAME {
                return Err(ErrorData::invalid_params(
                    format!("tool '{name}' not found"),
                    Some(json!({ "available_tools": [TOOLTEST_TOOL_NAME] })),
                ));
            }
            let input = parse_tooltest_input(arguments)?;
            worker::run_tooltest_call(worker::tooltest_worker().await, input).await
        }
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListPromptsResult {
            prompts: vec![fix_loop_prompt()],
            ..Default::default()
        }))
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetPromptResult, rmcp::ErrorData>> + Send + '_
    {
        let name = request.name;
        std::future::ready(if name == TOOLTEST_FIX_LOOP_PROMPT_NAME {
            Ok(fix_loop_prompt_result())
        } else {
            Err(prompt_not_found_error(&name))
        })
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_
    {
        std::future::ready(Ok(ListResourcesResult {
            resources: vec![fix_loop_resource()],
            ..Default::default()
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, rmcp::ErrorData>> + Send + '_
    {
        let uri = request.uri;
        std::future::ready(if uri == TOOLTEST_FIX_LOOP_RESOURCE_URI {
            Ok(ReadResourceResult {
                contents: vec![fix_loop_resource_contents()],
            })
        } else {
            Err(ErrorData::resource_not_found(
                format!("resource '{uri}' not found"),
                None,
            ))
        })
    }
}

fn tooltest_tool() -> Tool {
    Tool {
        name: TOOLTEST_TOOL_NAME.into(),
        title: None,
        description: Some(TOOLTEST_TOOL_DESCRIPTION.into()),
        input_schema: schema::tooltest_input_schema(),
        output_schema: Some(schema_for_type::<tooltest_core::RunResult>()),
        annotations: None,
        icons: None,
        meta: None,
    }
}

fn fix_loop_prompt() -> Prompt {
    Prompt::new(
        TOOLTEST_FIX_LOOP_PROMPT_NAME,
        Some(TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION),
        None,
    )
}

fn fix_loop_prompt_result() -> GetPromptResult {
    GetPromptResult {
        description: Some(TOOLTEST_FIX_LOOP_PROMPT_DESCRIPTION.to_string()),
        messages: vec![PromptMessage {
            role: PromptMessageRole::User,
            content: PromptMessageContent::Text {
                text: TOOLTEST_FIX_LOOP_PROMPT.to_string(),
            },
        }],
    }
}

fn prompt_not_found_error(name: &str) -> ErrorData {
    ErrorData::invalid_params(
        format!("prompt '{name}' not found"),
        Some(json!({ "available_prompts": [TOOLTEST_FIX_LOOP_PROMPT_NAME] })),
    )
}

fn fix_loop_resource() -> Resource {
    RawResource {
        uri: TOOLTEST_FIX_LOOP_RESOURCE_URI.to_string(),
        name: TOOLTEST_FIX_LOOP_RESOURCE_NAME.to_string(),
        title: None,
        description: Some(TOOLTEST_FIX_LOOP_RESOURCE_DESCRIPTION.to_string()),
        mime_type: Some("text/plain".to_string()),
        size: None,
        icons: None,
        meta: None,
    }
    .no_annotation()
}

fn fix_loop_resource_contents() -> ResourceContents {
    ResourceContents::TextResourceContents {
        uri: TOOLTEST_FIX_LOOP_RESOURCE_URI.to_string(),
        mime_type: Some("text/plain".to_string()),
        text: TOOLTEST_FIX_LOOP_PROMPT.to_string(),
        meta: None,
    }
}

fn parse_tooltest_input(
    arguments: Option<JsonObject>,
) -> Result<tooltest_core::TooltestInput, ErrorData> {
    let arguments =
        arguments.ok_or_else(|| ErrorData::invalid_params("tooltest input is required", None))?;
    serde_json::from_value(JsonValue::Object(arguments)).map_err(|error| {
        ErrorData::invalid_params(format!("invalid tooltest input: {error}"), None)
    })
}

pub(super) async fn run_stdio() -> Result<(), String> {
    let exit_immediately = exit_immediately();
    let service = if use_test_transport() {
        let transport = if std::env::var_os("TOOLTEST_MCP_BAD_TRANSPORT").is_some() {
            transport::stdio_bad_transport()
        } else if std::env::var_os("TOOLTEST_MCP_PANIC_TRANSPORT").is_some() {
            transport::stdio_panic_transport()
        } else {
            transport::stdio_test_transport()
        };
        McpServer::new()
            .serve(transport)
            .await
            .map_err(|error| format!("failed to start MCP stdio server: {error}"))?
    } else {
        McpServer::new()
            .serve(stdio())
            .await
            .map_err(|error| format!("failed to start MCP stdio server: {error}"))?
    };
    if exit_immediately {
        if std::env::var_os("TOOLTEST_MCP_PANIC_TRANSPORT").is_some() {
            tokio::task::yield_now().await;
        }
        service
            .cancel()
            .await
            .map_err(|error| format!("MCP stdio server failed: {error}"))?;
        return Ok(());
    }
    service
        .waiting()
        .await
        .map_err(|error| format!("MCP stdio server failed: {error}"))?;
    Ok(())
}
