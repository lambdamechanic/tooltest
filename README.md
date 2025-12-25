# tooltest

## CLI

The `tooltest` binary wraps `tooltest-core` with stdio/HTTP runners.

```bash
cargo install --path tooltest-cli
tooltest stdio --command ./mcp-server --arg --foo --env FOO=bar --cwd /tmp
tooltest http --url http://127.0.0.1:8080/mcp --auth-token "Bearer token"
```

Output is JSON on stdout. Exit codes are:
- `0` on success
- `1` on run failure
- `2` on argument/validation errors

## Hosted MCP integration tests

By default the hosted MCP integration test runs and exercises the three public MCP servers used for validation. To skip it:

```bash
SKIP_HOSTED_MCP_TESTS=1 cargo test -p tooltest-core --test hosted_mcp_tests
```

## Verbose rmcp tracing

The tests install a tracing subscriber that emits to stderr. Use `RUST_LOG` plus `--nocapture` to see the full interaction.

```bash
RUST_LOG=rmcp=trace cargo test -p tooltest-core --test hosted_mcp_tests -- --nocapture
```

## External Rust test example

This is an example integration test in another crate that uses `tooltest-core` to exercise a hosted MCP HTTP endpoint.

```rust
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use tooltest_core::{SessionDriver, ToolInvocation};

#[tokio::test]
async fn calls_hosted_tool() {
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri("https://pymcp.app.lambdamechanic.com/attack/mcp"),
    );
    let driver = SessionDriver::connect_with_transport(transport)
        .await
        .expect("connect");

    let invocation = ToolInvocation {
        name: "some_tool".into(),
        arguments: None,
    };

    let trace = driver.send_tool_call(invocation).await.expect("call tool");
    assert_eq!(trace.response.is_error, Some(false));
}
```
