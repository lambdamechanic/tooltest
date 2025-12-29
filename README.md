# tooltest

**Conformance testing for MCP servers — fast enough for the CLI, solid enough for CI.**

`tooltest` runs your MCP server like a real client/agent would (connect → list tools → call tools) and reports **protocol / schema / runtime** issues in a way that’s easy to act on.

Use it to:
- **sanity-check locally** while you’re developing
- **gate releases in CI** with repeatable integration tests
- **turn failures into fixes** by handing the report to a coding agent

---

## Quick start

### Install

```bash
cargo install --path tooltest-cli
```

### Test a stdio MCP server

```bash
tooltest stdio --command ./path/to/your-mcp-server
# optional: --arg ..., --env KEY=VALUE, --cwd /somewhere
```

### Test a Streamable HTTP MCP endpoint

```bash
tooltest http --url http://127.0.0.1:8080/mcp
# optional: --auth-token "Bearer …"
```

### Output

Human-readable output on stdout by default; pass `--json` for JSON output (including error messages).

### JSON Schema patterns

Tooltest treats JSON Schema `pattern` values as ECMAScript regexes and relies on `rslint_regex` plus
`regex_syntax`/`proptest` to keep generation aligned with ECMA-262 semantics (e.g., ASCII-only `\d`, `\w`).

### Exit codes

- `0` = success
- `1` = run failure
- `2` = argument/validation error

### Use it in CI / tests

Treat tooltest as an integration test: run it against your server build, and fail the job if it reports problems.

Example (shell):

```bash
set -euo pipefail
tooltest stdio --command ./target/release/my-mcp-server
```

---

## CLI examples

Simple run against a hosted MCP endpoint:

```bash
cargo run -p tooltest-cli --bin tooltest -- \
  --cases 100 \
  http --url https://pymcp.app.lambdamechanic.com/kev/mcp
```

Simple run against a local stdio MCP server:

```bash
cargo run -p tooltest-cli --bin tooltest -- \
  --cases 100 \
  stdio --command ./target/debug/my-mcp-server
```

### State-machine sourcing

State-machine mode is strict by default: it only uses values mined from the corpus when satisfying required schema fields. If your server needs schema-based generation (for example, on the very first call), enable lenient sourcing.

You can set this in the JSON config:

```bash
--state-machine-config '{"lenient_sourcing":true}'
```

Or override it on the CLI:

```bash
--lenient-sourcing
--no-lenient-sourcing
```

CLI flags take precedence over the JSON config.

---

## Hosted MCP integration tests

By default the hosted MCP integration test runs and exercises the three public MCP servers used for validation. To skip it:

```bash
SKIP_HOSTED_MCP_TESTS=1 cargo test -p tooltest-core --test hosted_mcp_tests
```

---

## Verbose rmcp tracing

The tests install a tracing subscriber that emits to stderr. Use `RUST_LOG` plus `--nocapture` to see the full interaction.

```bash
RUST_LOG=rmcp=trace cargo test -p tooltest-core --test hosted_mcp_tests -- --nocapture
```

---

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

---

## Agent-assisted “fix loop” prompt examples

Pick one of these, paste it into Codex/Claude (with repo access), and let it iterate until tooltest is clean.

### Codex prompt

```text
You are working in this repository.
Goal: make the repository’s MCP server(s) conform to the MCP spec as exercised by tooltest.

Figure out how to run the MCP server from this repo (stdio or HTTP).

Run tooltest against it (examples below).

When tooltest reports failures, fix the underlying issues in the smallest reasonable patch.

Re-run tooltest and repeat until it exits 0.

Don’t rename tools or change schemas unless required; prefer backward-compatible fixes.

Add/adjust tests if needed.

Commands (choose the right one):

stdio: tooltest stdio --command "<command that starts the repo’s MCP server>"

http: tooltest http --url "<server mcp url>"

Return a short summary of what you changed and why, plus the final passing tooltest output snippet.
```

### Claude prompt

```text
You have access to this repo and can run commands.
Please make the MCP server(s) in this repository pass tooltest with zero failures.

Process:

Identify how to start the MCP server from the repo (stdio or streamable HTTP).

Run tooltest against it.

Fix the issues reported (protocol violations, tool schema mismatches, error handling, etc.).

Re-run tooltest until it exits successfully.

Use minimal, targeted changes. Avoid breaking tool names/schemas unless necessary.
```

---

## Tips

- If you want deeper coverage, increase the number of generated cases / run modes (when available).
- If a failure is intermittent, keep the smallest reproduction from the report and turn it into a regression test.
