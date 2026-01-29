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

Latest prebuilt binaries (auto-detect OS/arch):

```bash
curl -fsSL https://raw.githubusercontent.com/lambdamechanic/tooltest/main/install.sh | bash
```

The installer verifies downloaded binaries against the `*.sha256` checksums when `sha256sum` or `shasum` is available.

Optionally set an install directory (default `/usr/local/bin`, fallback to `~/.local/bin`):

```bash
INSTALL_DIR="$HOME/.local/bin" \
  curl -fsSL https://raw.githubusercontent.com/lambdamechanic/tooltest/main/install.sh | bash
```

Direct downloads (stable URLs):

- `https://github.com/lambdamechanic/tooltest/releases/download/latest/tooltest-linux-x86_64`
- `https://github.com/lambdamechanic/tooltest/releases/download/latest/tooltest-linux-aarch64`
- `https://github.com/lambdamechanic/tooltest/releases/download/latest/tooltest-macos-arm64`
- `https://github.com/lambdamechanic/tooltest/releases/download/latest/tooltest-windows-x86_64.exe`

Install from crates.io:

```bash
cargo install tooltest
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

### Migration note (legacy generator removal)

Tooltest now runs only the state-machine generator. The `--generator-mode` flag and
`GeneratorMode` API are removed. If you previously relied on legacy random generation,
expect stricter input sourcing by default. To allow schema-based generation for required
fields when the corpus is empty, set `--lenient-sourcing` or provide
`--state-machine-config '{"lenient_sourcing":true}'`.

Simple run against a hosted MCP endpoint:

```bash
cargo run -p tooltest --bin tooltest -- \
  --cases 100 \
  http --url https://pymcp.app.lambdamechanic.com/kev/mcp
```

Simple run against a local stdio MCP server:

```bash
cargo run -p tooltest --bin tooltest -- \
  --cases 100 \
  stdio --command ./target/debug/my-mcp-server
```

### State-machine sourcing

State-machine mode is strict by default: it only uses values mined from the corpus when satisfying required schema fields. If your server needs schema-based generation (for example, on the very first call), enable lenient sourcing.

If you see `state-machine generator failed to reach minimum sequence length`, it usually means no eligible tool call could be generated (often because required fields had no corpus values). Re-run with `--lenient-sourcing` or seed values via `--state-machine-config` to unblock generation.

State-machine runs always track a corpus and coverage counts; this adds overhead compared to the legacy generator and can grow with response size.

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

### Coverage validation output

When coverage validation fails without a positive error, you can include uncallable tool traces in
the output with `--show-uncallable`. Use `--uncallable-limit <N>` to control how many calls per
tool are included (default: 1).

### Tool filters and pre-run hook

Filter eligible tools by name (exact, case-sensitive) using `--tool-allowlist` and
`--tool-blocklist`. These flags only affect invocation generation and are separate from
`coverage_allowlist`/`coverage_blocklist` in the state-machine config, which only affect
coverage warnings and validation.

Run a shell command before tool schema validation and before every generated sequence (including
shrink/minimization) using `--pre-run-hook "<shell command>"`. If the hook exits non-zero, the run
fails with `code: pre_run_hook_failed` and structured details (exit code, stdout, stderr, signal).
For stdio runs, the hook uses the same `--env` and `--cwd` settings as the MCP server process.

### In-band tool errors

Tool responses with `isError = true` are allowed by default and do not fail the run. To preserve
the previous behavior, pass `--in-band-error-forbidden`. MCP protocol errors (JSON-RPC errors) and
schema-invalid responses still fail the run.

Static checks (like output schema validation) always apply. If a tool advertises an output schema,
error responses are expected to include `structuredContent` that conforms to that schema. The MCP
spec describes `CallToolResult.structuredContent` as optional and says that if an output schema is
defined it SHOULD conform to the schema; tooltest treats invalid structured content as schema-invalid
and emits a warning when `structuredContent` is missing (even for `isError` results; see
`docs/mcp-spec/2025-11-25/schema.mdx`).

### Seed data

Seed the corpus with known values (strings or numbers) using inline JSON:

```bash
tooltest stdio --command ./target/debug/my-mcp-server \
  --state-machine-config '{"seed_strings":["alpha"],"seed_numbers":[42]}'
```

### Text mining

If your MCP server only emits textual content, you can mine whitespace-delimited tokens into the corpus:

```bash
--state-machine-config '{"mine_text":true}'
```

Or override it on the CLI:

```bash
--mine-text
```

### Corpus debugging

Dump the final corpus as JSON (stderr in human mode, inline in --json mode):

```bash
--dump-corpus
```

Log newly mined corpus values after each tool response (stderr):

```bash
--log-corpus-deltas
```

### Pre-run command hook

Run a command before each proptest case to reset external state. The hook expects a JSON argv array.
Non-zero exit codes fail the run and include stdout/stderr in the failure details.

```bash
--pre-run-hook '["/bin/sh","-c","./scripts/reset-state.sh"]'
```

---

## Tool enumeration and bulk validation (tooltest-core)

The `tooltest-core` crate exposes helper APIs for listing tools with schema validation and
running bulk tool validation. The default per-tool case count is controlled by
`TOOLTEST_CASES_PER_TOOL` and can be overridden in code.

```bash
export TOOLTEST_CASES_PER_TOOL=10
```

```rust
use tooltest_core::{
    list_tools_http, validate_tools, HttpConfig, SchemaConfig, SessionDriver, ToolValidationConfig,
};

# async fn run() {
let tools = list_tools_http(
    &HttpConfig {
        url: "http://localhost:3000/mcp".into(),
        auth_token: None,
    },
    &SchemaConfig::default(),
)
.await
.expect("list tools");
println!("found {} tools", tools.len());

let session = SessionDriver::connect_http(&HttpConfig {
    url: "http://localhost:3000/mcp".into(),
    auth_token: None,
})
.await
.expect("connect");
let config = ToolValidationConfig::new();
let summary = validate_tools(&session, &config, None)
    .await
    .expect("validate tools");
println!("validated {} tools", summary.tools.len());
# }
```

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

## Agent-assisted “fix loop” prompt

Paste this into your coding agent (with repo access) and let it iterate until tooltest is clean.

```text
You have access to this repository and can run commands.
Goal: make the repository’s MCP server(s) conform to the MCP spec as exercised by tooltest.

Figure out how to start the MCP server from this repo (stdio or streamable HTTP).

Run tooltest against it (examples below).

When tooltest reports failures, fix the underlying issues in the smallest reasonable patch.

Re-run tooltest and repeat until it exits 0.

If you see "state-machine generator failed to reach minimum sequence length", re-run with `--lenient-sourcing` or seed values in `--state-machine-config`.

If you need per-case traces for debugging, add `--trace-all /tmp/tooltest-traces.jsonl` (any writable path).

If you are invoking tooltest via the MCP tool instead of the CLI, pass the same options in the tool input.

Don’t rename tools or change schemas unless required; prefer backward-compatible fixes.

Add/adjust tests if needed.

Commands (choose the right one):

stdio: tooltest stdio --command "<command that starts the repo’s MCP server>"

http: tooltest http --url "<server mcp url>"

Return a short summary of what you changed and why, plus the final passing tooltest output snippet.
```

---

## Tips

- If you want deeper coverage, increase the number of generated cases / run modes (when available).
- If a failure is intermittent, keep the smallest reproduction from the report and turn it into a regression test.
- You can install the tooltest agent skill with `sk install lambdamechanic/tooltest tooltest-fix-loop`.
