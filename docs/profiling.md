# Profiling tooltest (debug)

`tooltest-prof` is an optional wrapper that runs the installed `tooltest` binary under
`flamegraph`. It is a debugging tool and is not included in release artifacts or `cargo install`
by default.

## Install

Install the wrapper via the install script:

```bash
TOOLTEST_INSTALL_DEBUG_TOOLS=1 \
  curl -fsSL https://raw.githubusercontent.com/lambdamechanic/tooltest/main/install.sh | bash
```

## Prerequisites

- `flamegraph` in your `PATH` (from `cargo install flamegraph`)
- `perf`/DTrace permissions for your platform (see `flamegraph --help`)

## Usage

Writes SVG output to `TOOLTEST_PROFILE_PATH` when set:

```bash
TOOLTEST_PROFILE_PATH="$PWD/tooltest.svg" \
  tooltest-prof stdio --command ./path/to/your-mcp-server
```

For MCP usage, configure your launcher to invoke `tooltest-prof` instead of `tooltest`.

## Better symbols (if stacks are mostly "unknown")

Rebuild tooltest with symbols + frame pointers and point the wrapper at the rebuilt binary:

```bash
./scripts/tooltest-prof-build
TOOLTEST_PROFILE_TOOLTEST_PATH="$PWD/target/release/tooltest" \
  TOOLTEST_PROFILE_PATH="$PWD/tooltest.svg" \
  tooltest-prof stdio --command ./path/to/your-mcp-server
```

Manual rebuild (if you prefer):

```bash
RUSTFLAGS="-C force-frame-pointers=yes" \
  CARGO_PROFILE_RELEASE_DEBUG=1 \
  CARGO_PROFILE_RELEASE_STRIP=none \
  CARGO_PROFILE_RELEASE_LTO=false \
  cargo build -p tooltest --bin tooltest --release
```
