# Change: Add tooltest CPU profiling via environment variable

## Why
Tooltest runs can consume significant CPU, and we need a straightforward way to capture profiling data in CI or local runs without code changes.

## What Changes
- Add a `tooltest-prof` wrapper script that runs the installed `tooltest` binary under the `flamegraph` command.
- Support `TOOLTEST_PROFILE_PATH` to control where the flamegraph output (SVG) is written.
- Support `TOOLTEST_PROFILE_TOOLTEST_PATH` to point at a locally rebuilt tooltest binary.
- Keep profiling support as a debugging tool (no changes to tooltest runtime or release artifacts).
- Provide an opt-in installer for the wrapper script.
- Document usage and prerequisites for profiling runs.

## Impact
- Affected specs: `openspec/specs/mcp-sequence-runner/spec.md`
- Affected code: install script, debug wrapper script, docs
