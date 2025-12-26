# Change: Add state-machine MCP sequence generation with response-sourced values

## Why
Current sequence generation uses random values, which misses stateful flows and cannot reuse values returned by MCP tools. We want deterministic, response-driven value sourcing with a single test entry point that uses the state-machine generator exclusively.

## What Changes
- Add a proptest-state-machine-based sequence generator that drives MCP tool calls using values sourced from a shared corpus, recomputing callable tools after each response expands the corpus.
- Seed the corpus from caller-provided numbers/strings (optional), and extend it by mining structured outputs (keys, strings, numbers) from MCP `structured_content` responses.
- Require the state-machine generator to use only values from the corpus for strings/numbers/integers; booleans, nulls, and enums are generated directly from schema constraints.
- **BREAKING** remove the legacy generator mode and generator mode selection from the core API and CLI; state-machine generation is the only supported mode.
- Add coverage reporting and validation for tool call counts when using the state-machine generator.

## Impact
- Affected specs: mcp-sequence-runner.
- Affected code: tool invocation generator, sequence runner entry point(s), coverage reporting/validation, CLI args, and tests/docs.

## Migration
- Remove usages of `GeneratorMode::Legacy`/`GeneratorMode` and any `--generator-mode` CLI flag usage; compilation should fail until callers switch to the state-machine-only configuration.
