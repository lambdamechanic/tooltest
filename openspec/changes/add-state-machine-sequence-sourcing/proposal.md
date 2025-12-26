# Change: Add state-machine MCP sequence generation with response-sourced values

## Why
Current sequence generation uses random values, which misses stateful flows and cannot reuse values returned by MCP tools. We want deterministic, response-driven value sourcing with a single test entry point that can switch between generator modes.

## What Changes
- Add a proptest-state-machine-based sequence generator that drives MCP tool calls using values sourced from a shared number/string corpus, recomputing callable tools after each response expands the corpus.
- Seed the corpus from caller-provided numbers/strings (optional), and extend it by mining numbers/strings from MCP `structured_content` responses.
- Require the state-machine generator to use only values from the corpus (no random numbers/strings).
- Provide a single public entry point for tests with a caller-selectable generator mode (existing generators vs state-machine).
- Add coverage reporting and validation for tool call counts when using the state-machine generator.

## Impact
- Affected specs: mcp-sequence-runner.
- Affected code: tool invocation generator, sequence runner entry point(s), coverage reporting/validation, and tests.
