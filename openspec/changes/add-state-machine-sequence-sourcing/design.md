## Context
Tooltest currently generates tool invocations using proptest strategies derived from MCP schemas. This proposal adds a state-machine generator that reuses values observed from MCP responses and makes it the only supported generator at the public entry point.

## Goals / Non-Goals
- Goals:
  - Use proptest-state-machine to generate sequences of MCP tool calls.
  - Maintain a shared corpus of numbers and strings, seeded by the caller and expanded from response `structured_content`.
  - Ensure numbers/strings used in generated inputs come only from the corpus.
  - Generate booleans, nulls, and enums directly from schema constraints without mining.
  - Offer a single public entry point that uses the state-machine generator.
  - Report tool coverage (call counts) and validate coverage expectations for the state-machine generator.
- Non-Goals:
  - Mining values from raw output payloads or errors.
  - Changing existing output validation or assertion behavior.

## Decisions
- Decision: Represent the corpus as three de-duplicated, insertion-ordered collections (integers, numbers, strings) with index-based access.
  - Rationale: Preserves set semantics while allowing deterministic index selection when the state-machine needs a stable reference to a prior value, and supports integer-only constraints.
- Decision: Mine only `structured_content` from successful tool responses, including both object keys and values, to expand the corpus after each tool call.
  - Rationale: Matches request scope, treats keys as domain-relevant strings, and avoids ambiguity in output/error shapes.
- Decision: Traverse `structured_content` deterministically using array index order and lexicographically sorted object keys.
  - Rationale: Guarantees stable corpus indexing across runs.
- Decision: Recursively mine nested arrays/objects with no bounds to collect keys and primitive values.
  - Rationale: Matches the expectation that all discoverable strings/numbers are available for future calls.
- Decision: Select values uniformly from the deduped corpus using proptest strategy selection.
  - Rationale: Keeps selection unbiased while relying on proptest's standard distribution.
- Decision: Recompute callable tools after each step using the updated corpus (Sequential state-machine strategy).
  - Rationale: Tool callability depends on values discovered during prior steps, so selection must reflect the current corpus instead of the initial seed.
- Decision: Remove the legacy generator and generator mode selection so the run entry point always uses the state-machine generator.
  - Rationale: Eliminates split behavior and improves coherency by enforcing a single generator.
- Decision: Provide optional coverage validation hooks only for the state-machine generator, with coverage counts based on successful tool responses and exclude tools outside allowlists/inside blocklists.
  - Rationale: Coverage is tied to the state-driven corpus behavior and should not alter existing generator behavior.
- Decision: Define tool callability based on required inputs being satisfiable by corpus values for numbers/strings and existing schema generators for other types, with lenient fallback when configured.
  - Rationale: Clarifies uncallable tool warnings while preserving existing schema-driven generation for non-corpus types and allowing opt-in fallback.

## Risks / Trade-offs
- Response mining may expand the corpus quickly, increasing state space. We can mitigate by bounding sequence length and optionally capping corpus growth in a follow-up change if needed.
- State-machine generation may require additional runtime to execute and shrink; test defaults must remain conservative.
- Coverage requirements may flag tools as uncallable due to missing corpus data; this is expected and should be surfaced as warnings.
- Failing when minimum sequence length is unattainable may increase failures in sparse toolsets; this is intentional to surface insufficient state coverage.

## Migration Plan
- Remove `GeneratorMode` and any generator mode selection fields/flags so existing callers fail to compile.
- Update public API/CLI documentation and examples to reflect state-machine-only generation.

## Open Questions
- None.
