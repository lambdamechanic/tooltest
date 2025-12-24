## Context
Tooltest currently generates tool invocations using proptest strategies derived from MCP schemas. This proposal adds a state-machine generator that reuses values observed from MCP responses, with a single test entry point selecting the generator mode.

## Goals / Non-Goals
- Goals:
  - Use proptest-state-machine to generate sequences of MCP tool calls.
  - Maintain a shared corpus of numbers and strings, seeded by the caller and expanded from response `structured_content`.
  - Ensure numbers/strings used in generated inputs come only from the corpus.
  - Offer a single public entry point that selects generator mode.
  - Report tool coverage (call counts) and validate coverage expectations for the state-machine generator.
- Non-Goals:
  - Mining values from raw output payloads or errors.
  - Changing existing output validation or assertion behavior.

## Decisions
- Decision: Represent the corpus as three de-duplicated, insertion-ordered collections (integers, numbers, strings) with index-based access.
  - Rationale: Preserves set semantics while allowing deterministic index selection when the state-machine needs a stable reference to a prior value, and supports integer-only constraints.
- Decision: Mine only `structured_content` from successful tool responses, including both object keys and values, to expand the corpus after each tool call.
  - Rationale: Matches request scope, treats keys as domain-relevant strings, and avoids ambiguity in output/error shapes.
- Decision: Keep the existing generator intact and add a generator mode selector at the run entry point.
  - Rationale: Provides backwards compatibility while enabling opt-in state-machine generation.
- Decision: Provide optional coverage validation hooks only for the state-machine generator mode, with coverage counts based on successful tool responses and exclude tools outside allowlists/inside blocklists.
  - Rationale: Coverage is tied to the state-driven corpus behavior and should not alter existing generator behavior.

## Risks / Trade-offs
- Response mining may expand the corpus quickly, increasing state space. We can mitigate by bounding sequence length and optionally capping corpus growth in a follow-up change if needed.
- State-machine generation may require additional runtime to execute and shrink; test defaults must remain conservative.
- Coverage requirements may flag tools as uncallable due to missing corpus data; this is expected and should be surfaced as warnings.

## Migration Plan
- Add a generator mode option with a default matching current behavior.
- Keep existing generator API paths so callers can opt in without breaking changes.

## Open Questions
- None.
