## 1. Proposal Implementation
- [ ] 1.1 Review current generator and runner APIs to identify the single test entry point and generator integration points
- [ ] 1.2 Remove legacy generator mode and generator mode selection from the public API and CLI
- [ ] 1.3 Implement corpus type for de-duplicated, insertion-ordered integers, numbers, and strings with stable indices
- [ ] 1.4 Implement response mining of `structured_content` (including nested keys/values) to extend the corpus after each tool call
- [ ] 1.5 Add translation layer to resolve state references into concrete invocation arguments
- [ ] 1.6 Add proptest-state-machine model that generates tool calls using only corpus-sourced numbers/strings, generates booleans/null/enums directly from schema constraints, recomputes callability each step, and ends runs when no callable tools remain
- [ ] 1.7 Integrate the state-machine generator into the unified entry point as the sole generator
- [ ] 1.8 Add coverage tracking for tool call counts (successful responses only), warning reporting with structured reason codes, and allowlist/blocklist exemptions
- [ ] 1.9 Add coverage validation rule helpers (e.g., minimum calls per tool, no uncalled tools, percentage called) that operate on successful call counts and treat uncallable tools as excluded from percentage denominators
- [ ] 1.10 Add tests for corpus seeding, de-duplication, response mining (including keys), nested mining, integer-only selection, and empty-corpus uncallable warnings with reason codes
- [ ] 1.11 Add tests for legacy generator removal, corpus-only value generation, inline enum/boolean/null generation, anyOf/oneOf using mined values, allowlist/blocklist coverage exemptions, coverage validation helpers, and error-response coverage exclusion
- [ ] 1.12 Add regression coverage for kev-style flows (discover IDs, then call fetch-by-id tools)
- [ ] 1.13 Run standard test suites (unit + property tests where reasonable) and confirm coverage targets for this change
- [ ] 1.14 Run `openspec validate add-state-machine-sequence-sourcing --strict`

## Dependencies
- 1.6 depends on 1.3, 1.4, and 1.5 (state-machine generator requires corpus, mining, and reference resolution).
- 1.7 depends on 1.6 (entry point integration requires the generator).
- 1.8 depends on 1.6 and 1.7 (coverage reporting needs the generator and integrated entry point).
- 1.9 depends on 1.8 (coverage validation operates on coverage tracking output).
- 1.11 depends on 1.8 and 1.9 (tests require coverage tracking and validation helpers).
