## 1. Proposal Implementation
- [ ] 1.1 Review current generator and runner APIs to identify the single test entry point and generator integration points
- [ ] 1.2 Define generator mode selection in the public API without breaking existing callers
- [ ] 1.3 Implement corpus type for de-duplicated, insertion-ordered integers, numbers, and strings with stable indices
- [ ] 1.4 Implement response mining of `structured_content` to extend the corpus after each tool call
- [ ] 1.5 Add proptest-state-machine model that generates tool calls using only corpus-sourced numbers/strings and ends runs when no callable tools remain
- [ ] 1.6 Integrate the state-machine generator into the unified entry point, preserving the existing generator
- [ ] 1.7 Add coverage tracking for tool call counts (successful responses only), warning reporting with structured reason codes, and allowlist/blocklist exemptions
- [ ] 1.8 Add coverage validation rule helpers (e.g., minimum calls per tool, no uncalled tools, percentage called) that operate on successful call counts and treat uncallable tools as excluded from percentage denominators
- [ ] 1.9 Add tests for corpus seeding, de-duplication, response mining (including keys), integer-only selection, and empty-corpus uncallable warnings with reason codes
- [ ] 1.10 Add tests for generator mode selection, corpus-only value generation, allowlist/blocklist coverage exemptions, coverage validation helpers, and error-response coverage exclusion
- [ ] 1.11 Run `openspec validate add-state-machine-sequence-sourcing --strict`

## Dependencies
- 1.5 depends on 1.3 and 1.4 (state-machine generator requires corpus and mining).
- 1.6 depends on 1.2 and 1.5 (entry point integration requires mode selection and generator).
- 1.8 depends on 1.7 (coverage validation operates on coverage tracking output).
- 1.10 depends on 1.6 and 1.8 (tests require integrated generator and validation helpers).
