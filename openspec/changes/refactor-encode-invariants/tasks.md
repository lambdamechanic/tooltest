## 1. Session Driver / Runner Refactor
- [ ] 1.1 Add typed `SessionDriver` tool-call API returning `CallToolResult`
- [ ] 1.2 Refactor state-machine runner to use typed tool-call response and construct `TraceEntry` explicitly
- [ ] 1.3 Deny `clippy::unwrap_used` / `clippy::expect_used` in `tooltest-core/src/runner/mod.rs` and remove violations
- [ ] 1.4 Update docs/examples that referenced the old API (if applicable)

## 2. Public Config Invariants (Breaking OK)
- [ ] 2.1 Encode config invariants by construction (private fields + validated constructors and/or invariant-carrying types)
- [ ] 2.2 Keep `Serialize/Deserialize`, with validation performed during deserialization (invalid configs fail to deserialize)
- [ ] 2.3 Update CLI/MCP wiring (`TooltestInput` conversions) to use tightened types
- [ ] 2.4 Add tests covering constructor/deserialization failure cases and happy paths for each invariant
- [ ] 2.5 Document breaking changes and migration notes (README/CHANGELOG as appropriate)

## 3. Generator NonEmpty Branches
- [ ] 3.1 Update oneOf/anyOf/type-union branch helpers to return `NonEmpty` lists
- [ ] 3.2 Refactor violation selection logic to remove unreachable `expect(...)`
- [ ] 3.3 Add/adjust tests for empty arrays, non-object entries, and correct violation selection

## 4. Quality Gates
- [ ] 4.1 `cargo test --workspace`
- [ ] 4.2 `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] 4.3 `cargo llvm-cov --workspace --fail-under-lines 100 --fail-under-regions 100`

