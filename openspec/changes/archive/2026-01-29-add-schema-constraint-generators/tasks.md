## 1. Implementation
- [ ] Add tests that demonstrate minLength/maxLength/pattern constraints are not respected.
- [ ] Add a generator that returns a JSON object violating exactly one schema constraint while otherwise valid.
- [ ] Ensure generator APIs remain internal and public API unchanged.
- [ ] Add tests for the invalid-input generator behavior.

## 2. Validation
- [ ] Run cargo test --workspace
- [ ] Run cargo llvm-cov --workspace --fail-under-lines 100
