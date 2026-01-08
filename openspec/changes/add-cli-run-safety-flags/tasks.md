## 1. Implementation
- [x] 1.1 Add pre-run hook configuration to RunConfig and runner execution
- [x] 1.2 Add CLI flags for tool allowlist/blocklist and pre-run hook (shell string; exact, case-sensitive names)
- [x] 1.3 Add tests for pre-run hook success/failure paths, including failure details and distinct failure code
- [x] 1.4 Add tests for pre-run hook inheriting stdio env/cwd and running before validation
- [x] 1.5 Add tests for allowlist/blocklist filtering via CLI predicate and no-eligible-tools failure
- [x] 1.6 Update docs/blog references for new flags and clarify that coverage allowlist/blocklist are separate
