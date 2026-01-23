## 1. Implementation
- [ ] 1.1 Add `--show-uncallable` and `--uncallable-limit <N>` CLI flags to enable uncallable tool traces and configure the per-tool call limit.
- [ ] 1.2 Track the last N calls per tool for tools with zero successes, including tools never invoked.
- [ ] 1.3 Update coverage validation failure reporting to include these traces when the flag is set.
- [ ] 1.4 Adjust default trace output so it is only included when a positive error caused the failure (not just warnings).
- [ ] 1.5 Emit input, output, error, and RFC3339 timestamps for each included call in both human output and run result JSON.
- [ ] 1.6 Order uncallable tool output alphabetically by tool.
- [ ] 1.7 Update CLI/help text and docs to describe the new flags and trace behavior.

## 2. Validation
- [ ] 2.1 Add tests that verify trace omission by default for coverage-only failures.
- [ ] 2.2 Add tests that verify the flag includes the last N calls per uncalled tool, including tools never invoked.
- [ ] 2.3 Add tests that verify positive errors suppress coverage output and trace inclusion rules.
