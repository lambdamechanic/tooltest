## 1. Implementation
- [x] 1.1 Add `--show-uncallable` and `--uncallable-limit <N>` CLI flags to enable uncallable tool traces and configure the per-tool call limit.
- [x] 1.2 Track the last N calls per tool for tools with zero successes, including tools never invoked.
- [x] 1.3 Update coverage validation failure reporting to include these traces when the flag is set.
- [x] 1.4 Adjust default trace output so it is only included when a positive error caused the failure (not just warnings).
- [x] 1.5 Emit input, output, error, and RFC3339 timestamps for each included call in both human output and run result JSON.
- [x] 1.6 Order uncallable tool output alphabetically by tool.
- [x] 1.7 Update CLI/help text and docs to describe the new flags and trace behavior.

## 2. Validation
- [x] 2.1 Add tests that verify trace omission by default for coverage-only failures.
- [x] 2.2 Add tests that verify the flag includes the last N calls per uncalled tool, including tools never invoked.
- [x] 2.3 Add tests that verify positive errors suppress coverage output and trace inclusion rules.
