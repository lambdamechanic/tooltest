## 1. Lint Configuration
- [x] 1.1 Define the TOML schema for lint configuration and levels.
- [x] 1.2 Implement config discovery (repo `tooltest.toml` via git-root upward search, else `~/.config/tooltest.toml`, else built-in defaults).
- [x] 1.3 Embed a default `tooltest.toml` (with comments) that encodes current behavior (`no_crash`, `coverage`).
- [x] 1.4 Expose the default config via a CLI subcommand (emit to stdout).
- [x] 1.5 Validate config schema (unknown lint IDs, invalid params, invalid levels, fixed-severity enforcement).
- [x] 1.6 Reject duplicate lint IDs during config parsing.
- [x] 1.7 Ensure default config enumerates all supported lints (disabled where not enabled).

## 2. Lint Framework Core
- [x] 2.1 Add lint model types (id, phase, level, params) and a result type for warnings/errors.
- [x] 2.2 Add list-phase lint evaluation after tools/list parsing (collect all findings, fail before tool calls on error).
- [x] 2.3 Add response-phase lint evaluation per tools/call response (collect findings, fail on error after response).
- [x] 2.4 Add run-phase lint evaluation after run completion (coverage, aggregate checks).

## 3. Initial Lints
- [x] 3.1 Implement `max_tools` (raw list-tools count).
- [x] 3.2 Implement `mcp_schema_min_version` (initialize protocol version check).
- [x] 3.3 Implement `json_schema_dialect_compat` (input/output `$schema` allowlist, default includes older drafts).
- [x] 3.4 Implement `max_structured_content_bytes` (per response).
- [x] 3.5 Remove `coverage_rules` from state-machine config and migrate coverage rules into the coverage lint config.
- [x] 3.6 Implement `coverage` lint over coverage data.
- [x] 3.7 Implement `no_crash` lint that preserves current failure semantics (error-only).
- [x] 3.8 Implement `missing_structured_content` lint (response-phase, warning by default).
- [x] 3.9 Remove legacy `tooltest_core::validation::validate_tools` workflow while retaining schema-based invocation generators for lenient sourcing.

## 4. Surfaces and Reporting
- [x] 4.1 Add lint warnings to run results (RunWarning) with stable codes and lint id details.

## 5. Validation
- [x] 5.1 Add unit tests for config precedence and lint level behavior.
- [x] 5.2 Add tests for each initial lint.
- [x] 5.3 Update README/docs for `tooltest.toml` and lint phases.
- [x] 5.4 Update public input schema/tests to remove `coverage_rules` from state-machine config.
- [x] 5.5 Remove tests that reference legacy validate-tools APIs or replace them with lint coverage.

## Dependencies
1. 1.3 precedes 1.4 to ensure the default config exists before emitting it.
2. 2.1-2.4 precede 3.1-3.7 (lint framework before lint implementations).
3. 2.4 precedes 3.6 (run-phase lint plumbing before coverage lint).
4. 1.6 precedes any lint evaluation (duplicates must be rejected before running lints).
5. 3.8 depends on 2.2-2.4 (missing_structured_content lint needs response-phase plumbing).
6. 5.4 depends on 3.5 (coverage_rules removed from state-machine config).
7. 3.9 precedes 5.5 (remove legacy API before cleaning tests).
