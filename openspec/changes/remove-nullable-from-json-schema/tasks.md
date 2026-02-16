## 1. New Lint: json_schema_non_standard_keywords

- [ ] 1.1 Implement `JsonSchemaNonStandardKeywordsLint` in `tooltest-core/src/lints.rs`
  - Check for `nullable` keyword in schemas declaring JSON Schema 2020-12
  - Report finding at warning level
- [ ] 1.2 Add lint registration to `lint_config.rs`
- [ ] 1.3 Add tests for the new lint
- [ ] 1.4 Enable lint in repo's `tooltest.toml` at warning level
- [ ] 1.5 Run dogfooding to verify lint catches `nullable` in current schemas

## 2. Implementation

- [ ] 2.1 Remove `AddNullable::default()` from schema transforms in `tooltest/src/mcp/schema.rs`
- [ ] 2.2 Add post-processing step to strip `nullable` keywords from outputSchema (workaround for rmcp upstream, document as such)
- [ ] 2.3 Update test helper in `tooltest-core/tests/internal/input_tests.rs` to remove `AddNullable` for consistency
- [ ] 2.4 Add automated test verifying inputSchema and outputSchema contain no `nullable` keyword
- [ ] 2.5 Run dogfooding to verify lint no longer reports `nullable` findings

## 3. Validation

- [ ] 3.1 Run `npx mcporter list tooltest` to confirm compatibility
- [ ] 3.2 Run existing tests to ensure no regressions

## 4. Documentation

- [ ] 4.1 Add comment explaining why `AddNullable` is not used for JSON Schema 2020-12
- [ ] 4.2 Document the post-processing workaround and link to upstream issue

## 5. Upstream

- [ ] 5.1 File issue on modelcontextprotocol/rust-sdk about `AddNullable` being non-compliant with JSON Schema 2020-12
- [ ] 5.2 Optionally submit PR to rmcp removing `AddNullable` from `schema_for_type()`
