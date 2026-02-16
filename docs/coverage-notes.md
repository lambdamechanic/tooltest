# Coverage Notes

This document tracks known coverage gaps and the rationale for exclusions.

## `is_modern_schema` in `tooltest-core/src/lints.rs`

### The Issue

The `is_modern_schema` function shows 1 missed region in llvm-cov coverage reports, despite all lines and logical paths being covered.

### Current Implementation

```rust
fn is_modern_schema(schema_id: &str) -> bool {
    let normalized = normalize_schema_id(schema_id);
    normalized.starts_with("https://json-schema.org/draft/2020-12")
        || normalized.starts_with("https://json-schema.org/draft/2019-09")
}
```

### Test Coverage

All three logical paths are exercised by tests:
1. **2020-12 schema** - `json_schema_non_standard_keywords_reports_2020_12_with_nullable`
2. **2019-09 schema** - `json_schema_non_standard_keywords_reports_nullable_in_2019_09`
3. **Legacy schema (no match)** - `json_schema_non_standard_keywords_ignores_legacy_schema`

### Root Cause

LLVM's region coverage tracking creates separate regions for:
- The `||` operator's short-circuit paths
- The closure body in `.iter().any()` approaches

The "missed" region is an artifact of how LLVM tracks coverage through these constructs, not actual uncovered code. This appears to be a known issue with llvm-cov's region tracking for short-circuit boolean expressions.

### Attempted Alternatives

1. **Original `||` expression**: Shows 1 missed region
2. **Match expression with guards**: Shows 1 missed region  
3. **`iter().any()` with closure**: Shows 1 missed region (closure evaluation)
4. **Manual for loop with early return**: Shows 1 missed region

All approaches produce the same result because the underlying issue is LLVM's region tracking, not the code structure.

### Resolution

The function is kept in its simplest form (inline `||`) since no alternative eliminates the region gap. The tests provide complete logical coverage, and the "missed region" is a coverage tool artifact.

Last updated: 2026-02-16
