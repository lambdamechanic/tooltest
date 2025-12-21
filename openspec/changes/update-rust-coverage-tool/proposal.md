# Change: Adopt cargo-llvm-cov for Rust coverage

## Why
Rust coverage reporting should use the project standard toolchain to ensure consistent local and CI results.

## What Changes
- Replace cargo-tarpaulin usage with cargo-llvm-cov for Rust coverage checks.
- Document the coverage command and update quality gate guidance.

## Impact
- Affected specs: testing-strategy
- Affected code: CI/scripts and developer workflow documentation
