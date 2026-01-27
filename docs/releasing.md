# Releasing

Tooltest uses release-plz to publish crates to crates.io.

## Prerequisites

- `CARGO_REGISTRY_TOKEN` is set in GitHub Actions secrets.
- `tooltest` and `tooltest-core` are the only crates published; `tooltest-test-support` is excluded.
- `tooltest-core` ships with an internal-use README to discourage direct consumption.

## Workflow

1. Merge changes to `main`.
2. The `release-plz` workflow opens or updates a release PR with version bumps and changelog updates.
3. Merge the release PR.
4. The workflow publishes `tooltest` and `tooltest-core` to crates.io and tags the release.

## Initial publish

The initial publish follows the same flow: release-plz creates the first release PR, and publishing happens after it merges.

## Release validation notes (2026-01-26)

### Blog feature support check

- MCP schema validation: `tooltest-core/src/schema.rs`
- Output schema checks: `tooltest-core/src/validation/validators.rs`
- State-machine generation: `tooltest-core/src/runner/state_machine.rs`
- Lenient sourcing: `tooltest-core/src/lib.rs`
- Pre-run hook: `tooltest-core/src/runner/pre_run.rs`

### Cargo install validation (clean container)

- Container: `rust:1.88-bullseye` (cargo 1.88.0, rustc 1.88.0)
- Commands: `export PATH=/usr/local/cargo/bin:$PATH && cargo install tooltest --locked && tooltest --version`
- Result: `tooltest 0.3.0`
- Notes: `rust:1.78-bullseye` lacks PATH setup and cargo 1.78 doesn't support edition2024; `rust:1.85-bullseye` failed due to dependencies requiring rustc 1.88+ (darling/process-wrap).
