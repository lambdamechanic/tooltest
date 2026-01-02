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
