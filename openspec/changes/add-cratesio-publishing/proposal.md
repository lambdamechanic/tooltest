# Change: Add crates.io publishing via release-plz

## Why
Tooltest crates are not yet published to crates.io, and releases are currently limited to GitHub artifacts. We need automated crate releases and a stable crate name for end users.

## What Changes
- Add a release-plz workflow for crates.io publishing.
- Rename the CLI package from `tooltest-cli` to `tooltest` for the published crate.
- Add required Cargo metadata for publishing.

## Impact
- Affected specs: release-publishing (new)
- Affected code: `.github/workflows`, `tooltest/Cargo.toml`, workspace metadata
- Release process: adds crates.io publishing on release-plz tags
