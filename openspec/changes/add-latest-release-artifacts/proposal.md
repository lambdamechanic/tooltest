# Change: Publish latest tooltest CLI builds on main

## Why
Teams need a stable, long-lived download URL for the latest tooltest CLI across key architectures, plus a short-term history of builds for debugging and rollback.

## What Changes
- Add a release job to the existing GitHub Actions CI workflow that runs on merges to main.
- Build and package tooltest CLI for linux-x86_64, linux-aarch64, macos-arm64, and windows-x86_64.
- Publish/overwrite a fixed `latest` Git tag and GitHub Release assets for stable URLs.
- Upload per-arch workflow artifacts to keep a build history (retention policy configurable; default 30 days).
- Provide a `curl | bash` installer script that detects OS/arch and downloads the correct `latest` asset.
- Document direct download URLs and the installer usage in README.

## Impact
- Affected specs: `release-artifacts` (new capability)
- Affected code: `.github/workflows/ci.yml`, new installer script, README documentation
