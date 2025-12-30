## Context
The project currently runs CI on pushes to main and PRs. It does not publish a stable, long-lived download URL for the tooltest CLI, and GitHub Actions artifacts expire after 90 days.

## Goals / Non-Goals
- Goals:
  - Publish stable "latest" download URLs for the tooltest CLI for key architectures.
  - Keep a short-term history of builds using workflow artifacts.
  - Provide a simple installer script that selects the correct build for the host.
- Non-Goals:
  - Versioned releases or semver tagging.
  - Long-term archival beyond what GitHub Releases provide.

## Decisions
- Decision: Use a fixed `latest` tag and GitHub Release that is updated on each merge to main.
  - Rationale: Provides durable URLs without introducing versioned releases.
- Decision: Build a matrix for linux-x86_64, linux-aarch64, macos-arm64, and windows-x86_64.
  - Rationale: Matches the requested "most important" targets.
- Decision: Keep workflow artifacts for history with a configurable retention period (default to 30 days).
  - Rationale: Workflow artifacts are short-lived, but sufficient for recent history.
- Decision: Provide a `curl | bash` installer that detects OS/arch and fetches the matching `latest` asset, plus direct URLs for manual downloads.
  - Rationale: Meets usability needs while keeping direct download options.

## Risks / Trade-offs
- Rewriting the `latest` tag changes release asset URLs for the same tag, but the path remains stable.
- GitHub Releases still depend on GitHub availability; long-term archival would need external storage.

## Migration Plan
- Add the new CI job and installer script.
- Document usage in README.
- Validate the workflow by merging to main and verifying the release assets.

## Open Questions
- None.
