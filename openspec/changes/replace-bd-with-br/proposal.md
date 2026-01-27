# Change: Replace bd With br (beads_rust)

## Why
This repo currently documents the Go `bd` CLI (beads) for issue tracking. We want to standardize on `br` (beads_rust) as the supported CLI to match the "classic" SQLite + JSONL workflow and reduce friction on machines where the `bd` toolchain/installer is problematic.

## What Changes
- Update repo agent-facing docs and local skills to use `br` commands instead of `bd`.
- Document a `br` installation path that avoids modifying system apt keyrings (e.g., using a release tarball or `--no-gum`).
- Update the "sync" workflow to reflect `br`'s non-invasive model:
  - `br sync --flush-only` to export to `.beads/issues.jsonl` before committing
  - `br sync --import-only` after pulling changes that modify `.beads/issues.jsonl`
- **Non-goal:** Change the issue storage format or move away from `.beads/issues.jsonl` tracked in git.
- **Migration note:** While implementing this change we may continue tracking work in `bd`, but we only update repo-facing documentation once `br` is installed and verified as a drop-in replacement.

## Impact
- Affected docs: `AGENTS.md`, `skills/beads/SKILL.md`, `skills/lambda-workflow/SKILL.md`.
- Affected tooling expectations: developers/agents will need `br` available in `PATH`.
- No product/runtime behavior changes expected (tooling/workflow only).

## Open Questions
- None.

## Decisions
- We remove `bd` references from repo-facing docs as a final step, after `br` is installed and verified.
- No `bd` compatibility shim (br should be a drop-in replacement once installed).
