# Change: Add br Git Hooks, Beads-Sync Workflow Notes, and bv Robot Triage

## Why
The repo now documents `br` (beads_rust) as the canonical issue tracker, but our developer ergonomics still depend on:
- A `beads-sync` git worktree that sparsely checks out only `.beads/` (used for beads-only syncing).
- Git hooks currently implemented as thin shims that delegate to `bd hook` / `bd hooks run`.
- `bv` robot triage output that still suggests `bd` commands in `claim_command` / `show_command`.

This mismatch makes the "default path" confusing: agents see `br` in docs, but tooling still nudges `bd`.

## What Changes
- Document the intended `beads-sync` workflow:
  - `beads-sync` remains the configured sync branch name.
  - The sync worktree uses sparse-checkout to include only `/.beads/`.
- Replace the current `.githooks/*` bd shims with br-native hook logic:
  - pre-commit: flush `br` changes to `.beads/issues.jsonl` and stage it
  - post-checkout/post-merge: import updated JSONL into the local DB (with a guard to avoid unnecessary work)
  - pre-push: ensure `.beads/issues.jsonl` is flushed (and optionally refuse pushes when out-of-sync)
  - prepare-commit-msg: either drop this behavior, or replicate the useful subset (decision needed)
- Update agent-facing docs to recommend bv robot triage as the default entry point:
  - Use `bv -robot-next` (or `bv -robot-triage`) to pick work
  - Use the returned `id` with `br show` / `br update --status in_progress` (ignore bv's embedded `bd` commands)
- Ensure hooks actively maintain the `beads-sync` worktree/branch and hard-block on failures:
  - Flush/import uses `br sync --flush-only` / `br sync --import-only`
  - The hook commits `.beads` changes on `beads-sync` and pushes to `origin/beads-sync`
  - If `br` or the git sync steps fail, the hook exits non-zero to block the git operation

## Impact
- Affected files: `.githooks/*`, `AGENTS.md`, and possibly `skills/lambda-workflow/SKILL.md`.
- Developer workflow: hooks will stop requiring `bd` and will instead require `br` on PATH.
- No runtime/product behavior changes.

## Open Questions
- None (decisions captured below).

## Decisions
- `.beads/issues.jsonl` remains tracked on `main`.
- Hooks actively maintain and push `beads-sync` and hard-block on failure.
