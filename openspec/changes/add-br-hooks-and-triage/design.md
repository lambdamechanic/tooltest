## Context
This repo uses:
- `br` (beads_rust) for issue tracking (SQLite + JSONL export).
- `bv` (beads_viewer) for graph analysis and robot triage.
- A `beads-sync` worktree configured with git sparse-checkout so only `/.beads/` is present.

Today, git hooks are thin shims that delegate to `bd` for automatic flush/import, and `bv` robot outputs embed `bd` commands. After switching the repo to `br`, those pieces should become br-native to avoid drift and confusion.

## Goals / Non-Goals
- Goals:
  - Keep `beads-sync` as the standard sync branch name.
  - Preserve the sparse worktree pattern (partial checkout of `/.beads/`).
  - Provide br-native git hooks that keep `.beads/issues.jsonl` and the local DB consistent across git operations.
  - Make `bv` robot triage the default "what should I do next?" entry point in docs, but use `br` for the actual claim/show/update steps.
- Non-Goals:
  - Modifying `bv` upstream behavior (it currently emits `bd` commands); we treat `bv` output as advisory.
  - Changing issue semantics, IDs, or the on-disk JSONL format.

## Decisions
### 1) Keep the sparse worktree model
The `beads-sync` worktree is implemented via:
- `git worktree` located at `.git/beads-worktrees/beads-sync`
- sparse-checkout enabled with pattern `/.beads/`

We keep this model and document how to recreate it on a fresh clone.

### 2) Replace bd hook shims with first-party shell hooks
Because `br` does not provide a `hook`/`hooks` subcommand, the repo will own the hook logic in `.githooks/*`.

Minimal behaviors to replicate:
- pre-commit: `br sync --flush-only` and `git add .beads/issues.jsonl` (if present)
- post-merge/post-checkout/post-rewrite: `br sync --import-only` when `.beads/issues.jsonl` changed
- pre-push: hard-block if `.beads/issues.jsonl` is not flushed and committed and/or `beads-sync` cannot be updated and pushed

Hooks also actively maintain `beads-sync`:
- The mirror update happens during `git push` (pre-push), not during `git commit` (no network in pre-commit).
- Canonical issue state remains `.beads/issues.jsonl` tracked on `main`; `beads-sync` is a mirror branch that always matches the last published `.beads/issues.jsonl`.
- After a successful flush, commit `.beads/issues.jsonl` to the `beads-sync` branch (in the sparse worktree) and push to the same remote as the push (typically `origin/beads-sync`).
- Hard-block only when publishing (`git commit`, `git push`). Import hooks warn and never block checkout/pull.
- Prevent recursion by ensuring commits performed inside the `beads-sync` worktree do not re-enter beads-sync maintenance.

### 3) Default triage flow uses bv robot outputs
For "what next?", prefer:
- `bv -robot-next` for the single best item
- `bv -robot-triage` for full context

Then use the `id` field with `br`.

## Risks / Trade-offs
- Mirror branches can drift if someone force-pushes or edits `beads-sync` manually; hooks should treat `beads-sync` as a mirror and reset/recreate it as needed.
- Hard-blocking publish hooks can be disruptive; this workflow chooses correctness for commit/push while keeping checkout/pull usable (warn-only imports).
- `bv` emitting `bd` commands can confuse; docs must clearly instruct to ignore those fields and use `br`.

## Migration Plan
1. Canonical source of truth: `main` tracks `.beads/issues.jsonl` (status quo).
2. Implement br-native hooks in `.githooks/*` (hard-block, maintains `beads-sync`) and validate on:
   - `git checkout`, `git pull --rebase`, `git commit`, `git push`
3. Update `AGENTS.md` and workflow skills to prefer `bv` robot triage for picking work.

## Open Questions
None.
