## 1. Discovery
- [ ] 1.1 Confirm current `beads-sync` worktree layout and sparse-checkout patterns on a fresh clone (document exact commands to create it).
- [ ] 1.2 Confirm canonical source of truth: `.beads/issues.jsonl` stays tracked on `main` and `beads-sync` acts as a mirror for fast beads-only sync.
- [ ] 1.3 Enumerate the existing hook behaviors we rely on today (pre-commit, post-merge, post-checkout, pre-push, prepare-commit-msg).

## 2. Implementation
- [ ] 2.1 Update `AGENTS.md` to prefer `bv -robot-next` / `bv -robot-triage` for work selection and show br-based follow-up commands.
- [ ] 2.2 Replace `.githooks/*` bd shims with br-native hook scripts.
- [ ] 2.3 Implement `beads-sync` maintenance in hooks (hard-block):
  - ensure the `beads-sync` sparse worktree exists
  - commit `.beads/issues.jsonl` on `beads-sync`
  - push `beads-sync` to `origin/beads-sync`

## 3. Validation
- [ ] 3.1 Verify hooks on the happy path:
  - `git checkout <branch>` triggers import when `.beads/issues.jsonl` changes
  - `git pull --rebase` triggers import when `.beads/issues.jsonl` changes
  - `git commit` triggers flush + stages `.beads/issues.jsonl`
  - `git push` hard-blocks when `.beads` is out-of-sync or `beads-sync` cannot be updated/pushed
- [ ] 3.2 Verify `bv -robot-next` output can be translated into br commands (`id` -> `br show`, `br update --status in_progress`).

## 4. Delivery
- [ ] 4.1 Run `openspec validate add-br-hooks-and-triage --strict`.
- [ ] 4.2 Land changes with hooks enabled locally (`git config core.hooksPath .githooks`) and ensure the repo remains usable without `bd`.
