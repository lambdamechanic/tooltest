## 1. Discovery
- [x] 1.1 Confirm current `beads-sync` worktree layout and sparse-checkout patterns on a fresh clone (document exact commands to create it).
- [x] 1.2 Confirm canonical source of truth: `.beads/issues.jsonl` stays tracked on `main` and `beads-sync` acts as a mirror for fast beads-only sync.
- [x] 1.3 Enumerate the existing hook behaviors we rely on today (pre-commit, post-merge, post-checkout, pre-push, prepare-commit-msg).
- [x] 1.4 Confirm hook coverage for rebases (`git pull --rebase`) and decide which hook(s) cover it (post-rewrite expected).

## 2. Implementation
- [x] 2.1 Update `AGENTS.md` to prefer `bv -robot-next` / `bv -robot-triage` for work selection and show br-based follow-up commands.
- [x] 2.2 Replace `.githooks/*` bd shims with br-native hook scripts.
- [x] 2.3 Implement `beads-sync` maintenance in hooks (hard-block):
  - ensure the `beads-sync` sparse worktree exists
  - commit `.beads/issues.jsonl` on `beads-sync`
  - push `beads-sync` to the same remote as the push (typically `origin/beads-sync`)
  - ensure recursion guards prevent re-entering beads-sync maintenance during the mirror update

## 3. Validation
- [x] 3.1 Verify hooks on the happy path:
  - `git checkout <branch>` triggers import when `.beads/issues.jsonl` changes
  - `git pull --rebase` triggers import when `.beads/issues.jsonl` changes (post-rewrite)
  - `git commit` triggers flush + stages `.beads/issues.jsonl`
  - `git push` hard-blocks when `.beads/issues.jsonl` is out-of-sync (flush produces changes) or `beads-sync` cannot be updated/pushed
- [x] 3.2 Verify `bv -robot-next` output can be translated into br commands (`id` -> `br show`, `br update --status in_progress`).

## 4. Delivery
- [x] 4.1 Run `openspec validate add-br-hooks-and-triage --strict`.
- [x] 4.2 Land changes with hooks enabled locally (`git config core.hooksPath .githooks`) and ensure the repo remains usable without `bd`.

## Dependencies
- 2.2 depends on 1.3 (hook replacement needs a baseline of current behavior).
- 2.3 depends on 1.1, 1.2, and 2.2 (mirror maintenance needs the worktree convention and hook scripts).
- 3.1 depends on 2.2 and 2.3 (validation needs hooks and mirror maintenance).
- 4.2 depends on 3.1 and 3.2 (delivery depends on validated behavior and updated docs).
- This change assumes `replace-bd-with-br` is applied or in-flight (br is canonical in docs).
