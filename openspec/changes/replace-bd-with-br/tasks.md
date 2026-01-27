## 1. Implementation
- [ ] 1.1 Install `br` on the dev machine using a method that does not touch system keyrings (prefer release tarball; alternative: upstream installer with `--no-gum`).
- [ ] 1.2 Validate `br` is a drop-in replacement in this repo (`br doctor`, `br ready`, `br show`, `br sync --status`).
- [ ] 1.3 Update `AGENTS.md` to use `br` commands (final step) and update the end-of-session checklist to use `br sync --flush-only` / `br sync --import-only`.
- [ ] 1.4 Update repo skills that reference `bd` (`skills/beads/SKILL.md`, `skills/lambda-workflow/SKILL.md`) to use `br` commands and semantics.
- [ ] 1.5 Remove remaining `bd` references from repo-facing docs/skills (no shim; no fallback), once `br` is verified.

## 2. Validation
- [ ] 2.1 Ensure `br doctor` reports healthy DB/JSONL sync.
- [ ] 2.2 Confirm `br ready --json`, `br show <id>`, and `br sync --status` work as documented.
- [ ] 2.3 Ensure core workflow docs no longer require `bd`:
  - `rg -n "\\bbd\\b" AGENTS.md` is empty
  - `rg -n "\\bbd\\b" skills/*/SKILL.md` is empty

## 3. Delivery
- [ ] 3.1 Run `openspec validate replace-bd-with-br --strict`.
- [ ] 3.2 Land doc changes with tests/linters as appropriate; keep changes scoped to workflow/docs.
