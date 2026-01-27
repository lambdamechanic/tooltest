## Context
This repository currently standardizes on `bd` (Go beads) for issue tracking and agent workflow. We want to switch to `br` (beads_rust), which keeps the "classic" SQLite + JSONL architecture and is designed to be non-invasive (explicit sync; no automatic git operations).

The key differences that affect this repo's workflow are:
- `br` does not auto-run git; exporting/importing the JSONL is explicit.
- The `br` installer may attempt to install `gum` for rich output (which can touch system package manager keyrings). We need a safe install path for locked-down machines.

## Goals / Non-Goals
- Goals:
  - Make `br` the canonical issue-tracking CLI referenced by repo docs and skills.
  - Provide installation instructions that work without requiring system apt keyring modification.
  - Preserve existing `.beads/issues.jsonl` as the git-synced artifact.
- Non-Goals:
  - Changing the issue ID format/prefix for this repo.
  - Migrating to a different issue tracker or storage layout.
  - Introducing background daemons or git hooks beyond what `br` already supports.

## Decisions
- Decision: Use `br` as the sole documented CLI for issue tracking in this repo.
  - Rationale: Single source of truth for agents; avoids drift between `bd` and `br` command semantics.
- Decision: Treat `.beads/issues.jsonl` as the shared artifact; treat SQLite DB as local cache.
  - Rationale: Matches `br`'s explicit sync model and existing `.gitignore` patterns.
- Decision: Recommend one of these installation paths (final selection in apply stage):
  - Preferred: download the `br-<version>-linux_amd64.tar.gz` release artifact and place `br` in `~/.local/bin`.
  - Alternative: run the upstream installer with `--no-gum` to avoid gum auto-install (and its apt keyring steps).
  - Alternative: `cargo +nightly install --git ...` if binary downloads are disallowed.

## Risks / Trade-offs
- Risk: Machines with an existing `.beads/beads.db` from `bd` may have schema differences.
  - Mitigation: Prefer importing from `.beads/issues.jsonl` (`br sync --import-only`) and document `--db` override or DB reset if needed.
- Risk: Some agents may have muscle memory around `bd sync` doing git commits.
  - Mitigation: Update `AGENTS.md` to explicitly include `git add/commit/push` steps after `br sync --flush-only`.

## Migration Plan
1. Install `br` on the dev machine.
2. In repo root, run `br doctor` to confirm DB/JSONL health.
3. Keep tracking this migration in `bd` if needed while `br` installation is being sorted out.
4. Update repo docs/skills to use `br` as a final step once `br` is verified as drop-in.
5. After merging, agents use:
   - After `git pull`: `br sync --import-only`
   - Before committing issue changes: `br sync --flush-only`

## Open Questions
- Should we track a shared `.beads/config.yaml` in git (would require `.gitignore` changes), or keep configuration local?
