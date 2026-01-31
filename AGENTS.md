<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

# Agent Instructions

This project uses **br** (beads_rust) for issue tracking.

Install `br` (use `--no-gum` to avoid gum auto-install, which can touch system apt keyrings):
```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/beads_rust/main/install.sh?$(date +%s)" | bash -s -- --no-gum --skip-skills
```

First-time setup (fresh clone/new worktree): if `.beads/beads.db` is missing, run `br sync --import-only --db .beads/beads.db` to hydrate from `.beads/issues.jsonl`.

Beads-sync worktree setup (fresh clone or missing worktree):
```bash
git fetch origin beads-sync:beads-sync || git branch beads-sync
git worktree add --no-checkout .git/beads-worktrees/beads-sync beads-sync
git -C .git/beads-worktrees/beads-sync sparse-checkout init --cone
git -C .git/beads-worktrees/beads-sync sparse-checkout set /.beads
git -C .git/beads-worktrees/beads-sync checkout beads-sync
```

## Quick Reference

```bash
br ready                       # Find available work
br show <id>                   # View issue details
br update <id> --status in_progress  # Claim work
br close <id> --reason "..."   # Complete work
br sync --flush-only           # Export DB -> .beads/issues.jsonl (before commit)
br sync --import-only          # Import .beads/issues.jsonl -> DB (after pull)
```

## Core Dependencies

These dependencies are considered core and can be used freely:
- proptest (do not expose proptest types in the public API)
- rmcp

## Schema/Type Integrity

- Never override schemas or types for tests. If a test needs different behavior, report it as a problem to fix in the implementation and notify the user instead of mutating schemas/types.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**Quality requirement:** Ensure tests pass before committing and pushing; Rust coverage must be 100% before pushing.
Note: `if let` constructs often confuse coverage reports because you need a test that exercises the non-match case too.
Types and tests must always respect the Galahad principle (see `skills/galahad/SKILL.md`).

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   br sync --import-only
   br sync --flush-only
   git add .beads/issues.jsonl  # if issues changed
   git commit -m "Update issues"  # if issues changed
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
- NEVER use `git commit --no-verify`; pre-commit hooks must run

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# Robot triage (default selection mechanism)
bv -robot-next
bv -robot-triage

# CLI commands for agents (use these instead)
br ready                    # Show issues ready to work (no blockers)
br list --status open        # All open issues
br show <id>                # Full issue details with dependencies
br create "..." --type task --priority 2
br update <id> --status in_progress
br close <id> --reason "Completed"
br close <id1> <id2>        # Close multiple issues at once
br sync --flush-only         # Export issue changes to .beads/issues.jsonl
```

### Workflow Pattern

1. **Start**: Run `bv -robot-next` (or `bv -robot-triage` for full context), then map the selected `id` to:
   - `br show <id>`
   - `br update <id> --status in_progress`
   - Ignore any embedded `bd` claim/show commands in `bv` output.
2. **Claim**: Use `br update <id> --status in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Export issue changes with `br sync --flush-only` before committing/pushing

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
br sync --flush-only    # Export issue changes to .beads/issues.jsonl
git add .beads/issues.jsonl
git commit -m "Update issues"  # if issues changed
git add <files>         # Stage code changes
git commit -m "..."     # Commit code changes
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only` before ending session if issues changed

<!-- end-bv-agent-instructions -->
