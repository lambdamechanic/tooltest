---
name: beads
description: "Git-backed issue tracker for multi-session agent work with dependency graphs and persistent memory across conversation compaction. Creates issues, tracks blockers, lists dependencies, updates status, and recovers project context. Use when work spans sessions, has blockers, needs context recovery after compaction, or requires task tracking beyond a single conversation."
allowed-tools: "Read,Bash(br:*)"
version: "0.43.0"
author: "Steve Yegge <https://github.com/steveyegge>"
license: "MIT"
---

# Beads (br) - Persistent Task Memory for AI Agents

Graph-based issue tracker that survives conversation compaction. Provides persistent memory for multi-session work with complex dependencies.

## br vs TodoWrite

| br (persistent) | TodoWrite (ephemeral) |
|-----------------|----------------------|
| Multi-session work | Single-session tasks |
| Complex dependencies | Linear execution |
| Survives compaction | Conversation-scoped |
| Git-backed, team sync | Local to session |

**Decision test**: "Will I need this context in 2 weeks?" → YES = br

## Prerequisites

```bash
br version  # verify br CLI is installed and in PATH
```

- **Git repository** required (br stores issues in SQLite, exports to JSONL for git)
- **Fresh clone**: If `.beads/beads.db` is missing, hydrate: `br sync --import-only --db .beads/beads.db`

## CLI Reference

Run `br <command> --help` for specific command usage.

Essential commands: `br ready`, `br create`, `br show`, `br update`, `br close`, `br sync --flush-only`

## Session Protocol

1. `br ready` — Find unblocked work
2. `br show <id>` — Get full context
3. `br update <id> --status in_progress` — Start work
4. `br update <id> --note "..."` — Add notes as you work (critical for compaction survival)
5. `br close <id> --reason "..."` — Complete task
6. Export and commit:
   ```bash
   br sync --flush-only
   git add .beads/issues.jsonl && git commit -m "Update issues" && git push
   ```

**If `br ready` returns empty**: Check `br list --status open` for blocked work, or create new issues with `br create`.
**If sync fails**: Re-run `br sync --import-only` to re-hydrate from the JSONL, then retry.

## Full Documentation

- `br --help` / `br <command> --help`
- GitHub: https://github.com/Dicklesworthstone/beads_rust
