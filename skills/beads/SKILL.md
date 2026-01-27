---
name: beads
description: >
  Git-backed issue tracker for multi-session work with dependencies and persistent
  memory across conversation compaction. Use when work spans sessions, has blockers,
  or needs context recovery after compaction.
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

**Decision test**: "Will I need this context in 2 weeks?" -> YES = br

**When to use br**:
- Work spans multiple sessions or days
- Tasks have dependencies or blockers
- Need to survive conversation compaction
- Exploratory/research work with fuzzy boundaries
- Collaboration with team (git sync)

**When to use TodoWrite**:
- Single-session linear tasks
- Simple checklist for immediate work
- All context is in current conversation
- Will complete within current session

## Prerequisites

```bash
br version
```

- **br CLI** installed and in PATH
- **Git repository** (br stores issues in SQLite, exports to JSONL for git)
- **Fresh clone**: If `.beads/beads.db` is missing, hydrate it from `.beads/issues.jsonl`:
  - `br sync --import-only --db .beads/beads.db`

## CLI Reference

Run `br <command> --help` for specific command usage.

Essential commands: `br ready`, `br create`, `br show`, `br update`, `br close`, `br sync --flush-only`

## Session Protocol

1. `br ready` - Find unblocked work
2. `br show <id>` - Get full context
3. `br update <id> --status in_progress` - Start work
4. Add notes as you work (critical for compaction survival)
5. `br close <id> --reason "..."` - Complete task
6. Export issue changes and commit/push:
   - `br sync --flush-only`
   - `git add .beads/issues.jsonl && git commit -m "Update issues" && git push`

## Full Documentation

- `br --help`
- GitHub: https://github.com/Dicklesworthstone/beads_rust
