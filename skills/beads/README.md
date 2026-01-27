# Beads (br) Skill for Claude Code

A skill for using `br` (beads_rust) issue tracking with Claude Code.

## What This Skill Does

This skill teaches Claude Code how to use br effectively for:
- **Multi-session work tracking** - Persistent memory across conversation compactions
- **Dependency management** - Graph-based issue relationships
- **Session handoff** - Writing notes that survive context resets

## Installation

Copy the `beads/` directory to your Claude Code skills location:

```bash
# Global installation
cp -r beads ~/.claude/skills/

# Or project-local
cp -r beads .claude/skills/
```

## When Claude Uses This Skill

The skill activates when conversations involve:
- "multi-session", "complex dependencies", "resume after weeks"
- "project memory", "persistent context", "side quest tracking"
- Work that spans multiple days or compaction cycles
- Tasks too complex for simple TodoWrite lists

## File Structure

```
beads/
├── SKILL.md                 # Main skill file (Claude reads this first)
├── CLAUDE.md                # Maintenance guide for updating the skill
├── README.md                # This file (for humans)
└── resources/               # Legacy reference docs (may not match br feature set)
```

## Key Concepts

### br vs TodoWrite

| Use br when... | Use TodoWrite when... |
|----------------|----------------------|
| Work spans multiple sessions | Single-session tasks |
| Complex dependencies exist | Linear step-by-step work |
| Need to resume after weeks | Just need a quick checklist |
| Knowledge work with fuzzy boundaries | Clear, immediate tasks |

### The Dependency Direction Trap

`br dep add A B` means **"A depends on B"** (B must complete before A can start).

```bash
# Want: "Setup must complete before Implementation"
br dep add implementation setup  # CORRECT
# NOT: br dep add setup implementation  # WRONG
```

### Surviving Compaction

When Claude's context gets compacted, conversation history is lost but br state survives. Write notes as if explaining to a future Claude with zero context:

```bash
br update issue-123 --notes "COMPLETED: JWT auth with RS256
KEY DECISION: RS256 over HS256 for key rotation
IN PROGRESS: Password reset flow
NEXT: Implement rate limiting"
```

## Requirements

- br installed: https://github.com/Dicklesworthstone/beads_rust
- A git repository (issues exported to `.beads/issues.jsonl` for sync)

## License

MIT
