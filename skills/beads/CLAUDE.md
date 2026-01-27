# Beads Skill Maintenance Guide

## Architecture Decisions

ADRs in `adr/` document key decisions. These are NOT loaded during skill invocation - they're reference material for maintainers making changes.

| ADR | Decision |
|-----|----------|
| [ADR-0001](adr/0001-bd-prime-as-source-of-truth.md) | Use `br --help` as the CLI reference source of truth |

## Key Principle: DRY via br --help

Do not duplicate detailed CLI syntax in `SKILL.md` or resources.

- `br --help` provides the top-level command set
- `br <command> --help` provides specific usage
- The upstream repo README documents install and sync semantics

**SKILL.md should only contain:**
- Decision frameworks (br vs TodoWrite)
- Prerequisites (install verification)
- Resource index (progressive disclosure)
- Pointers to `br --help`

## Keeping the Skill Updated

### When br releases a new version:

1. **Check for new features**: `br --help` for new commands
2. **Update SKILL.md frontmatter**: `version: "X.Y.Z"`
3. **Add resources for conceptual features** only when needed
4. **Don't add CLI reference** - that's `br --help`'s job

### What belongs in resources:

| Content Type | Belongs in Resources? | Why |
|--------------|----------------------|-----|
| Conceptual frameworks | ✅ Yes | `br --help` doesn't explain "when to use" |
| Decision trees | ✅ Yes | Cognitive guidance, not CLI reference |
| Advanced patterns | ✅ Yes | Depth beyond `--help` |
| CLI command syntax | ❌ No | Use `br <cmd> --help` |
| Workflow checklists | ❌ No | Keep in project `AGENTS.md` if needed |

### Resource update checklist:

```
[ ] Check if br docs / `br --help` now cover this content
[ ] If yes, remove from resources (avoid duplication)
[ ] If no, update resource for new br version
[ ] Update version compatibility in README.md
```

## File Roles

| File | Purpose | When to Update |
|------|---------|----------------|
| SKILL.md | Entry point, resource index | New features, version bumps |
| README.md | Human docs, installation | Structure changes |
| CLAUDE.md | This file, maintenance guide | Architecture changes |
| adr/*.md | Decision records | When making architectural decisions |
| resources/*.md | Deep-dive guides | New conceptual content |

## Testing Changes

After skill updates:

```bash
# Verify SKILL.md is within token budget
wc -w skills/beads/SKILL.md  # Target: 400-600 words

# Verify links resolve
# (Manual check: ensure all resource links in SKILL.md exist)

# Spot check the CLI surface
br --help | head -20
```

## Attribution

Resources adapted from other sources should include attribution header:

```markdown
# Resource Title

> Adapted from [source]
```
