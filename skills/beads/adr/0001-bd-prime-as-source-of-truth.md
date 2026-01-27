# ADR-0001: Use br --help as CLI Reference Source of Truth

## Status

Accepted

## Context

This skill avoids duplicating detailed CLI syntax in multiple places:

- `SKILL.md` inline
- Resource files
- Scattered examples throughout resource files

Duplicating CLI syntax creates:
- **Duplication**: Same commands documented 2-3 times
- **Drift risk**: Documentation can fall behind br versions
- **Token overhead**: Large docs get loaded even for simple operations

Meanwhile, br provides structured CLI help via `br --help` and `br <command> --help`.

## Decision

Use `br --help` as the single source of truth for CLI commands:

1. **SKILL.md** contains only value-add content (decision frameworks, cognitive patterns)
2. **CLI reference** points to `br --help` and `br <command> --help`
3. **Resources** provide depth for conceptual guidance and patterns

## Consequences

### Positive

- **Zero maintenance**: CLI docs auto-update with br versions
- **DRY**: Single source of truth
- **Accurate**: No version drift possible
- **Lighter SKILL.md**: ~500 words vs ~3,300

### Negative

- **External tool requirement**: Skill assumes br is installed

## Implementation

Files structured so `SKILL.md` stays short and the CLI remains discoverable via `br --help`.

## Related

- Claude Code skill progressive disclosure guidelines
- Similar pattern implemented in other Claude Code skill ecosystems

## Date

2026-01-27
