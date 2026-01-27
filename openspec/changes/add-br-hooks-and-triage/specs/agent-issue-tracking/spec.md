## ADDED Requirements

### Requirement: Beads-sync sparse worktree convention
The system SHALL preserve a `beads-sync` worktree convention that uses git sparse-checkout to include only `/.beads/`.

#### Scenario: Fresh clone recreates beads-sync worktree
- **WHEN** a developer clones the repository without an existing beads-sync worktree
- **THEN** the documented setup steps recreate a `beads-sync` worktree with sparse-checkout enabled for `/.beads/` only

### Requirement: Git hooks integrate br flush/import
The system SHALL provide git hooks that keep the local `br` SQLite DB and `.beads/issues.jsonl` consistent across common git operations, and SHALL actively maintain the `beads-sync` mirror branch.

#### Scenario: Commit flushes JSONL
- **WHEN** a user runs `git commit`
- **THEN** the pre-commit hook flushes pending changes via `br sync --flush-only`
- **AND** `.beads/issues.jsonl` is staged if it changed
- **AND** the hook commits the updated `.beads/issues.jsonl` to the `beads-sync` branch and pushes it to `origin/beads-sync`

#### Scenario: Checkout/merge imports JSONL when changed
- **WHEN** a user runs `git checkout` or `git pull` and `.beads/issues.jsonl` changes
- **THEN** the post-checkout/post-merge hook imports via `br sync --import-only`

#### Scenario: Hooks hard-block on beads sync failures
- **WHEN** a hook cannot flush/import via `br` or cannot update/push the `beads-sync` branch
- **THEN** the hook fails the git operation with a non-zero exit code

### Requirement: bv robot triage is the default selection mechanism
The system SHALL document `bv` robot triage as the default way to choose the next issue to work on, and SHALL map the output to `br` commands.

#### Scenario: Pick next issue and claim it
- **WHEN** an agent runs `bv -robot-next`
- **THEN** the agent uses the returned `id` with `br show <id>`
- **AND** claims work with `br update <id> --status in_progress`
