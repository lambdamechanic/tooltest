## ADDED Requirements

### Requirement: Beads-sync sparse worktree convention
The system SHALL preserve a `beads-sync` worktree convention that:
- uses a dedicated git worktree at `.git/beads-worktrees/beads-sync`
- checks out the `beads-sync` branch
- uses git sparse-checkout to include only `/.beads/`

#### Scenario: Fresh clone recreates beads-sync worktree
- **WHEN** a developer clones the repository without an existing beads-sync worktree
- **THEN** the documented setup steps recreate a `beads-sync` worktree at `.git/beads-worktrees/beads-sync`
- **AND** sparse-checkout is enabled with pattern `/.beads/` only

#### Scenario: Hooks auto-create beads-sync on demand
- **WHEN** a git hook needs to update the `beads-sync` mirror branch and the `beads-sync` worktree does not exist
- **THEN** the hook creates the worktree at `.git/beads-worktrees/beads-sync`
- **AND** enables sparse-checkout with pattern `/.beads/` only
- **AND** checks out the `beads-sync` branch

### Requirement: Git hooks integrate br flush/import
The system SHALL provide br-native git hooks that keep the local `br` SQLite DB and `.beads/issues.jsonl` consistent across common git operations, and SHALL actively maintain the `beads-sync` mirror branch.

#### Scenario: Commit flushes JSONL
- **WHEN** a user runs `git commit`
- **THEN** the pre-commit hook flushes pending changes via `br sync --flush-only`
- **AND** `.beads/issues.jsonl` is staged if it changed
- **AND** the hook does not perform network operations (no push)

#### Scenario: Checkout/merge imports JSONL when changed
- **WHEN** a user runs `git checkout`, `git pull` (merge), or `git pull --rebase` and `.beads/issues.jsonl` changes
- **THEN** the post-checkout/post-merge/post-rewrite hook imports via `br sync --import-only`
- **AND** the hook is a no-op when `.beads/issues.jsonl` did not change

#### Scenario: Push updates beads-sync mirror branch
- **WHEN** a user runs `git push`
- **THEN** the pre-push hook flushes pending changes via `br sync --flush-only`
- **AND** the hook hard-blocks if `.beads/issues.jsonl` is modified in the working tree after the flush (i.e., would require committing `.beads/issues.jsonl` before pushing)
- **AND** the hook updates the `beads-sync` mirror branch to match the committed `.beads/issues.jsonl` being pushed
- **AND** the hook creates or hard-resets the mirror branch as needed to match the committed file content
- **AND** the hook pushes the mirror branch to the same remote as the push (e.g., `origin/beads-sync`)

#### Scenario: Hooks hard-block only on publish steps
- **WHEN** the pre-commit hook cannot flush via `br`
- **THEN** the hook fails the commit with a non-zero exit code
- **WHEN** the pre-push hook cannot flush via `br` or cannot update/push the `beads-sync` mirror branch
- **THEN** the hook fails the push with a non-zero exit code
- **WHEN** an import hook cannot import via `br`
- **THEN** the hook prints a warning with a manual recovery command and exits zero

#### Scenario: Hooks avoid recursion during beads-sync maintenance
- **WHEN** the pre-push hook updates the `beads-sync` mirror branch
- **THEN** nested hook invocations (from commits inside the `beads-sync` worktree) do not re-enter beads-sync maintenance
- **AND** the update completes without infinite recursion

### Requirement: bv robot triage is the default selection mechanism
The system SHALL document `bv` robot triage as the default way to choose the next issue to work on, and SHALL map the output to `br` commands.

#### Scenario: Pick next issue and claim it
- **WHEN** an agent runs `bv -robot-next`
- **THEN** the agent uses the returned `id` with `br show <id>`
- **AND** claims work with `br update <id> --status in_progress`

#### Scenario: Use full triage output for context
- **WHEN** an agent runs `bv -robot-triage`
- **THEN** the agent selects a recommended issue `id`
- **AND** uses `br show <id>` for details and dependencies
- **AND** claims work with `br update <id> --status in_progress`

#### Scenario: Ignore embedded bd commands in bv output
- **WHEN** `bv` output includes `claim_command` / `show_command` fields that reference `bd`
- **THEN** the documented workflow instructs the agent to ignore those fields
- **AND** to use `br show <id>` / `br update <id> --status in_progress` instead
