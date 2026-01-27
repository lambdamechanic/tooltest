## ADDED Requirements

### Requirement: br is the canonical issue-tracking CLI
The system SHALL use `br` (beads_rust) as the canonical CLI for issue tracking in this repository, and repo agent-facing docs and skills SHALL not require `bd`.

#### Scenario: Agent instructions reference br commands
- **WHEN** an agent follows the workflow documented in `AGENTS.md`
- **THEN** issue tracking commands use `br` (e.g., `br ready`, `br show`, `br update`, `br close`)
- **AND** `bd` is not required to complete the documented workflow

#### Scenario: Issue sync uses explicit import/flush
- **WHEN** issue data is pulled from git and `.beads/issues.jsonl` changes
- **THEN** the workflow imports updates with `br sync --import-only`
- **AND** the workflow exports changes with `br sync --flush-only` before committing

### Requirement: br installation guidance avoids system keyring changes
The system SHALL document an installation path for `br` that does not require modifying system package-manager keyrings.

#### Scenario: Locked-down machine installation
- **WHEN** installing `br` on a machine where `/etc/apt/keyrings` cannot be modified
- **THEN** the documented installation path uses a release artifact download or uses the upstream installer with `--no-gum`

