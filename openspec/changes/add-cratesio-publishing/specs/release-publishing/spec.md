## ADDED Requirements

### Requirement: crates.io publishing via release-plz
The project SHALL publish the `tooltest` and `tooltest-core` crates to crates.io using a release-plz-driven workflow on the main branch, and SHALL NOT publish `tooltest-test-support`.

#### Scenario: Release PR created
- **WHEN** changes are pushed to `main`
- **THEN** the release-plz workflow creates or updates a release PR with workspace version bumps and changelog updates

#### Scenario: Release publish
- **WHEN** a release PR is merged to `main`
- **THEN** release-plz publishes `tooltest` and `tooltest-core` to crates.io and tags the release

### Requirement: Published crate naming
The CLI package SHALL be published to crates.io as `tooltest` and remain the primary install target for end users.

#### Scenario: Cargo package name
- **WHEN** the CLI crate is published
- **THEN** its package name is `tooltest` on crates.io

### Requirement: Publishable crate metadata
Publishable crates SHALL include the metadata required by crates.io (description, repository, and readme).

#### Scenario: crates.io validation
- **WHEN** a publish is attempted
- **THEN** Cargo metadata validation passes without missing-field errors

### Requirement: Release secrets and changelog conventions
Release-plz SHALL use `CARGO_REGISTRY_TOKEN` for crates.io publishing and SHALL manage `CHANGELOG.md` files in conventional locations for the workspace crates.

#### Scenario: Release secrets and changelog updates
- **WHEN** release-plz runs on `main`
- **THEN** it uses `CARGO_REGISTRY_TOKEN` and updates the relevant `CHANGELOG.md` files alongside the version bumps
