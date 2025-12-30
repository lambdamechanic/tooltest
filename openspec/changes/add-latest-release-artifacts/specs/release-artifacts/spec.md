## ADDED Requirements
### Requirement: Latest release artifacts for tooltest CLI
The system SHALL publish a `latest` GitHub Release on every merge to `main` containing tooltest CLI binaries for linux-x86_64, linux-aarch64, macos-arm64, and windows-x86_64.

#### Scenario: Merge to main publishes latest assets
- **WHEN** a commit is merged to `main`
- **THEN** the `latest` release is created or updated
- **AND** each architecture has a downloadable binary asset

### Requirement: Stable download URLs and installer
The system SHALL provide stable download URLs for the `latest` release assets and a `curl | bash` installer that selects the correct asset by OS/architecture.

#### Scenario: User installs via script
- **WHEN** a user runs the installer script
- **THEN** the script detects the host OS and architecture
- **AND** downloads the matching `latest` asset

#### Scenario: User downloads directly
- **WHEN** a user requests the documented URL
- **THEN** the `latest` asset is downloadable without additional parameters

### Requirement: Build history via workflow artifacts
The system SHALL upload workflow artifacts for each architecture to keep a short-term history of builds, with a configurable retention period.

#### Scenario: CI run stores artifacts
- **WHEN** the release job completes
- **THEN** artifacts for each architecture are uploaded
- **AND** the retention period is applied as configured
