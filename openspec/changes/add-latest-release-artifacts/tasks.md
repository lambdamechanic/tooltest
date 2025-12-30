## 1. Proposal Validation
- [ ] 1.1 Run `openspec validate add-latest-release-artifacts --strict` and resolve any errors

## 2. Implementation
- [ ] 2.1 Add release build job to `.github/workflows/ci.yml` for main merges
- [ ] 2.2 Build and package `tooltest` CLI for linux-x86_64, linux-aarch64, macos-arm64, windows-x86_64
- [ ] 2.3 Publish/overwrite `latest` GitHub Release assets for each architecture
- [ ] 2.4 Upload workflow artifacts for build history with configured retention
- [ ] 2.5 Add installer script that detects OS/arch and downloads matching asset
- [ ] 2.6 Document installer and direct URLs in README

## 3. Validation
- [ ] 3.1 Verify CI produces release assets on main
- [ ] 3.2 Validate installer downloads the correct asset per architecture
