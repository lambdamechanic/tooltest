# Changelog

## [Unreleased]
- Initial workspace release.
- Default tool `isError` responses no longer fail runs; use `--in-band-error-forbidden` to preserve the old behavior. Static output schema validation still applies, so tools with output schemas must return valid `structuredContent` even on errors.
