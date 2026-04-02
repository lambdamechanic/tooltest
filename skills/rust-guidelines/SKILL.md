---
name: rust-guidelines
description: "Project-specific Rust conventions covering error handling, documentation standards, safety rules, performance patterns, library API design, and AI-friendly coding practices. Use when writing or reviewing Rust code, asking about idiomatic patterns, error handling, module structure, documentation standards, unsafe usage, or Rust best practices in this codebase."
---

<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT license. -->

# Pragmatic Rust Guidelines

Project-specific conventions organized by topic. Each section below links to detailed reference files — read the relevant reference when working in that area.

## Table of Contents

| Topic | Reference | Key Guidelines |
|-------|-----------|---------------|
| AI-friendly coding | [ai-guidelines.md](references/ai-guidelines.md) | M-DESIGN-FOR-AI: idiomatic APIs, thorough docs/examples, strong types, testable APIs |
| Application patterns | [application-guidelines.md](references/application-guidelines.md) | M-APP-ERROR (anyhow/eyre for apps), M-MIMALLOC-APPS (global allocator) |
| Documentation | [documentation.md](references/documentation.md) | M-CANONICAL-DOCS, M-DOC-INLINE, M-FIRST-DOC-SENTENCE (~15 words), M-MODULE-DOCS |
| FFI | [ffi-guidelines.md](references/ffi-guidelines.md) | M-ISOLATE-DLL-STATE: isolate state between FFI libraries |
| Performance | [performance-guidelines.md](references/performance-guidelines.md) | M-HOTPATH (profile early), M-THROUGHPUT (avoid empty cycles), M-YIELD-POINTS |
| Safety | [safety-guidelines.md](references/safety-guidelines.md) | M-UNSAFE-IMPLIES-UB, M-UNSAFE (avoid/justify), M-UNSOUND (all code must be sound) |
| Universal | [universal-guidelines.md](references/universal-guidelines.md) | Naming, logging, panics, errors, Debug/Display, static verification, clippy lints |
| Library building | [libraries-building.md](references/libraries-building.md) | Compile-time checks, feature flags, minimal dependencies |
| Library interop | [libraries-interoperability.md](references/libraries-interoperability.md) | Send+Sync, async compatibility, no platform-specific leaks |
| Library resilience | [libraries-resilience.md](references/libraries-resilience.md) | No glob re-exports, sealed traits, non-exhaustive enums |
| Library UX | [libraries-ux.md](references/libraries-ux.md) | Error types, DI hierarchy, builders, AsRef/RangeBounds, Clone services |

## Critical Rules (Always Apply)

### Error handling
- **Libraries**: canonical error structs with `Display`, `Debug`, `Error`, and backtrace (see [M-ERRORS-CANONICAL-STRUCTS](references/libraries-ux.md))
- **Applications**: use `anyhow`/`eyre` for ergonomic error propagation (see [M-APP-ERROR](references/application-guidelines.md))

### Safety
- `unsafe` implies potential undefined behavior — avoid unless required for FFI, performance (with benchmarks), or novel abstractions
- All code must be sound: no undefined behavior reachable from safe code
- Document safety invariants with `// SAFETY:` comments

### Naming & types
- No weasel words in names (`Manager`, `Helper`, `Utils`) — be precise
- Magic values must be named constants with doc comments
- Public types must derive `Debug`; types meant to be read must implement `Display`

### Logging
- Use structured logging with message templates, not string formatting
- Follow OpenTelemetry semantic conventions
- Redact sensitive data

### Panics
- Panics mean "stop the program" — never use for expected errors
- Detected programming bugs (invariant violations, unreachable states) should panic, not return `Err`

### Static verification
- Enable and configure clippy lints (see [lint configuration](references/universal-guidelines.md))
- Use `#[expect(...)]` instead of `#[allow(...)]` for lint overrides
