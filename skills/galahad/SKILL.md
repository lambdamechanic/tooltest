---
name: galahad
description: “Enforces the Galahad Principle for type safety, test quality, and 100% coverage targets. Defines priority order (types > tests > clarity > performance), forbidden patterns (type escapes, coverage gaming), and the fix-root-cause workflow for failures. Use when writing tests, fixing type errors, reviewing coverage reports, or deciding whether to suppress a lint/warning.”
---

# Coding Agent Quality Rules (Galahad Principle)

Based on Jonathan Lange’s [The Galahad Principle](https://jml.io/galahad-principle/): **getting to 100% yields disproportionate value**—especially **simplicity** and **trust**. Any new failure is a strong, unambiguous signal.

## Non-negotiables: never evade feedback

Treat **type errors, test failures, pre-commit hooks, lint errors, and coverage warnings** as helpful feedback. Fix root causes.

### Absolutely forbidden (unless the user explicitly orders it)
- **Type escapes / silencing** — `any`, `as any`, `@ts-ignore`, `# type: ignore`, `noqa`, disabling strict mode, weakening compiler flags
- **Coverage gaming** — `/* istanbul ignore */`, `# pragma: no cover`, config exclusions, decorator/macro suppression
- **Faking results** — skipping CI steps, “snapshotting” coverage, lowering thresholds, marking tests flaky to ignore them

## Priorities

When tradeoffs exist, prioritize in this order:
1. **Type safety / soundness**
2. **Correctness + meaningful tests**
3. **Clarity / maintainability**
4. **Performance**
5. **Backwards compatibility** (lowest)

## Default workflow (when anything fails)

1. Read the failure output carefully.
2. Restate the real invariant being violated in plain English.
3. Fix the root cause (not the symptom).
4. Improve tests so the behavior is pinned and regressions get caught.
5. Refactor production code if needed to make it easy to type-check and validate.

### Run checks in this order
1. **Typecheck** → 2. **Unit tests** → 3. **Integration tests** → 4. **Lint / pre-commit** → 5. **Coverage**

## “Hard to test” means refactor

If something is hard to test or hard to type, treat it as a **design smell**. Refactor towards smaller pure functions, explicit data flow, clear boundaries between logic and side effects, and typed domain models.

**Before** (hard to test — hidden dependency):
```rust
fn process_order(order: &Order) -> Result<Receipt, Error> {
    let now = SystemTime::now(); // hidden side effect
    let rate = fetch_exchange_rate(order.currency)?; // hidden I/O
    Ok(Receipt { total: order.amount * rate, timestamp: now })
}
```

**After** (testable — explicit dependencies):
```rust
fn process_order(order: &Order, now: SystemTime, rate: f64) -> Receipt {
    Receipt { total: order.amount * rate, timestamp: now }
}
```

## Mocks: prefer explicit injection

Pass substitutable operations explicitly (function parameters or small interfaces) instead of monkeypatching. Only abstract operations that genuinely need substitution in tests (time, randomness, network, filesystem).

```rust
// Explicit dependency injection — testable without mocking frameworks
pub trait Clock { fn now(&self) -> SystemTime; }
pub struct Service<C: Clock> { clock: C }

// Test: inject a fake
struct FixedClock(SystemTime);
impl Clock for FixedClock { fn now(&self) -> SystemTime { self.0 } }
```

## What “good” looks like

- Types encode invariants; no “trust me” casts.
- Tests assert observable behavior (not implementation trivia).
- Coverage comes from exercising real behavior, not exclusions.
- If a thing can’t be verified cleanly, refactor until it can.

