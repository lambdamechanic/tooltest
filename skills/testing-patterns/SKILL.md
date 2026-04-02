---
name: testing-patterns
description: “Guides writing unit tests, integration tests, and property-based tests (proptest) for this Rust codebase. Covers effect abstraction via traits, fakes vs mocks, async test patterns, and coverage standards. Use when writing tests, choosing between fakes and mocks, setting up property-based tests, testing async effects, or reviewing test coverage in this codebase.”
---

# Testing Patterns & Effect Abstraction

Model effects as traits, inject them, keep core logic pure, provide real + fake implementations.

---

## Pattern

- **Define algebras as traits** (ports).
- **Implement adapters** for prod (HTTP, DB, clock, FS) and for tests (fakes/mocks).
- **Inject via generics** (zero-cost, monomorphized) or **trait objects** (`dyn Trait`) when you need late binding.
- Keep domain functions pure; pass in effect results or tiny capability traits.

### Minimal sync example

```rust
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock {
    fn now(&self) -> SystemTime;
}

pub trait Payments {
    type Err;
    fn charge(&self, cents: u32, card: &str) -> Result<String, Self::Err>; // returns ChargeId
}

pub struct Service<P, C> {
    pay: P,
    clock: C,
}

impl<P, C> Service<P, C>
where
    P: Payments,
    C: Clock,
{
    pub fn bill(&self, card: &str, cents: u32) -> Result<String, P::Err> {
        let _ts = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // domain logic… (e.g., time-based rules)
        self.pay.charge(cents, card)
    }
}

// --- prod adapters ---
pub struct RealClock;
impl Clock for RealClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub struct StripeClient;
impl Payments for StripeClient {
    type Err = String;
    fn charge(&self, cents: u32, _card: &str) -> Result<String, Self::Err> {
        // call real API
        Ok(format!("ch_{cents}"))
    }
}

// --- test fakes ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::time::{Duration, SystemTime};

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    struct FakePayments {
        pub calls: RefCell<Vec<(u32, String)>>,
        pub next: RefCell<Result<String, String>>,
    }
    impl Payments for FakePayments {
        type Err = String;
        fn charge(&self, cents: u32, card: &str) -> Result<String, Self::Err> {
            self.calls.borrow_mut().push((cents, card.to_string()));
            self.next.borrow_mut().clone()
        }
    }

    #[test]
    fn happy_path() {
        let svc = Service {
            pay: FakePayments {
                calls: RefCell::new(vec![]),
                next: RefCell::new(Ok("ch_42".into())),
            },
            clock: FixedClock(SystemTime::UNIX_EPOCH + Duration::from_secs(123)),
        };

        let id = svc.bill("4111...", 4200).unwrap();
        assert_eq!(id, "ch_42");
    }
}
```

Prod wiring stays simple:

```rust
let svc = Service { pay: StripeClient, clock: RealClock };
```

### Trait objects (dynamic dispatch when needed)

```rust
pub struct Svc<'a> {
    pay: &'a dyn Payments<Err = String>,
    clock: &'a dyn Clock,
}
```

Ensure traits are object-safe (no generic methods, no `impl Trait` returns).

---

## Async Effects

1. **`async-trait` macro** – ergonomic, small overhead:

```rust
use async_trait::async_trait;

#[async_trait]
pub trait Http {
    async fn get(&self, url: &str) -> Result<String, anyhow::Error>;
}
```

2. **RPITIT** (return-position `impl Trait` in traits) for macro-free, low-overhead code:

```rust
use core::future::Future;

pub trait Http {
    fn get(&self, url: &str) -> impl Future<Output = Result<String, anyhow::Error>> + Send;
}
```

Pick #1 for simplicity, #2 if you want zero-macro builds and control over allocations.

---

## Mocks vs. Fakes

- Prefer hand-rolled fakes/stubs or in-memory adapters.
- If you need expectation-based mocks:
  - `mockall` for general traits.
  - `wiremock` / `httpmock` for HTTP.
- For FS/DB, lean on temp dirs (`tempfile`, `assert_fs`) or in-memory backends.

---

## Tips

- Don’t over-abstract; put traits only at IO boundaries (time, network, FS, DB).
- In async code, wrap shared deps in `Arc<dyn Trait + Send + Sync>` when needed.
- Return owned data (`Vec<T>`) from trait methods to avoid lifetime tangles.
- Keep domain logic as pure functions over data; invoke effects at the edges.
- For CLI flows, lean on `tests/support/mod.rs` (`CliFixture`, `RemoteRepo`, and helpers that pre-wire `SK_CACHE_DIR`/`SK_CONFIG_DIR`) so every integration test spins up the same deterministic temp repos.

---

## Testing Standards

- **Coverage gate: 45% (cargo llvm-cov).** CI currently enforces `cargo llvm-cov --fail-under-lines 45`. Treat that as the floor, not the ceiling—once `main` sits comfortably above a higher percentage, ratchet the workflow file and avoid ever lowering the bar without a written justification.
- **Business logic ⇒ property tests.** Use `proptest` for any non-trivial domain rule (scheduling, diffing, parsing, state machines, etc.). Unit tests that check a couple of examples aren’t enough; capture invariants as properties.
- **Structure:** keep property tests in `tests` modules alongside unit tests, e.g.:

```rust
#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fee_is_never_negative(amount in 0u64..) {
            let fee = compute_fee(amount);
            prop_assert!(fee >= 0);
        }
    }
}
```

- **Make generators realistic.** Compose `any::<T>()`, `prop::collection`, or custom strategies so you’re exercising edge cases (empty, max values, random ordering).
- **Integration tests still matter.** Use harnesses under `tests/` or `crates/*/tests/` to cover end-to-end flows (e.g., env lifecycle, DB migrations) but keep them deterministic—no real network calls.

When in doubt, assume reviewers will ask “where’s the property test?” and “what’s the coverage delta?” Bake both answers into the PR.

---

## Property-Based Testing Workflow (proptest)

1. **Identify high-value properties.** Start with public API or core modules. Look for invariants (round trips, idempotence, ordering guarantees). Skip trivial wrappers.
2. **Study usage.** Grep the repo to see how the function/struct is consumed so strategies stay within real-world preconditions.
3. **Write precise `proptest` cases.** Few high-signal tests beat shotgun suites. Favor `prop::collection`, `any::<T>()`, `from_regex`; only add bounds when the code requires them.
4. **Use real generators.** Model inputs with strategies (vecs, maps, enums) instead of manual loops. Let generators produce arbitrarily long inputs unless the code has a hard limit.
5. **Run and reflect.** `cargo test` with property tests. If a failure exposes a gap, fix the bug or constrain the strategy with a documented reason.

Name properties after the behavior they document. Every non-trivial business rule should eventually have a companion `proptest!` block next to its unit tests.
