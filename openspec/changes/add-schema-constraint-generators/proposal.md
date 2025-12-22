# Change: add schema-constraint test coverage and invalid-input generator

## Why
We need explicit coverage showing that generation does not yet respect minLength/maxLength/pattern, and a generator that intentionally violates exactly one schema rule for validation warnings.

## What Changes
- Add tests that demonstrate current generators ignore minLength/maxLength/pattern constraints.
- Add a generator that produces an otherwise valid JSON object that violates exactly one schema constraint.
- Keep public API stable so generator internals can change without affecting consumers.

## Impact
- Affected specs: mcp-sequence-runner
- Affected code: tooltest-core generator and tests
