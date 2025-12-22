## ADDED Requirements

### Requirement: Schema constraint coverage gaps
The system SHALL include tests that demonstrate the current input generator does not enforce string constraints `minLength`, `maxLength`, and `pattern`.

#### Scenario: String constraints are ignored today
- **WHEN** the generator builds inputs from a schema that includes `minLength`, `maxLength`, or `pattern`
- **THEN** tests show the generated values can violate those constraints

### Requirement: Invalid-input generator for constraint validation
The system SHALL provide an internal generator that produces a JSON object that is otherwise valid but violates exactly one schema constraint.

#### Scenario: Single-constraint violation generation
- **WHEN** given a schema with constraints
- **THEN** the generator returns an object that matches all constraints except one
- **AND** the violated constraint is detectable for warning reporting
