## MODIFIED Requirements
### Requirement: Proptest-Based Invocation Generation
The system SHALL generate tool invocation sequences using proptest strategies derived from MCP tool schemas and a configurable sequence length range. The generator SHALL support anyOf/union schemas (including nullable unions such as string|null) so long as each branch is otherwise supported.

#### Scenario: Sequence length respects configuration
- **WHEN** a run is configured with a sequence length range
- **THEN** generated sequences contain a number of invocations within that range

#### Scenario: Tool predicate filters invocations
- **WHEN** a tool predicate is supplied
- **THEN** only tools accepted by the predicate are eligible for sequence generation

#### Scenario: anyOf union selects a valid branch
- **WHEN** a tool input schema uses anyOf to define multiple valid shapes
- **THEN** generated inputs match at least one of the anyOf branches

#### Scenario: Nullable union accepts null
- **WHEN** a tool input schema allows string|null for a property
- **THEN** generated inputs may include null or string values for that property
