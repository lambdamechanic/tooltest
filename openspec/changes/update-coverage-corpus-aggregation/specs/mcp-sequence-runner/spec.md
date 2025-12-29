## ADDED Requirements
### Requirement: Coverage Corpus Aggregation
The system SHALL aggregate mined corpus values across all proptest cases for final coverage computation.

#### Scenario: Coverage warnings use aggregated corpus
- **WHEN** earlier cases mine valid inputs for a tool
- **THEN** coverage warnings consider the aggregated corpus, even if the final case lacks those inputs
