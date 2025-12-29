## ADDED Requirements
### Requirement: Text Mining for State Corpus
When enabled, the system SHALL mine textual outputs into the state-machine corpus by splitting text on whitespace and classifying tokens as strings or numbers.

#### Scenario: Text mining off by default
- **WHEN** text mining is not enabled
- **THEN** textual outputs do not add values to the state corpus

#### Scenario: Text mining seeds numbers and strings
- **WHEN** text mining is enabled and a tool response includes textual content
- **THEN** whitespace-delimited tokens that parse as numbers are added to the number corpus
- **AND** remaining tokens are added to the string corpus
