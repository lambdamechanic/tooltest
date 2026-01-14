## 1. Implementation
- [x] 1.1 Add CLI flag and config plumbing for in-band error handling
- [x] 1.2 Update runner default assertions to honor the flag and classify non-fatal in-band errors
- [x] 1.3 Ensure coverage tracking continues to exclude in-band error responses
- [x] 1.4 Add tests for default non-fatal behavior and flag-preserved failure behavior
- [x] 1.5 Run tests and coverage gates
## 2. Dependencies
- 1.2 depends on 1.1
- 1.4 depends on 1.2 and 1.3
- 1.5 depends on 1.4
