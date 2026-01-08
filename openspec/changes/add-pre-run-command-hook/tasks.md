## 1. Implementation
- [x] 1.1 Add CLI option to configure a pre-run command (JSON array argv) and parse it into run configuration.
- [x] 1.2 Execute the pre-run command before each proptest case for stdio, HTTP, and session runs.
- [x] 1.3 Treat non-zero exits as run failures and include captured stdout/stderr in failure details.
- [x] 1.4 Add tests covering command success, failure, and per-case invocation.
- [x] 1.5 Update CLI help and documentation for the new flag.
