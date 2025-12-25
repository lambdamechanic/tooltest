#[cfg(all(test, not(feature = "stdio-test-server"), not(coverage)))]
compile_error!(
    "tooltest-core tests require the stdio-test-server feature; run `cargo test -p tooltest-core --features stdio-test-server`."
);
