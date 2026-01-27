# llvm-cov mismatch warnings

Running `cargo llvm-cov --workspace --fail-under-lines 100 --fail-under-regions 100`
still emits:

```
warning: 31 functions have mismatched data
```

## Identify the mismatched functions

1. Run `cargo llvm-cov -v --workspace --fail-under-lines 100 --fail-under-regions 100`
   and capture the `llvm-cov report ...` command it prints.
2. Re-run that exact `llvm-cov report` command with `--dump` appended.
3. Look for `hash-mismatch:` lines in stderr.

With the current workspace, the mismatched functions reported are:

```
_RNvMsa_NtCsaaNauVfvEG4_9hashbrown3rawNtB5_13RawTableInner10find_inner
_RNvNtCsaaNauVfvEG4_9hashbrown4util8unlikely
_RNvXso_NtCsh26fxMtYdfR_12tracing_core8metadataNtB5_11LevelFilterNtNtCs3XFJfFEDSOQ_4core3cmp3Ord3cmp
_RNvXsv_NtCsaaNauVfvEG4_9hashbrown3rawNtB5_18FullBucketsIndicesNtNtNtNtCs3XFJfFEDSOQ_4core4iter6traits8iterator8Iterator4next
```

These come from dependency crates (`hashbrown`, `tracing_core`). The overall
warning count is the sum across objects, so the same 3-4 functions are repeated
per object during the combined report.

`llvm-profdata merge` does not emit this warning; it appears during `llvm-cov report`
when loading the combined profile against multiple objects.

## Suppression

`llvm-cov report --no-warn` silences the warnings, but `cargo llvm-cov` does not
currently expose a way to pass that flag directly.
