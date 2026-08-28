# Contributing

Bug reports and focused pull requests are welcome. Before changing the container layout, open an issue: old files must remain readable, and silent format drift is worse than a slightly slower release.

For code changes, run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

New parsing behavior should include a malformed-input test. New CLI behavior should include an integration test that invokes the real `itx` binary.

