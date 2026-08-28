# Contributing

Bug reports and focused pull requests are welcome. Before changing either storage layout, open an issue: old files must remain readable, and silent format drift is worse than a slightly slower release. Changes to candidate ranking, fingerprinting, placement, matrix coding, KDF parameters, or envelope layout are format changes even if the CLI stays the same.

For code changes, run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

New parsing behavior should include a malformed-input test. New CLI behavior should include an integration test that invokes the real `itx` binary.

Stealth changes must also test password determinism, cover-fingerprint stability, per-channel modification bounds, unsupported PNG layouts, capacity enforcement, and round-trip compatibility with an artifact written before the implementation change.
