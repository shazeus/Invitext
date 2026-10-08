# Changelog

All notable changes are recorded here. Versions follow Semantic Versioning.

## 0.3.0 - 2026-10-08

- Added encrypted binary attachments with `hide --file PATH` in append and PNG stealth modes. ZIP, PDF, and other files are restored byte for byte, without text encoding.
- Added `extract -o PATH` (alias `unpack`) with indexed append-record selection, explicit output paths, safe overwrite defaults, and JSON size/hash reporting.
- Added encrypted filename metadata, bounded file-body parsing, a 128 MiB attachment limit, and file/text identification in append listings.
- Extended deep verification to authenticate both text and file payloads. Existing text carriers remain readable; older releases reject attachment flags.
- Fixed compressed PNG text decoding and recoverability of authenticated 0.2.0 compressed-text carriers.
- Made append compression conditional on reducing size, bounded reads against files growing during input, and removed the unlink gap when replacing outputs.
- Updated the README, format specifications, and portable usage guides with file-in-file workflows and security limits.
- The old `extract` alias for text reveal is now a file extraction command. Use `reveal`, `decode`, or `show` for text.

## 0.2.0 - 2026-08-28

- Added password-keyed, content-adaptive embedding for non-animated 8-bit PNG carriers.
- Added Hamming `(7,3)` matrix coding and a conservative 1.43% maximum color-channel change policy.
- Removed public magic, lengths, labels, timestamps, and flags from PNG stealth carriers; metadata lives inside an authenticated encrypted envelope.
- Added `--mode stealth` to `hide`, `reveal`, and `verify` while preserving append format v1 and existing command behavior.
- Added PNG capacity reporting to `inspect` and explicit rejection of unsupported image layouts.
- Added round-trip, wrong-password, low-density, alpha-preservation, capacity, CLI, and public-signature tests.
- Documented the construction, operational limits, non-detectability disclaimer, and lack of lossless stripping.

## 0.1.1 - 2026-08-28

- Added install-free portable bundles for Windows, Linux, Intel macOS, and Apple Silicon macOS.
- Windows release binaries now statically link the C runtime.
- Linux release binaries now target musl for a self-contained executable.
- Added double-clickable portable terminal launchers and USB-specific usage notes.
- Updated GitHub Actions and runtime dependencies to their current supported releases.

## 0.1.0 - 2026-08-28

- Initial versioned Invitext container format.
- Optional Argon2id and XChaCha20-Poly1305 encryption.
- zstd compression and BLAKE3 carrier/payload integrity checks.
- Multiple notes per carrier with indexed reveal and one-record removal.
- Streaming writes for large carrier files.
- Safe output defaults, explicit in-place mode, JSON output, and shell completions.
- Linux, macOS, and Windows release builds.
