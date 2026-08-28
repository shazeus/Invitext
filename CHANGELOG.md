# Changelog

All notable changes are recorded here. Versions follow Semantic Versioning.

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
