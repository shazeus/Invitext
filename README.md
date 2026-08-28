# Invitext

Invitext hides text notes inside ordinary files. The carrier still opens as the same image, archive, document, or media file; Invitext stores its note in an authenticated trailer after the carrier's original bytes.

The short command is `itx`. The full `invitext` command is installed alongside it and behaves identically.

```console
$ itx hide photo.jpg -m "The spare key is in the blue box" --encrypt
New password:
Confirm password:
Hidden note #1 in photo.invitext.jpg
84.3 KiB total · encrypted

$ itx reveal photo.invitext.jpg
Password:
The spare key is in the blue box
```

Invitext is deliberately boring about the important parts: it does not invent its own cipher, overwrite the source file by default, or pretend that appending data is invisible to forensic tools.

## What it does

- Adds one or more text notes to the same carrier file.
- Encrypts notes with XChaCha20-Poly1305 and derives keys with Argon2id.
- Compresses text with zstd before encryption.
- Detects a changed carrier, damaged payload, and incorrect password as separate failures.
- Reads and writes large carriers as streams instead of loading a multi-gigabyte archive into RAM.
- Provides human-readable output and stable `--json` output for scripts.
- Replaces files through a same-directory temporary file when `--in-place` is requested.
- Accepts text from an argument, a UTF-8 file, or stdin.

There is no extension allowlist. Invitext can append a note to any regular file, but whether the carrier's usual application accepts trailing data depends on its format.

## Install

Prebuilt archives for macOS, Linux, and Windows are attached to tagged [GitHub releases](https://github.com/shazeus/Invitext/releases).

With Rust installed:

```sh
cargo install --git https://github.com/shazeus/Invitext --locked
```

Or build the checkout:

```sh
cargo build --release
```

Both executables are produced:

```text
target/release/itx
target/release/invitext
```

On Windows they have the usual `.exe` suffix.

## Everyday use

Hide a short note without encryption:

```sh
itx hide report.pdf -m "Reviewed on 2026-08-28"
```

Hide the contents of a text file and label the note:

```sh
itx hide backup.zip --message-file recovery.txt --label "recovery instructions" --encrypt
```

Pipe text without putting it in shell history:

```sh
printf '%s' 'private text' | itx hide image.png --encrypt --password-env ITX_PASSWORD
```

List notes without revealing their contents:

```console
$ itx list image.invitext.png
2 note(s) in image.invitext.png
  #1   encrypted  intact     2026-08-28T09:31:04Z · 312 B
  #2   plain      intact     2026-08-28T09:34:51Z · 228 B
```

Reveal the newest note (the default), a specific note, or every note:

```sh
itx reveal image.invitext.png
itx reveal image.invitext.png --index 1
itx reveal image.invitext.png --all
itx reveal image.invitext.png --output note.txt
```

Check integrity without exposing text:

```sh
itx verify image.invitext.png
itx verify image.invitext.png --deep --index 1
```

Remove Invitext data while keeping the carrier bytes exactly as they were:

```sh
itx strip image.invitext.png                 # new image.invitext.clean.png
itx strip image.invitext.png --latest        # keep older notes
itx strip image.invitext.png --in-place      # explicit replacement
```

Inspect a carrier before using it:

```sh
itx inspect archive.rar
```

Generate completions for Bash, Zsh, Fish, PowerShell, or Elvish:

```sh
itx completions zsh > _itx
itx completions powershell > _itx.ps1
```

Run `itx <command> --help` for every option and alias.

## Password handling

An explicit `--password` enables encryption, but the password can be visible in process listings and shell history. Interactive prompting is the safest convenient default. Automation should use a protected password file or an environment variable:

```sh
itx hide plans.pdf -m "..." --encrypt --password-file ./secret.pass
itx reveal plans.invitext.pdf --password-env ITX_PASSWORD
```

Three Argon2id presets are available:

| Preset | Memory | Passes | Intended use |
| --- | ---: | ---: | --- |
| `interactive` | 32 MiB | 2 | Tests and resource-constrained systems |
| `standard` | 64 MiB | 3 | Default for normal use |
| `hardened` | 128 MiB | 4 | Stronger offline-guessing resistance |

The parameters and random salt are stored with the encrypted note. The password is not stored.

## Carrier compatibility

Appending data is widely tolerated, but not guaranteed by every parser.

| Carrier family | Typical result | Notes |
| --- | --- | --- |
| JPEG, PNG, GIF, WebP | Good | Most viewers ignore bytes after the image terminator. Editors may discard them when re-saving. |
| ZIP, RAR, 7z, tar, gzip | Good | Mainstream extractors commonly accept a trailing record. Strict validators may warn. |
| PDF | Good | Readers normally locate the final cross-reference data before the Invitext trailer. Rewriting the PDF can remove the note. |
| MP3, WAV, FLAC, MP4, MOV, MKV | Usually good | Test the player or editing pipeline you actually use. |
| DOCX, XLSX, PPTX, APK, JAR | Mixed | These are ZIP-based. Signed packages can fail signature verification after any byte is added. |
| EXE, DLL, app bundles | Avoid | Code signing and platform integrity checks are likely to fail. |

Invitext never modifies bytes already present in the carrier. `strip` can therefore recover the exact pre-Invitext byte sequence unless another program has rewritten the file in the meantime.

## Security model

Encrypted notes use:

- Argon2id v1.3 for password-based key derivation;
- a fresh 128-bit salt per note;
- XChaCha20-Poly1305 with a fresh 192-bit nonce;
- the complete payload header as authenticated additional data;
- BLAKE3 hashes for carrier and payload integrity;
- bounded KDF and decompression parameters when reading untrusted files.

Labels are inside the encrypted body. The public trailer still reveals that Invitext data exists, its approximate size, creation time, and whether it is encrypted. This is an encrypted container, not deniable steganography.

Without a password, an unencrypted note is only encoded and compressed. Anyone can recover it by implementing the [documented format](FORMAT.md). “Only Invitext can decode it” should be understood as tool compatibility, not a security boundary; actual confidentiality comes from encryption and a strong password.

No independent cryptographic audit has been completed. Do not make Invitext the only copy of critical secrets. See [SECURITY.md](SECURITY.md) for reporting and operational guidance.

## Format and stability

The on-disk format is versioned. Invitext v0.1 writes format version 1 and refuses unknown versions instead of guessing. The byte-level layout and validation order are documented in [FORMAT.md](FORMAT.md).

The note chain is append-only: adding a second note treats the first complete Invitext file as its carrier. This makes note order unambiguous and lets `strip --latest` remove exactly one record.

## Development

The project requires Rust 1.88 or newer.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release --locked
```

The CLI integration tests exercise both executable names, encrypted and unencrypted round trips, wrong passwords, JSON output, and byte-exact restoration of the original carrier.

## License

Invitext is released under the [MIT License](LICENSE).
