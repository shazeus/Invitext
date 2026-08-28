# Invitext

Invitext hides encrypted text inside ordinary files. It has two deliberately different storage modes:

- `stealth` distributes one encrypted note through the color data of a supported PNG, without an Invitext footer or other fixed signature;
- `append` places a versioned, authenticated record after any carrier file and favors compatibility, capacity, and exact removal over concealment.

The short command is `itx`. The full `invitext` command is installed alongside it and behaves identically.

```console
$ itx hide photo.png --mode stealth -m "The spare key is in the blue box"
New password:
Confirm password:
Concealed one encrypted note in photo.invitext.png
612.4 KiB total · 281 channel changes · 1.429% policy ceiling

$ itx reveal photo.invitext.png --mode stealth
Password:
The spare key is in the blue box
```

Invitext is deliberately boring about the important parts: it does not invent its own cipher, overwrite the source file by default, or claim forensic undetectability. Stealth mode is designed to reduce obvious structural and statistical signals, not to defeat every possible analyst or comparison against the original image.

## What it does

- Provides password-keyed, content-adaptive PNG embedding with no public format marker.
- Uses Hamming matrix coding to encode three bits while changing at most one of seven selected channels.
- Enforces a conservative density ceiling and reports carrier capacity before anything is written.
- Adds one or more append-mode text notes to images, archives, documents, media, and other regular files.
- Encrypts notes with XChaCha20-Poly1305 and derives keys with Argon2id.
- Compresses text with zstd when compression makes it smaller.
- Detects a changed carrier, damaged payload, and incorrect password as separate failures where the storage format permits it.
- Reads and writes large append carriers as streams rather than loading a multi-gigabyte archive into memory.
- Provides human-readable output and stable `--json` output for scripts.
- Replaces files through a same-directory temporary file when `--in-place` is explicitly requested.
- Accepts text from an argument, a UTF-8 file, or stdin.

Append mode has no extension allowlist. Stealth mode is intentionally narrower: v1 supports non-animated, 8-bit grayscale, grayscale-alpha, RGB, and RGBA PNG files. Palette-indexed and animated PNGs are rejected instead of silently converted.

## Install

Prebuilt archives for macOS, Linux, and Windows are attached to tagged [GitHub releases](https://github.com/shazeus/Invitext/releases).

The release archives are portable: extract one to a USB drive or desktop folder and run it without installing Invitext. Windows and Linux builds include their runtime statically; macOS uses only system libraries. See [Portable use](PORTABLE.md) for the exact workflow and platform notes.

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

### Portable / USB

Download the archive matching the computer, extract it, and keep the whole folder on the USB drive:

```text
invitext-portable-windows-x86_64.zip
invitext-portable-linux-x86_64.tar.gz
invitext-portable-macos-x86_64.tar.gz
invitext-portable-macos-aarch64.tar.gz
```

On Windows, double-click `Invitext Portable.cmd`. On macOS, double-click `Invitext Portable.command`; if Gatekeeper quarantines a downloaded unsigned binary, follow the one-time command in [PORTABLE.md](PORTABLE.md). You can always run `itx` directly from an existing terminal.

## Low-density PNG embedding

Inspect a PNG before using it. Capacity varies with its dimensions, color layout, and transparent areas:

```console
$ itx inspect photo.png
File          photo.png
Type          image/png
Stealth       supported (png-stealth-v1)
Capacity      about 31.8 KiB encrypted payload
Change limit  1.429% of eligible color channels
```

Conceal and reveal one encrypted note:

```sh
itx hide photo.png --mode stealth --message-file note.txt
itx reveal photo.invitext.png --mode stealth
itx verify photo.invitext.png --mode stealth
```

A password is mandatory in stealth mode. The label, timestamp, compression flag, lengths, and note text are all inside the encrypted envelope. The outer salt and nonce are random and are themselves distributed through password-keyed image locations.

There is no password-free `list` operation for a stealth note. Exposing one would require a stable discovery signal, which is exactly what this mode avoids. Stealth mode stores one note per image; do not layer notes with different passwords into the same PNG.

Do not mix append and stealth records in one carrier. Stealth mode rejects PNG files with trailing data rather than silently discarding it during recompression.

Keep the original carrier. A pixel-domain note cannot be stripped back to the byte-exact original because the original least-significant bits are not retained.

## Compatible append mode

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

Reveal, verify, or remove append records:

```sh
itx reveal image.invitext.png
itx reveal image.invitext.png --index 1
itx reveal image.invitext.png --all --output notes.txt
itx verify image.invitext.png --deep --index 1
itx strip image.invitext.png
itx strip image.invitext.png --latest
itx strip image.invitext.png --in-place
```

`strip` recovers the exact pre-Invitext bytes unless another application has rewritten the carrier. This guarantee applies only to append mode.

Inspect any carrier or generate shell completions:

```sh
itx inspect archive.rar
itx completions zsh > _itx
itx completions powershell > _itx.ps1
```

Run `itx <command> --help` for every option and alias.

## Password handling

An explicit `--password` is convenient but can be visible in process listings and shell history. Interactive prompting is the safest convenient default. Automation should use a protected password file or an environment variable:

```sh
itx hide plans.pdf -m "..." --encrypt --password-file ./secret.pass
itx reveal plans.invitext.pdf --password-env ITX_PASSWORD
```

Append mode provides three Argon2id presets:

| Preset | Memory | Passes | Intended use |
| --- | ---: | ---: | --- |
| `interactive` | 32 MiB | 2 | Tests and resource-constrained systems |
| `standard` | 64 MiB | 3 | Default for normal use |
| `hardened` | 128 MiB | 4 | Stronger offline-guessing resistance |

PNG stealth format v1 uses the `standard` profile as a fixed format parameter. That avoids placing a recognizable KDF descriptor outside the encrypted header or creating a cheap guessed-password check. The password itself is never stored.

## Carrier compatibility

| Carrier family | Stealth mode | Append mode |
| --- | --- | --- |
| 8-bit PNG | Supported | Usually accepted; public footer remains visible |
| Indexed or animated PNG | Rejected | Usually accepted |
| JPEG, GIF, WebP | Not yet supported | Most viewers tolerate trailing bytes |
| ZIP, RAR, 7z, tar, gzip | Not realistically covert | Mainstream extractors commonly tolerate trailing bytes; strict validators may warn |
| PDF | Not supported | Readers normally tolerate the trailer; rewriting may remove it |
| MP3, WAV, FLAC, MP4, MOV, MKV | Not supported | Usually accepted; test the actual player or editor |
| DOCX, XLSX, PPTX, APK, JAR | Not supported | Mixed; signed packages can fail verification |
| EXE, DLL, app bundles | Not supported | Avoid; signing and integrity checks are likely to fail |

## Security model

Encrypted notes use Argon2id v1.3, random salts, XChaCha20-Poly1305 with fresh nonces, authenticated metadata, and bounded KDF and decompression parameters.

PNG stealth mode additionally uses:

- a placement permutation derived from the password and a cover fingerprint that ignores eligible low bits;
- local luminance and channel activity to prefer textured regions;
- the most active 40% of eligible channels as a candidate pool, with at most 25% of that pool used;
- Hamming `(7,3)` matrix embedding, producing a hard maximum near 1.43% modified eligible channels;
- no cleartext magic, timestamp, label, payload length, or algorithm flag in the PNG data.

The append trailer reveals that Invitext data exists, its approximate size, creation time, and whether it is encrypted. Stealth mode removes that trailer and reduces low-bit changes, but it cannot hide differences from someone who has the original image. Advanced steganalysis may still assign a non-zero likelihood to a modified image. “Undetectable” is not a claim this project makes.

Lossless PNG bytes are recompressed when a note is concealed. Visual pixels and alpha are preserved apart from selected color-channel least-significant bits, but compressed size and chunk layout can change. Any later resize, color conversion, optimizer that rewrites pixels, lossy upload, or screenshot will normally destroy the note.

Without a password, an unencrypted append note is only encoded and compressed. “Only Invitext can decode it” means tool compatibility, not a security boundary; confidentiality comes from encryption and a strong password.

No independent cryptographic or steganalysis audit has been completed. Do not make Invitext the only copy of critical secrets. Read [STEALTH.md](STEALTH.md) for the construction and limits, and [SECURITY.md](SECURITY.md) for operational guidance.

## Format and stability

Both storage formats are versioned independently. Invitext v0.2 continues to read and write append container version 1 and adds PNG stealth envelope version 1. The layouts and validation rules are documented in [FORMAT.md](FORMAT.md) and [STEALTH.md](STEALTH.md).

Append notes form a backward-walked chain, so multiple notes and lossless removal are unambiguous. PNG stealth v1 stores one envelope and intentionally provides neither public discovery nor lossless removal.

## Development

The project requires Rust 1.88 or newer.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release --locked
```

The tests exercise both executable names, encrypted and unencrypted append round trips, PNG stealth round trips, wrong passwords, absence of public format magic, bounded per-channel changes, alpha preservation, JSON output, and byte-exact restoration of append carriers.

## License

Invitext is released under the [MIT License](LICENSE).
