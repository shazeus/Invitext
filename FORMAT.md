# Invitext append container format v1

This document covers `--mode append`. The pixel-domain format used by `--mode stealth` is specified separately in [STEALTH.md](STEALTH.md).

All integers are unsigned little-endian unless explicitly marked otherwise. Invitext 0.3 adds a file-body flag to the existing v1 container. Earlier readers reject this flag; existing text records remain compatible.

An Invitext file is an ordinary carrier followed by one or more records:

```text
[original carrier][payload 1][footer 1][payload 2][footer 2]...
```

Each footer records the exact length and BLAKE3 digest of everything before its payload. A reader starts at end-of-file, parses the fixed footer, and walks backward through `carrier_len` until no valid `INVITEXT` footer remains.

## Footer (96 bytes)

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII magic `INVITEXT` |
| 8 | 2 | Format version (`1`) |
| 10 | 2 | Flags |
| 12 | 8 | Payload length |
| 20 | 8 | Carrier length |
| 28 | 32 | BLAKE3 digest of the complete carrier prefix |
| 60 | 32 | BLAKE3 digest of the payload |
| 92 | 4 | CRC32 of footer bytes 0 through 91 |

The payload must begin exactly at `carrier_len`, and `carrier_len + payload_len` must equal the footer offset. Unknown flag bits are rejected.

## Payload header (76 bytes)

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `ITXP` |
| 4 | 2 | Format version (`1`) |
| 6 | 2 | Flags |
| 8 | 8 | Signed Unix creation timestamp |
| 16 | 4 | Argon2 memory cost in KiB, or zero when unencrypted |
| 20 | 4 | Argon2 iteration count, or zero when unencrypted |
| 24 | 4 | Argon2 parallelism, or zero when unencrypted |
| 28 | 16 | Random salt, or zero when unencrypted |
| 44 | 24 | XChaCha20 nonce, or zero when unencrypted |
| 68 | 8 | Original text or attachment byte length, excluding metadata |

Flag bit 0 means encrypted. Flag bit 1 means zstd-compressed. Flag bit 2 means a file body. File records must be encrypted. The footer and payload flags must match.

For encrypted records, the entire 76-byte payload header is XChaCha20-Poly1305 additional authenticated data. The bytes after the header are the ciphertext and 16-byte Poly1305 tag. Argon2id version 1.3 derives a 256-bit key directly into the cipher key buffer.

## Note body

Compression is applied before encryption. Once decrypted and decompressed, the note body is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `NOTE` |
| 4 | 4 | UTF-8 label length |
| 8 | 8 | UTF-8 text length |
| 16 | variable | Label bytes, followed by text bytes |

The decoded body must end immediately after the declared text. Implementations should enforce resource limits before allocating or decompressing untrusted lengths. Invitext currently accepts at most 16 KiB of label text, 128 MiB of note text, and 256 MiB of stored payload.

## File body

When bit 2 is set, the decrypted and decompressed body is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `FILE` |
| 4 | 4 | UTF-8 label length |
| 8 | 4 | UTF-8 filename length |
| 12 | 8 | Raw file byte length |
| 20 | variable | Label bytes, filename bytes, then raw file bytes |

The body must end immediately after the declared file bytes. The file length must also equal the original byte length in the authenticated payload header. Labels are limited to 16 KiB, filenames to 255 UTF-8 bytes, and file content to 128 MiB before compression. Binary content need not be valid UTF-8, and zero-byte files are accepted.

The filename is a basename, not a path. Empty names, `.` and `..`, slashes, backslashes, colons, and control characters are rejected. The CLI always requires an explicit extraction path and never uses the stored name to choose where to write.

Compression precedes encryption and is used only when it reduces the body size. Older append writers may have compressed larger bodies; readers still accept them.

## Validation order

The reference reader validates, in order:

1. footer magic, version, and CRC32;
2. length arithmetic and configured size limits;
3. BLAKE3 payload digest;
4. payload magic, version, and flags;
5. BLAKE3 carrier digest when integrity checking is requested;
6. KDF parameter bounds;
7. AEAD authentication and decryption;
8. bounded decompression;
9. body type, lengths, metadata validity, and original byte length.

CRC32 is only an early corruption check. It is not a cryptographic authenticator.
