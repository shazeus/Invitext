# PNG stealth format v1

This document describes the low-density PNG embedding format introduced in Invitext 0.2. It is an engineering specification, not a promise of forensic invisibility.

## Scope

The v1 carrier is a non-animated PNG with 8-bit grayscale, grayscale-alpha, RGB, or RGBA samples. Palette-indexed images are rejected because changing a palette index can produce a large visual change. Alpha samples are never modified, and pixels with alpha below 32 are excluded from placement.

Invitext decodes the PNG, changes selected color-channel least-significant bits, and writes a new lossless PNG. It preserves supported metadata represented by the PNG library, but byte layout, compression ratio, filtering, interlacing, and unknown ancillary chunks are not guaranteed to remain identical.

## Stable cover fingerprint

Placement has to be reproduced after low bits have changed. The cover fingerprint is therefore a BLAKE3 derive-key hash over:

1. image dimensions and color type;
2. every eligible color sample with its least-significant bit cleared;
3. every ineligible sample, including alpha, unchanged.

The fingerprint is authenticated as part of the encrypted envelope. Changing a higher bit, alpha value, dimension, or color layout prevents successful authentication.

## Candidate ranking and density policy

For every eligible color channel, Invitext calculates local activity from the four orthogonal neighboring pixels. The score combines stable, low-bit-cleared luminance contrast and same-channel contrast. Candidates are sorted from highest to lowest activity with their byte index as a deterministic tie-breaker.

Only the most active 40% of eligible channels enter the candidate pool. A ChaCha20 permutation seeded from the password and cover fingerprint scatters placement across that pool. At most 25% of the pool can be used by an envelope.

This means at most 10% of all eligible channels participate in matrix groups. The matrix encoder changes at most one channel in every seven participating channels, so the policy ceiling is approximately 1.43% of eligible channels. Most short notes change substantially fewer.

## Matrix encoding

Invitext uses Hamming `(7,3)` matrix embedding. For each group of seven selected low bits, their XOR syndrome represents three payload bits. If the syndrome differs from the desired value, flipping one indexed bit makes it match. A group therefore requires either zero or one color-channel change, rather than the roughly 3.5 changes expected from direct low-bit replacement across seven samples.

Matrix coding here reduces modifications; it is not an error-correcting layer. PNG is lossless, and XChaCha20-Poly1305 rejects any payload damage. Pixel rewriting by another application is expected to destroy the envelope.

## Encrypted envelope

The matrix-coded byte stream is:

```text
[16-byte random salt][24-byte random nonce][48-byte encrypted header][encrypted body]
```

There is no cleartext magic, length, timestamp, label, or flag. The outer salt and nonce are random. Argon2id with the fixed `standard` profile derives a 256-bit key. A fixed KDF avoids placing a recognizable parameter descriptor outside the encrypted header or creating a fast guessed-password check.

The 32-byte header plaintext contains:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | Internal magic `ITXSTG01` |
| 8 | 2 | Envelope version (`1`) |
| 10 | 2 | Flags |
| 12 | 4 | Encrypted body length |
| 16 | 4 | Decoded note-body length |
| 20 | 8 | Signed Unix creation timestamp |
| 28 | 4 | Random padding |

The internal magic is visible only after successful authenticated decryption. The header uses the outer nonce; the body uses that nonce incremented as a 192-bit integer. Both authenticate a domain-separated cover fingerprint. The note body uses the same label-and-text representation as append format v1 and is zstd-compressed only when compression makes it smaller.

## Discovery and removal

Stealth format intentionally has no password-free discovery operation. `itx list` only recognizes append records. Use `itx reveal --mode stealth` or `itx verify --mode stealth` with the password.

One stealth envelope is supported per image. Concealing again with the same password overwrites the deterministic placement prefix; using different passwords can create overlapping, unrecoverable data. Start from the original carrier for every new note.

There is no lossless `strip` operation because the original low bits are not stored. Keep the original carrier if exact restoration matters.

## Security limits

- Anyone holding the original and modified images can locate changed samples by comparison.
- Statistical steganalysis can produce evidence or a probability estimate even without the original.
- Re-encoding fingerprints or metadata changes may show that a file was processed, regardless of the pixel payload.
- A weak password remains vulnerable to guessing. Placement secrecy does not replace Argon2id or authenticated encryption.
- Resizing, quantization, palette conversion, screenshotting, social-media processing, and many optimizers destroy the envelope.
- The construction has not received independent cryptographic or steganalysis review.
