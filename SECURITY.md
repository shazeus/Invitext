# Security policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that could expose hidden content, bypass authentication, cause unsafe file replacement, or exhaust resources with a crafted carrier.

Use GitHub's private vulnerability reporting for this repository. Include the Invitext version, operating system, a minimal reproducer, and whether the carrier may be shared privately. Reports will be acknowledged as soon as practical; no fixed response SLA is promised for this volunteer project.

## Operational guidance

- Prefer the interactive password prompt. `--password` can expose a secret through shell history or process inspection.
- Use a long, unique passphrase. Encryption cannot compensate for a guessable password.
- Keep another copy of important carrier files until you have tested the result in its normal application.
- Do not append data to signed executables, signed mobile packages, or documents whose byte identity is externally verified.
- Treat unencrypted notes as public information.
- Remember that the trailer reveals the presence and approximate size of a note.
- Do not describe PNG stealth mode as undetectable. Keep the original private, use a fresh carrier for each note, and stay well below the reported capacity when practical.
- Do not resize, optimize, color-convert, screenshot, or upload a stealth carrier through a lossy media pipeline before revealing its note.
- Stealth notes cannot be removed with byte-exact restoration. Retain the untouched original carrier.
- Attachments always require encryption. Their original filename and label are inside the encrypted body; append mode still reveals the record type, timestamp, and approximate stored size.
- Extraction authenticates and validates the entire payload before writing. Stored filenames never select output paths. Existing outputs require `--force`, and the carrier cannot be replaced by extraction.
- A successfully decrypted file is not necessarily safe to open. Invitext does not scan for malware, execute attachments, or unpack archives; handle restored files according to their source.
- Attachment content is limited to 128 MiB before compression and is processed in memory. Decompression output, the zstd history window, and metadata lengths are bounded separately. Memory wiping is best effort and does not prevent operating-system swap or crash dumps.

Invitext has not received an independent security or steganalysis audit. The cryptographic construction uses established primitives, but implementation defects and statistical detection remain possible.
