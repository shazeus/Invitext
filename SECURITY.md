# Security policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that could expose hidden text, bypass authentication, cause unsafe file replacement, or exhaust resources with a crafted carrier.

Use GitHub's private vulnerability reporting for this repository. Include the Invitext version, operating system, a minimal reproducer, and whether the carrier may be shared privately. Reports will be acknowledged as soon as practical; no fixed response SLA is promised for this volunteer project.

## Operational guidance

- Prefer the interactive password prompt. `--password` can expose a secret through shell history or process inspection.
- Use a long, unique passphrase. Encryption cannot compensate for a guessable password.
- Keep another copy of important carrier files until you have tested the result in its normal application.
- Do not append data to signed executables, signed mobile packages, or documents whose byte identity is externally verified.
- Treat unencrypted notes as public information.
- Remember that the trailer reveals the presence and approximate size of a note.

Invitext has not received an independent security audit. The cryptographic construction uses established primitives, but implementation defects are still possible.

