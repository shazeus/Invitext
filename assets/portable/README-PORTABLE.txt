INVITEXT PORTABLE
=================

No installation is required. Keep this folder on a USB drive or copy it to the
desktop. The program stores no settings, cache, telemetry, or logs.

Windows:
  Double-click "Invitext Portable.cmd", then type: itx --help

macOS:
  Double-click "Invitext Portable.command", then type: itx --help

Linux / existing terminal:
  Run: ./itx --help

Low-density PNG mode:
  itx inspect photo.png
  itx hide photo.png --mode stealth -m "private note"
  itx reveal photo.invitext.png --mode stealth

Encrypted file attachments:
  itx hide report.pdf --file backup.zip
  itx extract report.invitext.pdf -o restored.zip
  itx hide photo.png --mode stealth --file document.pdf
  itx extract photo.invitext.png --mode stealth -o restored.pdf

File attachments require a password and are limited to 128 MiB before
compression. PNG mode also requires enough image capacity. Use inspect first.
Extraction never opens files or unpacks archives, and preserves existing files
unless --force is explicitly given.

Use the interactive password prompt. A password passed with --password can be
recorded in shell history or process listings.

Read PORTABLE.md and README.md for complete examples, integrity checks, format
compatibility, and macOS/Windows download warnings.
