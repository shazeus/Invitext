# Portable use

Invitext does not need an installer, service, account, registry entry, or configuration directory. A portable bundle can live on a USB drive, external disk, desktop folder, or encrypted volume.

## Pick the right archive

| Computer | Archive |
| --- | --- |
| Windows 10/11, Intel or AMD 64-bit | `invitext-portable-windows-x86_64.zip` |
| Linux, Intel or AMD 64-bit | `invitext-portable-linux-x86_64.tar.gz` |
| Intel Mac | `invitext-portable-macos-x86_64.tar.gz` |
| Apple Silicon Mac (M1 and newer) | `invitext-portable-macos-aarch64.tar.gz` |

Each archive contains both command names, this guide, the main README, the license, both format specifications, the security policy, the changelog, and a small terminal launcher.

## Windows

1. Extract the ZIP. Windows cannot reliably run the program while it is still inside the compressed archive.
2. Double-click `Invitext Portable.cmd`.
3. Use `itx` in the terminal window that opens.

The portable Windows executable statically links the Microsoft C runtime. It does not need a separate Visual C++ redistributable or administrator access.

PowerShell and an existing Command Prompt work too:

```powershell
cd E:\Invitext
.\itx.exe inspect E:\photo.jpg
.\itx.exe hide E:\photo.jpg -m "private note" --encrypt
.\itx.exe hide E:\photo.png --mode stealth -m "private note"
.\itx.exe hide E:\report.pdf --file E:\backup.zip
.\itx.exe extract E:\report.invitext.pdf -o E:\restored.zip
```

Windows SmartScreen may warn because community release binaries are not code-signed. Verify the SHA-256 file beside the download, then use the repository release only if the digest matches.

```powershell
Get-FileHash .\invitext-portable-windows-x86_64.zip -Algorithm SHA256
```

## macOS

Extract the archive, then double-click `Invitext Portable.command`. It opens a Terminal session with the portable folder temporarily added to `PATH`.

GitHub release binaries are not Apple-notarized. If macOS quarantines the extracted folder, verify the SHA-256 download first, then remove quarantine from that exact folder:

```sh
shasum -a 256 invitext-portable-macos-aarch64.tar.gz
xattr -dr com.apple.quarantine /path/to/Invitext
```

Do not run the `xattr` command against Downloads or another broad directory.

From an existing terminal:

```sh
cd /Volumes/MY_USB/Invitext
./itx inspect photo.jpg
./itx hide photo.jpg -m 'private note' --encrypt
./itx hide photo.png --mode stealth -m 'private note'
./itx hide photo.png --mode stealth --file backup.zip
./itx extract photo.invitext.png --mode stealth -o restored.zip
```

## Linux

The Linux executable is built against musl and is intended to run without a distribution-specific glibc dependency.

```sh
tar -xzf invitext-portable-linux-x86_64.tar.gz
cd Invitext
./itx --version
```

If an archive tool did not preserve executable permissions:

```sh
chmod +x itx invitext "Invitext Portable.command"
```

## File attachments

File attachments work from the portable executables too. They require a password and an explicit extraction path. Keep within the carrier's capacity in PNG mode; append mode accepts attachments up to 128 MiB. The portable terminal starts in the bundle folder, so use absolute paths when the carrier lives elsewhere.

## Where data is stored

Nowhere outside the paths you choose. Invitext has no settings database, cache, telemetry, log file, or “recent files” list. The launcher changes `PATH` only inside its own terminal session.

The operating system or shell can still leave traces such as command history, recent-document entries, filesystem metadata, antivirus logs, or USB access records. Use the interactive password prompt instead of putting a password on the command line.

## Safe removal

Wait until Invitext finishes writing, close the portable terminal, and eject the USB drive through the operating system. Invitext calls file and directory sync operations before reporting a successful write, but removing a drive during an operation can still corrupt the output.
