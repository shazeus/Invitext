use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::container::{EmbedOptions, build_record};
use crate::error::{InvitextError, Result};

pub const MAX_INPUT_FILE: u64 = 16 * 1024 * 1024 * 1024;

pub fn file_len(path: &Path) -> Result<u64> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(InvitextError::InvalidFormat("input is not a regular file"));
    }
    if metadata.len() > MAX_INPUT_FILE {
        return Err(InvitextError::SizeLimit {
            kind: "input file",
            limit: MAX_INPUT_FILE,
        });
    }
    Ok(metadata.len())
}

pub fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let expected = file_len(path)?;
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let copied = std::io::copy(&mut file, &mut hasher)?;
    if copied != expected {
        return Err(InvitextError::InvalidFormat(
            "input changed while it was being read",
        ));
    }
    Ok(*hasher.finalize().as_bytes())
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    read_file_limited(path, MAX_INPUT_FILE, "input file")
}

pub fn read_file_limited(path: &Path, limit: u64, kind: &'static str) -> Result<Vec<u8>> {
    let length = file_len(path)?;
    if length > limit {
        return Err(InvitextError::SizeLimit { kind, limit });
    }
    let capacity = usize::try_from(length)
        .map_err(|_| InvitextError::InvalidFormat("input file is too large for this platform"))?;
    let mut file = File::open(path)?;
    let mut data = Vec::with_capacity(capacity);
    file.read_to_end(&mut data)?;
    Ok(data)
}

pub fn write_atomic(path: &Path, data: &[u8], overwrite: bool) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    if path.exists() && !overwrite {
        return Err(InvitextError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; use --force to replace it",
                path.display()
            ),
        )));
    }

    let existing_permissions = fs::metadata(path).ok().map(|meta| meta.permissions());
    let mut temp = NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.as_file_mut().sync_all()?;
    if let Some(permissions) = existing_permissions {
        temp.as_file().set_permissions(permissions)?;
    }

    if path.exists() {
        fs::remove_file(path)?;
    }
    temp.persist(path)
        .map_err(|error| InvitextError::Io(error.error))?;
    sync_parent(parent);
    Ok(())
}

pub fn copy_prefix_atomic(input: &Path, output: &Path, length: u64, overwrite: bool) -> Result<()> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    if output.exists() && !overwrite {
        return Err(InvitextError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; use --force to replace it",
                output.display()
            ),
        )));
    }

    let mut temp = NamedTempFile::new_in(parent)?;
    {
        let mut source = File::open(input)?;
        let mut limited = (&mut source).take(length);
        let copied = std::io::copy(&mut limited, &mut temp)?;
        if copied != length {
            return Err(InvitextError::DamagedFooter);
        }
    }
    temp.as_file_mut().sync_all()?;
    if let Ok(metadata) = fs::metadata(input) {
        temp.as_file().set_permissions(metadata.permissions())?;
    }
    if output.exists() {
        fs::remove_file(output)?;
    }
    temp.persist(output)
        .map_err(|error| InvitextError::Io(error.error))?;
    sync_parent(parent);
    Ok(())
}

pub fn append_atomic(input: &Path, output: &Path, suffix: &[u8], overwrite: bool) -> Result<()> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    if output.exists() && !overwrite && input != output {
        return Err(InvitextError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; use --force to replace it",
                output.display()
            ),
        )));
    }

    let mut temp = NamedTempFile::new_in(parent)?;
    {
        let mut source = File::open(input)?;
        std::io::copy(&mut source, &mut temp)?;
    }
    temp.write_all(suffix)?;
    temp.as_file_mut().sync_all()?;
    if let Ok(metadata) = fs::metadata(input) {
        temp.as_file().set_permissions(metadata.permissions())?;
    }
    if output.exists() {
        fs::remove_file(output)?;
    }
    temp.persist(output)
        .map_err(|error| InvitextError::Io(error.error))?;
    sync_parent(parent);
    Ok(())
}

/// Streams a carrier into a temporary file, hashes the exact bytes copied, and
/// appends a freshly built record before publishing the result.
pub fn embed_file_atomic(
    input: &Path,
    output: &Path,
    text: &str,
    options: &EmbedOptions,
    overwrite: bool,
) -> Result<u64> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    if output.exists() && !overwrite && input != output {
        return Err(InvitextError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; use --force to replace it",
                output.display()
            ),
        )));
    }

    let expected_len = file_len(input)?;
    let mut temp = NamedTempFile::new_in(parent)?;
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0u64;
    {
        let mut source = File::open(input)?;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            temp.write_all(&buffer[..read])?;
            hasher.update(&buffer[..read]);
            copied = copied
                .checked_add(read as u64)
                .ok_or(InvitextError::InvalidFormat("input is too large"))?;
        }
    }
    if copied != expected_len {
        return Err(InvitextError::InvalidFormat(
            "input changed while it was being copied",
        ));
    }

    let record = build_record(*hasher.finalize().as_bytes(), copied, text, options)?;
    temp.write_all(&record)?;
    temp.as_file_mut().sync_all()?;
    if let Ok(metadata) = fs::metadata(input) {
        temp.as_file().set_permissions(metadata.permissions())?;
    }
    if output.exists() {
        fs::remove_file(output)?;
    }
    temp.persist(output)
        .map_err(|error| InvitextError::Io(error.error))?;
    sync_parent(parent);
    Ok(copied + record.len() as u64)
}

fn sync_parent(parent: &Path) {
    if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
        let _ = directory.sync_all();
    }
}

pub fn default_hidden_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|part| part.to_str())
        .unwrap_or("file");
    let name = match input.extension().and_then(|part| part.to_str()) {
        Some(extension) => format!("{stem}.invitext.{extension}"),
        None => format!("{stem}.invitext"),
    };
    parent.join(name)
}

pub fn default_clean_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|part| part.to_str())
        .unwrap_or("file");
    let name = match input.extension().and_then(|part| part.to_str()) {
        Some(extension) => format!("{stem}.clean.{extension}"),
        None => format!("{stem}.clean"),
    };
    parent.join(name)
}
