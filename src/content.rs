//! Binary attachments shared by the append and PNG storage formats.

use crate::{EmbeddedNote, InvitextError, Result};
use zeroize::Zeroizing;

pub const MAX_ATTACHMENT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_LABEL_BYTES: usize = 16 * 1024;
const MAX_FILENAME_BYTES: usize = 255;
const FILE_MAGIC: &[u8; 4] = b"FILE";
const FILE_HEADER_BYTES: usize = 20;

/// An attachment's filename is metadata, never an extraction path.
#[derive(Clone, Debug)]
pub struct EmbeddedFile {
    pub filename: String,
    pub data: Zeroizing<Vec<u8>>,
    pub label: String,
    pub created_at: i64,
    pub encrypted: bool,
    pub compressed: bool,
}

#[derive(Clone, Debug)]
pub enum EmbeddedContent {
    Text(EmbeddedNote),
    File(EmbeddedFile),
}

impl EmbeddedContent {
    pub fn into_note(self) -> Result<EmbeddedNote> {
        match self {
            Self::Text(note) => Ok(note),
            Self::File(_) => Err(InvitextError::FilePayload),
        }
    }

    pub fn into_file(self) -> Result<EmbeddedFile> {
        match self {
            Self::File(file) => Ok(file),
            Self::Text(_) => Err(InvitextError::TextPayload),
        }
    }
}

pub(crate) fn encode_file_body(filename: &str, data: &[u8], label: &str) -> Result<Vec<u8>> {
    validate_filename(filename)?;
    if label.len() > MAX_LABEL_BYTES {
        return Err(InvitextError::SizeLimit {
            kind: "label",
            limit: MAX_LABEL_BYTES as u64,
        });
    }
    if data.len() as u64 > MAX_ATTACHMENT_BYTES {
        return Err(InvitextError::SizeLimit {
            kind: "attachment",
            limit: MAX_ATTACHMENT_BYTES,
        });
    }
    let mut encoded =
        Vec::with_capacity(FILE_HEADER_BYTES + filename.len() + label.len() + data.len());
    encoded.extend_from_slice(FILE_MAGIC);
    encoded.extend_from_slice(&(label.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&(filename.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&(data.len() as u64).to_le_bytes());
    encoded.extend_from_slice(label.as_bytes());
    encoded.extend_from_slice(filename.as_bytes());
    encoded.extend_from_slice(data);
    Ok(encoded)
}

pub(crate) fn decode_content_body(
    body: &[u8],
    is_file: bool,
    created_at: i64,
    encrypted: bool,
    compressed: bool,
) -> Result<EmbeddedContent> {
    if !is_file {
        let (label, text) = crate::container::decode_note(body)?;
        return Ok(EmbeddedContent::Text(EmbeddedNote {
            text: String::from_utf8(text).map_err(|_| InvitextError::InvalidUtf8)?,
            label: String::from_utf8(label).map_err(|_| InvitextError::InvalidUtf8)?,
            created_at,
            encrypted,
            compressed,
        }));
    }
    if !encrypted || body.len() < FILE_HEADER_BYTES || &body[..4] != FILE_MAGIC {
        return Err(InvitextError::DamagedPayload);
    }
    let label_len = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
    let filename_len = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    let data_len = u64::from_le_bytes(body[12..20].try_into().unwrap());
    if label_len > MAX_LABEL_BYTES
        || filename_len > MAX_FILENAME_BYTES
        || data_len > MAX_ATTACHMENT_BYTES
    {
        return Err(InvitextError::DamagedPayload);
    }
    let filename_start = FILE_HEADER_BYTES
        .checked_add(label_len)
        .ok_or(InvitextError::DamagedPayload)?;
    let data_start = filename_start
        .checked_add(filename_len)
        .ok_or(InvitextError::DamagedPayload)?;
    let data_len = usize::try_from(data_len).map_err(|_| InvitextError::DamagedPayload)?;
    if data_start.checked_add(data_len) != Some(body.len()) {
        return Err(InvitextError::DamagedPayload);
    }
    let label = std::str::from_utf8(&body[FILE_HEADER_BYTES..filename_start])
        .map_err(|_| InvitextError::InvalidUtf8)?;
    let filename = std::str::from_utf8(&body[filename_start..data_start])
        .map_err(|_| InvitextError::InvalidUtf8)?;
    validate_filename(filename)?;
    Ok(EmbeddedContent::File(EmbeddedFile {
        filename: filename.to_owned(),
        label: label.to_owned(),
        data: Zeroizing::new(body[data_start..].to_vec()),
        created_at,
        encrypted,
        compressed,
    }))
}

fn validate_filename(filename: &str) -> Result<()> {
    if filename.is_empty()
        || filename.len() > MAX_FILENAME_BYTES
        || filename == "."
        || filename == ".."
        || filename
            .chars()
            .any(|ch| matches!(ch, '/' | '\\' | ':') || ch.is_control())
    {
        return Err(InvitextError::InvalidFormat(
            "attachment filename must be a plain basename of at most 255 UTF-8 bytes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_paths_and_malformed_lengths() {
        for filename in [
            "",
            "..",
            "../secret.zip",
            "a\\secret.pdf",
            "C:evil",
            "bad\0name",
        ] {
            assert!(encode_file_body(filename, b"data", "").is_err());
        }
        let mut encoded = encode_file_body("report.pdf", b"\0\xffdata", "label").unwrap();
        let decoded = decode_content_body(&encoded, true, 0, true, false)
            .unwrap()
            .into_file()
            .unwrap();
        assert_eq!(decoded.data.as_slice(), b"\0\xffdata");
        encoded[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_content_body(&encoded, true, 0, true, false).is_err());
    }
}
