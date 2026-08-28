use std::io::{Cursor, Read, Seek, SeekFrom};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::Rng;
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::FORMAT_VERSION;
use crate::error::{InvitextError, Result};

const FOOTER_MAGIC: &[u8; 8] = b"INVITEXT";
const PAYLOAD_MAGIC: &[u8; 4] = b"ITXP";
const NOTE_MAGIC: &[u8; 4] = b"NOTE";
const FOOTER_SIZE: usize = 96;
const PAYLOAD_HEADER_SIZE: usize = 76;
const FLAG_ENCRYPTED: u16 = 1 << 0;
const FLAG_COMPRESSED: u16 = 1 << 1;
const DEFAULT_MAX_PAYLOAD: u64 = 256 * 1024 * 1024;
const DEFAULT_MAX_TEXT: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct KdfConfig {
    /// Argon2 memory cost in KiB.
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

#[derive(Clone)]
pub struct EncryptionOptions {
    pub password: Zeroizing<String>,
    pub kdf: KdfConfig,
}

#[derive(Clone)]
pub struct EmbedOptions {
    pub label: String,
    pub compression: bool,
    pub encryption: Option<EncryptionOptions>,
    pub created_at: i64,
}

impl Default for EmbedOptions {
    fn default() -> Self {
        Self {
            label: String::new(),
            compression: true,
            encryption: None,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs() as i64)
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NoteInfo {
    /// One-based index, oldest note first.
    pub index: usize,
    pub encrypted: bool,
    pub compressed: bool,
    pub created_at: i64,
    pub stored_bytes: u64,
    pub carrier_bytes: u64,
    pub intact: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanResult {
    pub original_size: u64,
    pub total_size: u64,
    pub notes: Vec<NoteInfo>,
}

#[derive(Clone, Debug)]
pub struct EmbeddedNote {
    pub text: String,
    pub label: String,
    pub created_at: i64,
    pub encrypted: bool,
    pub compressed: bool,
}

#[derive(Clone, Debug)]
struct Footer {
    flags: u16,
    payload_len: u64,
    carrier_len: u64,
    carrier_hash: [u8; 32],
    payload_hash: [u8; 32],
}

#[derive(Clone, Debug)]
struct PayloadHeader {
    flags: u16,
    created_at: i64,
    kdf: KdfConfig,
    salt: [u8; 16],
    nonce: [u8; 24],
    plaintext_len: u64,
}

pub fn embed_bytes(carrier: &[u8], text: &str, options: &EmbedOptions) -> Result<Vec<u8>> {
    let record = build_record(
        *blake3::hash(carrier).as_bytes(),
        carrier.len() as u64,
        text,
        options,
    )?;
    let mut output = Vec::with_capacity(carrier.len() + record.len());
    output.extend_from_slice(carrier);
    output.extend_from_slice(&record);
    Ok(output)
}

/// Builds the bytes appended to a carrier. This is useful for streaming large
/// files: hash and copy the carrier separately, then append the returned record.
pub fn build_record(
    carrier_hash: [u8; 32],
    carrier_len: u64,
    text: &str,
    options: &EmbedOptions,
) -> Result<Vec<u8>> {
    if text.len() as u64 > DEFAULT_MAX_TEXT {
        return Err(InvitextError::SizeLimit {
            kind: "text",
            limit: DEFAULT_MAX_TEXT,
        });
    }

    let mut note = encode_note(options.label.as_bytes(), text.as_bytes())?;
    let mut flags = 0u16;
    let mut body = if options.compression {
        flags |= FLAG_COMPRESSED;
        let compressed = zstd::stream::encode_all(Cursor::new(&note), 9)?;
        note.zeroize();
        compressed
    } else {
        note
    };

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    let mut kdf = KdfConfig {
        memory_kib: 0,
        iterations: 0,
        parallelism: 0,
    };

    if let Some(encryption) = &options.encryption {
        flags |= FLAG_ENCRYPTED;
        kdf = encryption.kdf;
        validate_kdf(kdf)?;
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);

        let mut key = Zeroizing::new([0u8; 32]);
        derive_key(encryption.password.as_bytes(), &salt, kdf, &mut key)?;
        let header = PayloadHeader {
            flags,
            created_at: options.created_at,
            kdf,
            salt,
            nonce,
            plaintext_len: text.len() as u64,
        };
        let aad = encode_payload_header(&header);
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let plaintext_body = Zeroizing::new(std::mem::take(&mut body));
        body = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext_body,
                    aad: &aad,
                },
            )
            .map_err(|_| InvitextError::Crypto)?;
    }

    let header = PayloadHeader {
        flags,
        created_at: options.created_at,
        kdf,
        salt,
        nonce,
        plaintext_len: text.len() as u64,
    };
    let mut payload = encode_payload_header(&header);
    payload.extend_from_slice(&body);
    if payload.len() as u64 > DEFAULT_MAX_PAYLOAD {
        body.zeroize();
        return Err(InvitextError::SizeLimit {
            kind: "payload",
            limit: DEFAULT_MAX_PAYLOAD,
        });
    }

    let footer = Footer {
        flags,
        payload_len: payload.len() as u64,
        carrier_len,
        carrier_hash,
        payload_hash: *blake3::hash(&payload).as_bytes(),
    };

    let mut record = Vec::with_capacity(payload.len() + FOOTER_SIZE);
    record.extend_from_slice(&payload);
    record.extend_from_slice(&encode_footer(&footer));
    body.zeroize();
    Ok(record)
}

pub fn scan(data: &[u8], verify_carriers: bool) -> Result<ScanResult> {
    scan_reader(&mut Cursor::new(data), data.len() as u64, verify_carriers)
}

pub fn scan_reader<R: Read + Seek>(
    reader: &mut R,
    total_size: u64,
    verify_carriers: bool,
) -> Result<ScanResult> {
    let mut cursor = total_size;
    let mut found = Vec::new();

    while cursor >= FOOTER_SIZE as u64 {
        let footer_start = cursor - FOOTER_SIZE as u64;
        reader.seek(SeekFrom::Start(footer_start))?;
        let mut footer_bytes = [0u8; FOOTER_SIZE];
        reader.read_exact(&mut footer_bytes)?;
        if &footer_bytes[..8] != FOOTER_MAGIC {
            break;
        }
        let footer = decode_footer(&footer_bytes)?;
        let payload_len = usize::try_from(footer.payload_len)
            .map_err(|_| InvitextError::InvalidFormat("payload length is too large"))?;
        if payload_len > DEFAULT_MAX_PAYLOAD as usize
            || footer.carrier_len.checked_add(footer.payload_len) != Some(footer_start)
        {
            return Err(InvitextError::DamagedFooter);
        }
        reader.seek(SeekFrom::Start(footer.carrier_len))?;
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload)?;
        let payload_ok = blake3::hash(&payload).as_bytes() == &footer.payload_hash;
        if !payload_ok {
            return Err(InvitextError::DamagedPayload);
        }
        let carrier_ok = !verify_carriers
            || hash_reader_prefix(reader, footer.carrier_len)? == footer.carrier_hash;
        let header = decode_payload_header(&payload)?;
        if header.flags != footer.flags {
            return Err(InvitextError::DamagedPayload);
        }
        found.push(NoteInfo {
            index: 0,
            encrypted: header.flags & FLAG_ENCRYPTED != 0,
            compressed: header.flags & FLAG_COMPRESSED != 0,
            created_at: header.created_at,
            stored_bytes: footer.payload_len + FOOTER_SIZE as u64,
            carrier_bytes: footer.carrier_len,
            intact: carrier_ok,
        });
        cursor = footer.carrier_len;
    }

    if found.is_empty() {
        return Err(InvitextError::NoNote);
    }
    found.reverse();
    for (position, info) in found.iter_mut().enumerate() {
        info.index = position + 1;
    }
    Ok(ScanResult {
        original_size: cursor,
        total_size,
        notes: found,
    })
}

pub fn reveal_note(data: &[u8], index: usize, password: Option<&str>) -> Result<EmbeddedNote> {
    reveal_note_reader(&mut Cursor::new(data), data.len() as u64, index, password)
}

pub fn reveal_note_reader<R: Read + Seek>(
    reader: &mut R,
    total_size: u64,
    index: usize,
    password: Option<&str>,
) -> Result<EmbeddedNote> {
    let scan_result = scan_reader(reader, total_size, true)?;
    if index == 0 || index > scan_result.notes.len() {
        return Err(InvitextError::InvalidIndex {
            requested: index,
            available: scan_result.notes.len(),
        });
    }

    let target = &scan_result.notes[index - 1];
    if !target.intact {
        return Err(InvitextError::CarrierModified);
    }
    let payload_len = usize::try_from(target.stored_bytes - FOOTER_SIZE as u64)
        .map_err(|_| InvitextError::DamagedPayload)?;
    reader.seek(SeekFrom::Start(target.carrier_bytes))?;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload)?;
    let header = decode_payload_header(&payload)?;
    let mut body = payload[PAYLOAD_HEADER_SIZE..].to_vec();

    if header.flags & FLAG_ENCRYPTED != 0 {
        let password = password.ok_or(InvitextError::PasswordRequired)?;
        validate_kdf(header.kdf)?;
        let mut key = Zeroizing::new([0u8; 32]);
        derive_key(password.as_bytes(), &header.salt, header.kdf, &mut key)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        body = cipher
            .decrypt(
                XNonce::from_slice(&header.nonce),
                Payload {
                    msg: &body,
                    aad: &payload[..PAYLOAD_HEADER_SIZE],
                },
            )
            .map_err(|_| InvitextError::DecryptionFailed)?;
    }

    let mut decoded = if header.flags & FLAG_COMPRESSED != 0 {
        let decoded = decode_zstd_limited(&body, DEFAULT_MAX_TEXT + 1024 * 1024)?;
        body.zeroize();
        decoded
    } else {
        body
    };
    let (label, text) = decode_note(&decoded)?;
    decoded.zeroize();
    if text.len() as u64 != header.plaintext_len {
        return Err(InvitextError::DamagedPayload);
    }

    Ok(EmbeddedNote {
        text: String::from_utf8(text).map_err(|_| InvitextError::InvalidUtf8)?,
        label: String::from_utf8(label).map_err(|_| InvitextError::InvalidUtf8)?,
        created_at: header.created_at,
        encrypted: header.flags & FLAG_ENCRYPTED != 0,
        compressed: header.flags & FLAG_COMPRESSED != 0,
    })
}

fn hash_reader_prefix<R: Read + Seek>(reader: &mut R, length: u64) -> Result<[u8; 32]> {
    reader.seek(SeekFrom::Start(0))?;
    let mut limited = reader.take(length);
    let mut hasher = blake3::Hasher::new();
    let copied = std::io::copy(&mut limited, &mut hasher)?;
    if copied != length {
        return Err(InvitextError::DamagedFooter);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn encode_note(label: &[u8], text: &[u8]) -> Result<Vec<u8>> {
    const MAX_LABEL: usize = 16 * 1024;
    if label.len() > MAX_LABEL {
        return Err(InvitextError::SizeLimit {
            kind: "label",
            limit: MAX_LABEL as u64,
        });
    }
    let label_len = u32::try_from(label.len())
        .map_err(|_| InvitextError::InvalidFormat("label is too long"))?;
    let mut encoded = Vec::with_capacity(16 + label.len() + text.len());
    encoded.extend_from_slice(NOTE_MAGIC);
    encoded.extend_from_slice(&label_len.to_le_bytes());
    encoded.extend_from_slice(&(text.len() as u64).to_le_bytes());
    encoded.extend_from_slice(label);
    encoded.extend_from_slice(text);
    Ok(encoded)
}

fn decode_note(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    const MAX_LABEL: usize = 16 * 1024;
    if data.len() < 16 || &data[..4] != NOTE_MAGIC {
        return Err(InvitextError::DamagedPayload);
    }
    let label_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    if label_len > MAX_LABEL {
        return Err(InvitextError::SizeLimit {
            kind: "label",
            limit: MAX_LABEL as u64,
        });
    }
    let text_len = u64::from_le_bytes(data[8..16].try_into().unwrap());
    if text_len > DEFAULT_MAX_TEXT {
        return Err(InvitextError::SizeLimit {
            kind: "text",
            limit: DEFAULT_MAX_TEXT,
        });
    }
    let text_len = text_len as usize;
    let label_end = 16usize
        .checked_add(label_len)
        .ok_or(InvitextError::DamagedPayload)?;
    let text_end = label_end
        .checked_add(text_len)
        .ok_or(InvitextError::DamagedPayload)?;
    if text_end != data.len() {
        return Err(InvitextError::DamagedPayload);
    }
    Ok((
        data[16..label_end].to_vec(),
        data[label_end..text_end].to_vec(),
    ))
}

fn encode_payload_header(header: &PayloadHeader) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(PAYLOAD_HEADER_SIZE);
    encoded.extend_from_slice(PAYLOAD_MAGIC);
    encoded.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&header.flags.to_le_bytes());
    encoded.extend_from_slice(&header.created_at.to_le_bytes());
    encoded.extend_from_slice(&header.kdf.memory_kib.to_le_bytes());
    encoded.extend_from_slice(&header.kdf.iterations.to_le_bytes());
    encoded.extend_from_slice(&header.kdf.parallelism.to_le_bytes());
    encoded.extend_from_slice(&header.salt);
    encoded.extend_from_slice(&header.nonce);
    encoded.extend_from_slice(&header.plaintext_len.to_le_bytes());
    debug_assert_eq!(encoded.len(), PAYLOAD_HEADER_SIZE);
    encoded
}

fn decode_payload_header(payload: &[u8]) -> Result<PayloadHeader> {
    if payload.len() < PAYLOAD_HEADER_SIZE || &payload[..4] != PAYLOAD_MAGIC {
        return Err(InvitextError::DamagedPayload);
    }
    let version = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    if version != FORMAT_VERSION {
        return Err(InvitextError::UnsupportedVersion(version));
    }
    let flags = u16::from_le_bytes(payload[6..8].try_into().unwrap());
    if flags & !(FLAG_ENCRYPTED | FLAG_COMPRESSED) != 0 {
        return Err(InvitextError::InvalidFormat("unknown payload flags"));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&payload[28..44]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&payload[44..68]);
    let header = PayloadHeader {
        flags,
        created_at: i64::from_le_bytes(payload[8..16].try_into().unwrap()),
        kdf: KdfConfig {
            memory_kib: u32::from_le_bytes(payload[16..20].try_into().unwrap()),
            iterations: u32::from_le_bytes(payload[20..24].try_into().unwrap()),
            parallelism: u32::from_le_bytes(payload[24..28].try_into().unwrap()),
        },
        salt,
        nonce,
        plaintext_len: u64::from_le_bytes(payload[68..76].try_into().unwrap()),
    };
    if header.plaintext_len > DEFAULT_MAX_TEXT {
        return Err(InvitextError::SizeLimit {
            kind: "text",
            limit: DEFAULT_MAX_TEXT,
        });
    }
    if flags & FLAG_ENCRYPTED == 0
        && (header.kdf.memory_kib != 0
            || header.kdf.iterations != 0
            || header.kdf.parallelism != 0
            || header.salt != [0u8; 16]
            || header.nonce != [0u8; 24])
    {
        return Err(InvitextError::InvalidFormat(
            "unencrypted payload has encryption parameters",
        ));
    }
    Ok(header)
}

fn encode_footer(footer: &Footer) -> [u8; FOOTER_SIZE] {
    let mut encoded = [0u8; FOOTER_SIZE];
    encoded[..8].copy_from_slice(FOOTER_MAGIC);
    encoded[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    encoded[10..12].copy_from_slice(&footer.flags.to_le_bytes());
    encoded[12..20].copy_from_slice(&footer.payload_len.to_le_bytes());
    encoded[20..28].copy_from_slice(&footer.carrier_len.to_le_bytes());
    encoded[28..60].copy_from_slice(&footer.carrier_hash);
    encoded[60..92].copy_from_slice(&footer.payload_hash);
    let checksum = crc32fast::hash(&encoded[..92]);
    encoded[92..96].copy_from_slice(&checksum.to_le_bytes());
    encoded
}

fn decode_footer(data: &[u8]) -> Result<Footer> {
    if data.len() != FOOTER_SIZE || &data[..8] != FOOTER_MAGIC {
        return Err(InvitextError::NoNote);
    }
    let expected_checksum = u32::from_le_bytes(data[92..96].try_into().unwrap());
    if crc32fast::hash(&data[..92]) != expected_checksum {
        return Err(InvitextError::DamagedFooter);
    }
    let version = u16::from_le_bytes(data[8..10].try_into().unwrap());
    if version != FORMAT_VERSION {
        return Err(InvitextError::UnsupportedVersion(version));
    }
    let mut carrier_hash = [0u8; 32];
    carrier_hash.copy_from_slice(&data[28..60]);
    let mut payload_hash = [0u8; 32];
    payload_hash.copy_from_slice(&data[60..92]);
    Ok(Footer {
        flags: u16::from_le_bytes(data[10..12].try_into().unwrap()),
        payload_len: u64::from_le_bytes(data[12..20].try_into().unwrap()),
        carrier_len: u64::from_le_bytes(data[20..28].try_into().unwrap()),
        carrier_hash,
        payload_hash,
    })
}

fn derive_key(
    password: &[u8],
    salt: &[u8; 16],
    kdf: KdfConfig,
    output: &mut [u8; 32],
) -> Result<()> {
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(output.len()),
    )
    .map_err(|_| InvitextError::Crypto)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, output)
        .map_err(|_| InvitextError::Crypto)
}

fn validate_kdf(kdf: KdfConfig) -> Result<()> {
    if !(8 * 1024..=256 * 1024).contains(&kdf.memory_kib)
        || !(1..=10).contains(&kdf.iterations)
        || !(1..=16).contains(&kdf.parallelism)
    {
        return Err(InvitextError::InvalidFormat("unsafe Argon2 parameters"));
    }
    Ok(())
}

fn decode_zstd_limited(data: &[u8], limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;

    let decoder = zstd::stream::read::Decoder::new(Cursor::new(data))?;
    let mut limited = decoder.take(limit + 1);
    let mut output = Vec::new();
    limited.read_to_end(&mut output)?;
    if output.len() as u64 > limit {
        return Err(InvitextError::SizeLimit {
            kind: "decompressed data",
            limit,
        });
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted(password: &str) -> EmbedOptions {
        EmbedOptions {
            label: "private note".into(),
            encryption: Some(EncryptionOptions {
                password: Zeroizing::new(password.into()),
                kdf: KdfConfig {
                    memory_kib: 8 * 1024,
                    iterations: 1,
                    parallelism: 1,
                },
            }),
            ..EmbedOptions::default()
        }
    }

    #[test]
    fn unencrypted_round_trip() {
        let carrier = b"fake png bytes";
        let encoded = embed_bytes(carrier, "hello, dünya", &EmbedOptions::default()).unwrap();
        let result = scan(&encoded, true).unwrap();
        assert_eq!(result.original_size, carrier.len() as u64);
        assert_eq!(result.notes.len(), 1);
        let note = reveal_note(&encoded, 1, None).unwrap();
        assert_eq!(note.text, "hello, dünya");
    }

    #[test]
    fn encrypted_round_trip_and_wrong_password() {
        let encoded = embed_bytes(b"carrier", "classified", &encrypted("correct horse")).unwrap();
        assert!(matches!(
            reveal_note(&encoded, 1, None),
            Err(InvitextError::PasswordRequired)
        ));
        assert!(matches!(
            reveal_note(&encoded, 1, Some("wrong")),
            Err(InvitextError::DecryptionFailed)
        ));
        assert_eq!(
            reveal_note(&encoded, 1, Some("correct horse"))
                .unwrap()
                .text,
            "classified"
        );
    }

    #[test]
    fn supports_multiple_notes() {
        let first = embed_bytes(b"archive", "first", &EmbedOptions::default()).unwrap();
        let second = embed_bytes(&first, "second", &encrypted("secret")).unwrap();
        let result = scan(&second, true).unwrap();
        assert_eq!(result.notes.len(), 2);
        assert_eq!(reveal_note(&second, 1, None).unwrap().text, "first");
        assert_eq!(
            reveal_note(&second, 2, Some("secret")).unwrap().text,
            "second"
        );
    }

    #[test]
    fn detects_modified_carrier() {
        let mut encoded = embed_bytes(b"carrier", "note", &EmbedOptions::default()).unwrap();
        encoded[0] ^= 0xff;
        let result = scan(&encoded, true).unwrap();
        assert!(!result.notes[0].intact);
        assert!(matches!(
            reveal_note(&encoded, 1, None),
            Err(InvitextError::CarrierModified)
        ));
    }

    #[test]
    fn detects_modified_payload() {
        let mut encoded = embed_bytes(b"carrier", "note", &EmbedOptions::default()).unwrap();
        encoded[10] ^= 0xff;
        assert!(matches!(
            scan(&encoded, true),
            Err(InvitextError::DamagedPayload)
        ));
    }
}
