//! Password-keyed, content-adaptive embedding for lossless PNG carriers.
//!
//! Unlike the generic container, this module never appends a recognizable
//! record. It hides one encrypted envelope among high-activity image channels.
//! The public interface deliberately keeps image parsing, placement, matrix
//! coding, encryption, and capacity policy behind one seam.

use std::cmp::Ordering;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::container::{
    EmbeddedNote, KdfConfig, decode_note, decode_zstd_limited, derive_key, encode_note,
};
use crate::error::{InvitextError, Result};

const ENVELOPE_MAGIC: &[u8; 8] = b"ITXSTG01";
const ENVELOPE_VERSION: u16 = 1;
const HEADER_PLAINTEXT_BYTES: usize = 32;
const HEADER_CIPHERTEXT_BYTES: usize = HEADER_PLAINTEXT_BYTES + 16;
const OUTER_PREFIX_BYTES: usize = 16 + 24;
const FIXED_ENVELOPE_BYTES: usize = OUTER_PREFIX_BYTES + HEADER_CIPHERTEXT_BYTES;
const FLAG_COMPRESSED: u16 = 1;
pub const MAX_STEALTH_PNG_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DECODED_PNG: usize = MAX_STEALTH_PNG_BYTES as usize;
const MAX_DECODED_NOTE: u64 = 128 * 1024 * 1024 + 16 * 1024 + 16;

// Only the most locally active 40% of eligible color channels are considered.
const CANDIDATE_NUMERATOR: usize = 2;
const CANDIDATE_DENOMINATOR: usize = 5;

// At most one quarter of that pool is used. Matrix coding changes no more than
// one channel in each seven-channel group, so the absolute modification ceiling
// is about 1.43% of all eligible channels.
const USAGE_NUMERATOR: usize = 1;
const USAGE_DENOMINATOR: usize = 4;

#[derive(Clone)]
pub struct StealthOptions {
    pub label: String,
    pub password: Zeroizing<String>,
    pub created_at: i64,
}

impl StealthOptions {
    pub fn new(password: Zeroizing<String>) -> Self {
        Self {
            label: String::new(),
            password,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs() as i64)
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StealthAnalysis {
    pub format: &'static str,
    pub width: u32,
    pub height: u32,
    pub color_type: &'static str,
    /// Maximum complete envelope size, including the encrypted internal header.
    pub capacity_bytes: usize,
    /// Approximate maximum note payload after subtracting envelope overhead.
    pub payload_capacity_bytes: usize,
    pub candidate_channels: usize,
    pub maximum_changed_channels: usize,
    pub maximum_change_percent: f64,
}

#[derive(Clone, Debug)]
pub struct StealthOutput {
    pub bytes: Vec<u8>,
    pub analysis: StealthAnalysis,
    pub envelope_bytes: usize,
    pub changed_channels: usize,
}

struct DecodedPng {
    info: png::Info<'static>,
    pixels: Vec<u8>,
    width: usize,
    height: usize,
    color_type: png::ColorType,
    channels: usize,
}

#[derive(Clone, Copy)]
struct Candidate {
    index: usize,
    score: u16,
}

pub fn analyze_png(data: &[u8]) -> Result<StealthAnalysis> {
    let image = decode_png(data)?;
    Ok(analyze_decoded(&image))
}

pub fn conceal_png(data: &[u8], text: &str, options: &StealthOptions) -> Result<StealthOutput> {
    if options.password.is_empty() {
        return Err(InvitextError::PasswordRequired);
    }

    let mut image = decode_png(data)?;
    let analysis = analyze_decoded(&image);
    let fingerprint = cover_fingerprint(&image);
    let mut candidates = ranked_candidates(&image);
    select_and_shuffle_candidates(&mut candidates, options.password.as_bytes(), &fingerprint);
    let usable_positions = usable_position_count(candidates.len());
    candidates.truncate(usable_positions);

    let mut note = Zeroizing::new(encode_note(options.label.as_bytes(), text.as_bytes())?);
    let compressed = zstd::stream::encode_all(Cursor::new(note.as_slice()), 9)?;
    let (flags, body_plaintext) = if compressed.len() < note.len() {
        (FLAG_COMPRESSED, Zeroizing::new(compressed))
    } else {
        (0, Zeroizing::new(std::mem::take(&mut *note)))
    };

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);
    let mut key = Zeroizing::new([0u8; 32]);
    derive_key(
        options.password.as_bytes(),
        &salt,
        KdfConfig::default(),
        &mut key,
    )?;

    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = envelope_aad(&fingerprint);
    let body_nonce = increment_nonce(nonce);
    let mut body_ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&body_nonce),
            Payload {
                msg: &body_plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| InvitextError::Crypto)?;

    let body_len = u32::try_from(body_ciphertext.len()).map_err(|_| InvitextError::SizeLimit {
        kind: "stealth payload",
        limit: u32::MAX as u64,
    })?;
    let decoded_len =
        u32::try_from(body_plaintext.len()).map_err(|_| InvitextError::SizeLimit {
            kind: "decoded stealth payload",
            limit: u32::MAX as u64,
        })?;
    let mut header_plaintext = encode_header(flags, body_len, decoded_len, options.created_at);
    let header_ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &header_plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| InvitextError::Crypto)?;
    header_plaintext.zeroize();
    debug_assert_eq!(header_ciphertext.len(), HEADER_CIPHERTEXT_BYTES);

    let mut envelope = Zeroizing::new(Vec::with_capacity(
        FIXED_ENVELOPE_BYTES + body_ciphertext.len(),
    ));
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&header_ciphertext);
    envelope.append(&mut body_ciphertext);

    if envelope.len() > analysis.capacity_bytes {
        return Err(InvitextError::InsufficientCapacity {
            available: analysis.capacity_bytes.saturating_sub(FIXED_ENVELOPE_BYTES),
            required: envelope.len().saturating_sub(FIXED_ENVELOPE_BYTES),
        });
    }

    let positions: Vec<usize> = candidates.iter().map(|candidate| candidate.index).collect();
    let changed_channels = matrix_embed(&mut image.pixels, &positions, &envelope)?;
    let encoded = encode_png(image)?;

    Ok(StealthOutput {
        bytes: encoded,
        analysis,
        envelope_bytes: envelope.len(),
        changed_channels,
    })
}

pub fn reveal_png(data: &[u8], password: &str) -> Result<EmbeddedNote> {
    if password.is_empty() {
        return Err(InvitextError::PasswordRequired);
    }

    let image = decode_png(data)?;
    let analysis = analyze_decoded(&image);
    if analysis.capacity_bytes < FIXED_ENVELOPE_BYTES {
        return Err(InvitextError::NoNote);
    }
    let fingerprint = cover_fingerprint(&image);
    let mut candidates = ranked_candidates(&image);
    select_and_shuffle_candidates(&mut candidates, password.as_bytes(), &fingerprint);
    candidates.truncate(usable_position_count(candidates.len()));
    let positions: Vec<usize> = candidates.iter().map(|candidate| candidate.index).collect();

    let prefix_and_header = Zeroizing::new(matrix_extract(
        &image.pixels,
        &positions,
        FIXED_ENVELOPE_BYTES,
    )?);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&prefix_and_header[..16]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&prefix_and_header[16..40]);
    let header_ciphertext = &prefix_and_header[40..FIXED_ENVELOPE_BYTES];

    let mut key = Zeroizing::new([0u8; 32]);
    derive_key(password.as_bytes(), &salt, KdfConfig::default(), &mut key)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = envelope_aad(&fingerprint);
    let mut header_plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: header_ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| InvitextError::DecryptionFailed)?;
    let header = decode_header(&header_plaintext)?;
    header_plaintext.zeroize();

    let total_envelope = FIXED_ENVELOPE_BYTES
        .checked_add(header.body_ciphertext_len)
        .ok_or(InvitextError::DamagedPayload)?;
    if total_envelope > analysis.capacity_bytes {
        return Err(InvitextError::DamagedPayload);
    }
    let envelope = Zeroizing::new(matrix_extract(&image.pixels, &positions, total_envelope)?);
    let body_ciphertext = &envelope[FIXED_ENVELOPE_BYTES..];
    let body_nonce = increment_nonce(nonce);
    let mut body = cipher
        .decrypt(
            XNonce::from_slice(&body_nonce),
            Payload {
                msg: body_ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| InvitextError::DecryptionFailed)?;
    if body.len() != header.decoded_body_len && header.flags & FLAG_COMPRESSED == 0 {
        body.zeroize();
        return Err(InvitextError::DamagedPayload);
    }

    let mut decoded = if header.flags & FLAG_COMPRESSED != 0 {
        let decoded = decode_zstd_limited(&body, MAX_DECODED_NOTE)?;
        body.zeroize();
        decoded
    } else {
        body
    };
    if decoded.len() != header.decoded_body_len {
        decoded.zeroize();
        return Err(InvitextError::DamagedPayload);
    }
    let (label, text) = decode_note(&decoded)?;
    decoded.zeroize();

    Ok(EmbeddedNote {
        text: String::from_utf8(text).map_err(|_| InvitextError::InvalidUtf8)?,
        label: String::from_utf8(label).map_err(|_| InvitextError::InvalidUtf8)?,
        created_at: header.created_at,
        encrypted: true,
        compressed: header.flags & FLAG_COMPRESSED != 0,
    })
}

struct EnvelopeHeader {
    flags: u16,
    body_ciphertext_len: usize,
    decoded_body_len: usize,
    created_at: i64,
}

fn encode_header(flags: u16, body_len: u32, decoded_len: u32, created_at: i64) -> [u8; 32] {
    let mut header = [0u8; 32];
    header[..8].copy_from_slice(ENVELOPE_MAGIC);
    header[8..10].copy_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    header[10..12].copy_from_slice(&flags.to_le_bytes());
    header[12..16].copy_from_slice(&body_len.to_le_bytes());
    header[16..20].copy_from_slice(&decoded_len.to_le_bytes());
    header[20..28].copy_from_slice(&created_at.to_le_bytes());
    rand::rng().fill_bytes(&mut header[28..32]);
    header
}

fn decode_header(data: &[u8]) -> Result<EnvelopeHeader> {
    if data.len() != HEADER_PLAINTEXT_BYTES || &data[..8] != ENVELOPE_MAGIC {
        return Err(InvitextError::DecryptionFailed);
    }
    let version = u16::from_le_bytes(data[8..10].try_into().unwrap());
    if version != ENVELOPE_VERSION {
        return Err(InvitextError::UnsupportedVersion(version));
    }
    let flags = u16::from_le_bytes(data[10..12].try_into().unwrap());
    if flags & !FLAG_COMPRESSED != 0 {
        return Err(InvitextError::DamagedPayload);
    }
    let body_ciphertext_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
    let decoded_body_len = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    if body_ciphertext_len < 16 || decoded_body_len as u64 > MAX_DECODED_NOTE {
        return Err(InvitextError::DamagedPayload);
    }
    Ok(EnvelopeHeader {
        flags,
        body_ciphertext_len,
        decoded_body_len,
        created_at: i64::from_le_bytes(data[20..28].try_into().unwrap()),
    })
}

fn decode_png(data: &[u8]) -> Result<DecodedPng> {
    if data.len() > MAX_DECODED_PNG {
        return Err(InvitextError::SizeLimit {
            kind: "PNG input",
            limit: MAX_DECODED_PNG as u64,
        });
    }
    validate_no_trailing_png_data(data)?;
    let decoder = png::Decoder::new(Cursor::new(data));
    let mut reader = decoder
        .read_info()
        .map_err(|error| InvitextError::Png(error.to_string()))?;
    if reader.info().animation_control.is_some() {
        return Err(InvitextError::UnsupportedStealthCarrier(
            "animated PNG files are not supported",
        ));
    }
    let buffer_size = reader
        .output_buffer_size()
        .ok_or(InvitextError::InvalidFormat("PNG dimensions are too large"))?;
    if buffer_size > MAX_DECODED_PNG {
        return Err(InvitextError::SizeLimit {
            kind: "decoded PNG",
            limit: MAX_DECODED_PNG as u64,
        });
    }
    let mut pixels = vec![0u8; buffer_size];
    let output = reader
        .next_frame(&mut pixels)
        .map_err(|error| InvitextError::Png(error.to_string()))?;
    pixels.truncate(output.buffer_size());
    if output.bit_depth != png::BitDepth::Eight {
        return Err(InvitextError::UnsupportedStealthCarrier(
            "only 8-bit PNG color channels are supported",
        ));
    }
    if output.color_type == png::ColorType::Indexed {
        return Err(InvitextError::UnsupportedStealthCarrier(
            "indexed-color PNG files must first be converted to RGB or RGBA",
        ));
    }
    let channels = output.color_type.samples();
    let expected = (output.width as usize)
        .checked_mul(output.height as usize)
        .and_then(|pixels| pixels.checked_mul(channels))
        .ok_or(InvitextError::InvalidFormat("PNG dimensions are too large"))?;
    if pixels.len() != expected {
        return Err(InvitextError::InvalidFormat(
            "PNG frame layout is not supported",
        ));
    }
    let mut info = reader.info().clone();
    info.interlaced = false;
    info.animation_control = None;
    info.frame_control = None;
    Ok(DecodedPng {
        info,
        pixels,
        width: output.width as usize,
        height: output.height as usize,
        color_type: output.color_type,
        channels,
    })
}

fn validate_no_trailing_png_data(data: &[u8]) -> Result<()> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if data.len() < SIGNATURE.len() || &data[..8] != SIGNATURE {
        return Err(InvitextError::UnsupportedStealthCarrier(
            "the input is not a PNG file",
        ));
    }
    let mut cursor = SIGNATURE.len();
    loop {
        let header_end = cursor
            .checked_add(8)
            .ok_or(InvitextError::InvalidFormat("PNG chunk length overflow"))?;
        if header_end > data.len() {
            return Err(InvitextError::Png("truncated chunk header".into()));
        }
        let length = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
        let chunk_type = &data[cursor + 4..cursor + 8];
        let chunk_end = header_end
            .checked_add(length)
            .and_then(|end| end.checked_add(4))
            .ok_or(InvitextError::InvalidFormat("PNG chunk length overflow"))?;
        if chunk_end > data.len() {
            return Err(InvitextError::Png("truncated chunk data".into()));
        }
        cursor = chunk_end;
        if chunk_type == b"IEND" {
            if cursor != data.len() {
                return Err(InvitextError::UnsupportedStealthCarrier(
                    "PNG files with trailing data cannot be used in stealth mode",
                ));
            }
            return Ok(());
        }
    }
}

fn encode_png(image: DecodedPng) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    {
        let encoder = png::Encoder::with_info(&mut encoded, image.info)
            .map_err(|error| InvitextError::Png(error.to_string()))?;
        let mut writer = encoder
            .write_header()
            .map_err(|error| InvitextError::Png(error.to_string()))?;
        writer
            .write_image_data(&image.pixels)
            .map_err(|error| InvitextError::Png(error.to_string()))?;
    }
    Ok(encoded)
}

fn analyze_decoded(image: &DecodedPng) -> StealthAnalysis {
    let candidates = ranked_candidates(image);
    let usable = usable_position_count(candidates.len());
    let capacity_bytes = matrix_capacity_bytes(usable);
    let eligible = eligible_channel_count(image);
    let maximum_changed_channels = usable / 7;
    StealthAnalysis {
        format: "png-stealth-v1",
        width: image.width as u32,
        height: image.height as u32,
        color_type: color_type_name(image.color_type),
        capacity_bytes,
        payload_capacity_bytes: capacity_bytes.saturating_sub(FIXED_ENVELOPE_BYTES + 16),
        candidate_channels: candidates.len(),
        maximum_changed_channels,
        maximum_change_percent: if eligible == 0 {
            0.0
        } else {
            maximum_changed_channels as f64 * 100.0 / eligible as f64
        },
    }
}

fn ranked_candidates(image: &DecodedPng) -> Vec<Candidate> {
    let mut candidates = Vec::with_capacity(eligible_channel_count(image));
    for y in 0..image.height {
        for x in 0..image.width {
            let pixel = y * image.width + x;
            if alpha_too_transparent(image, pixel) {
                continue;
            }
            let activity = local_activity(image, x, y);
            let base = pixel * image.channels;
            for offset in eligible_offsets(image.color_type) {
                let index = base + *offset;
                let channel_activity = local_channel_activity(image, x, y, *offset);
                candidates.push(Candidate {
                    index,
                    score: activity.saturating_mul(2).saturating_add(channel_activity),
                });
            }
        }
    }
    candidates.sort_unstable_by(|left, right| match right.score.cmp(&left.score) {
        Ordering::Equal => left.index.cmp(&right.index),
        order => order,
    });
    let keep = candidates.len().saturating_mul(CANDIDATE_NUMERATOR) / CANDIDATE_DENOMINATOR;
    candidates.truncate(keep);
    candidates
}

fn select_and_shuffle_candidates(
    candidates: &mut [Candidate],
    password: &[u8],
    fingerprint: &[u8; 32],
) {
    let mut seed_hasher = blake3::Hasher::new_derive_key("Invitext PNG placement v1");
    seed_hasher.update(password);
    seed_hasher.update(fingerprint);
    let seed = *seed_hasher.finalize().as_bytes();
    let mut rng = ChaCha20Rng::from_seed(seed);
    candidates.shuffle(&mut rng);
}

fn cover_fingerprint(image: &DecodedPng) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("Invitext PNG cover fingerprint v1");
    hasher.update(&(image.width as u64).to_le_bytes());
    hasher.update(&(image.height as u64).to_le_bytes());
    hasher.update(&[image.color_type as u8]);
    for (index, value) in image.pixels.iter().copied().enumerate() {
        let offset = index % image.channels;
        if eligible_offsets(image.color_type).contains(&offset) {
            hasher.update(&[value & 0xfe]);
        } else {
            hasher.update(&[value]);
        }
    }
    *hasher.finalize().as_bytes()
}

fn envelope_aad(fingerprint: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(56);
    aad.extend_from_slice(b"Invitext PNG stealth envelope v1");
    aad.extend_from_slice(fingerprint);
    aad
}

fn increment_nonce(mut nonce: [u8; 24]) -> [u8; 24] {
    for byte in nonce.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
    nonce
}

fn matrix_embed(pixels: &mut [u8], positions: &[usize], data: &[u8]) -> Result<usize> {
    let bit_count = data
        .len()
        .checked_mul(8)
        .ok_or(InvitextError::DamagedPayload)?;
    let groups = bit_count.div_ceil(3);
    let required_positions = groups.checked_mul(7).ok_or(InvitextError::DamagedPayload)?;
    if required_positions > positions.len() {
        return Err(InvitextError::InsufficientCapacity {
            available: matrix_capacity_bytes(positions.len()),
            required: data.len(),
        });
    }

    let mut changed = 0;
    for group in 0..groups {
        let mut desired = 0u8;
        for bit_offset in 0..3 {
            desired <<= 1;
            let bit_index = group * 3 + bit_offset;
            if bit_index < bit_count {
                desired |= bit_at(data, bit_index);
            }
        }
        let group_positions = &positions[group * 7..group * 7 + 7];
        let mut syndrome = 0u8;
        for (slot, position) in group_positions.iter().enumerate() {
            if pixels[*position] & 1 == 1 {
                syndrome ^= (slot + 1) as u8;
            }
        }
        let flip = syndrome ^ desired;
        if flip != 0 {
            pixels[group_positions[flip as usize - 1]] ^= 1;
            changed += 1;
        }
    }
    Ok(changed)
}

fn matrix_extract(pixels: &[u8], positions: &[usize], byte_count: usize) -> Result<Vec<u8>> {
    let bit_count = byte_count
        .checked_mul(8)
        .ok_or(InvitextError::DamagedPayload)?;
    let groups = bit_count.div_ceil(3);
    let required_positions = groups.checked_mul(7).ok_or(InvitextError::DamagedPayload)?;
    if required_positions > positions.len() {
        return Err(InvitextError::DamagedPayload);
    }
    let mut output = vec![0u8; byte_count];
    let mut output_bit = 0;
    for group in 0..groups {
        let mut syndrome = 0u8;
        for slot in 0..7 {
            let position = positions[group * 7 + slot];
            if pixels[position] & 1 == 1 {
                syndrome ^= (slot + 1) as u8;
            }
        }
        for shift in (0..3).rev() {
            if output_bit < bit_count {
                set_bit(&mut output, output_bit, (syndrome >> shift) & 1);
                output_bit += 1;
            }
        }
    }
    Ok(output)
}

fn bit_at(data: &[u8], bit: usize) -> u8 {
    (data[bit / 8] >> (7 - bit % 8)) & 1
}

fn set_bit(data: &mut [u8], bit: usize, value: u8) {
    data[bit / 8] |= value << (7 - bit % 8);
}

fn matrix_capacity_bytes(positions: usize) -> usize {
    (positions / 7 * 3) / 8
}

fn usable_position_count(candidate_count: usize) -> usize {
    candidate_count.saturating_mul(USAGE_NUMERATOR) / USAGE_DENOMINATOR
}

fn eligible_channel_count(image: &DecodedPng) -> usize {
    let offsets = eligible_offsets(image.color_type).len();
    if matches!(
        image.color_type,
        png::ColorType::GrayscaleAlpha | png::ColorType::Rgba
    ) {
        (0..image.width * image.height)
            .filter(|pixel| !alpha_too_transparent(image, *pixel))
            .count()
            * offsets
    } else {
        image.width * image.height * offsets
    }
}

fn eligible_offsets(color_type: png::ColorType) -> &'static [usize] {
    match color_type {
        png::ColorType::Grayscale => &[0],
        png::ColorType::Rgb => &[0, 1, 2],
        png::ColorType::GrayscaleAlpha => &[0],
        png::ColorType::Rgba => &[0, 1, 2],
        png::ColorType::Indexed => &[],
    }
}

fn alpha_too_transparent(image: &DecodedPng, pixel: usize) -> bool {
    match image.color_type {
        png::ColorType::GrayscaleAlpha => image.pixels[pixel * image.channels + 1] < 32,
        png::ColorType::Rgba => image.pixels[pixel * image.channels + 3] < 32,
        _ => false,
    }
}

fn local_activity(image: &DecodedPng, x: usize, y: usize) -> u16 {
    let center = luminance(image, x, y);
    let mut total = 0u16;
    let mut count = 0u16;
    for (nx, ny) in neighbors(x, y, image.width, image.height) {
        total = total.saturating_add(center.abs_diff(luminance(image, nx, ny)) as u16);
        count += 1;
    }
    total.checked_div(count).unwrap_or(0)
}

fn local_channel_activity(image: &DecodedPng, x: usize, y: usize, offset: usize) -> u16 {
    let center = image.pixels[(y * image.width + x) * image.channels + offset] & 0xfe;
    let mut total = 0u16;
    let mut count = 0u16;
    for (nx, ny) in neighbors(x, y, image.width, image.height) {
        let other = image.pixels[(ny * image.width + nx) * image.channels + offset] & 0xfe;
        total = total.saturating_add(center.abs_diff(other) as u16);
        count += 1;
    }
    total.checked_div(count).unwrap_or(0)
}

fn luminance(image: &DecodedPng, x: usize, y: usize) -> u8 {
    let base = (y * image.width + x) * image.channels;
    match image.color_type {
        png::ColorType::Grayscale | png::ColorType::GrayscaleAlpha => image.pixels[base] & 0xfe,
        png::ColorType::Rgb | png::ColorType::Rgba => {
            let red = (image.pixels[base] & 0xfe) as u16;
            let green = (image.pixels[base + 1] & 0xfe) as u16;
            let blue = (image.pixels[base + 2] & 0xfe) as u16;
            ((54 * red + 183 * green + 19 * blue) >> 8) as u8
        }
        png::ColorType::Indexed => 0,
    }
}

fn neighbors(
    x: usize,
    y: usize,
    width: usize,
    height: usize,
) -> impl Iterator<Item = (usize, usize)> {
    let left = x.checked_sub(1).map(|next| (next, y));
    let right = x
        .checked_add(1)
        .filter(|next| *next < width)
        .map(|next| (next, y));
    let up = y.checked_sub(1).map(|next| (x, next));
    let down = y
        .checked_add(1)
        .filter(|next| *next < height)
        .map(|next| (x, next));
    [left, right, up, down].into_iter().flatten()
}

fn color_type_name(color_type: png::ColorType) -> &'static str {
    match color_type {
        png::ColorType::Grayscale => "grayscale-8",
        png::ColorType::Rgb => "rgb-8",
        png::ColorType::Indexed => "indexed",
        png::ColorType::GrayscaleAlpha => "grayscale-alpha-8",
        png::ColorType::Rgba => "rgba-8",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carrier(width: u32, height: u32) -> Vec<u8> {
        let mut pixels = Vec::with_capacity(width as usize * height as usize * 4);
        for y in 0..height {
            for x in 0..width {
                pixels.extend_from_slice(&[
                    ((x * 17 + y * 31) % 256) as u8,
                    ((x * 47 + y * 13) % 256) as u8,
                    ((x * 7 + y * 61) % 256) as u8,
                    255,
                ]);
            }
        }
        let mut output = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut output, width, height);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&pixels)
                .unwrap();
        }
        output
    }

    fn carrier_for_color(color: png::ColorType) -> Vec<u8> {
        let width = 256u32;
        let height = 256u32;
        let channels = color.samples();
        let mut pixels = Vec::with_capacity(width as usize * height as usize * channels);
        for y in 0..height {
            for x in 0..width {
                let values = [
                    ((x * 17 + y * 31) % 256) as u8,
                    ((x * 47 + y * 13) % 256) as u8,
                    ((x * 7 + y * 61) % 256) as u8,
                    255,
                ];
                match color {
                    png::ColorType::Grayscale => pixels.push(values[0]),
                    png::ColorType::Rgb => pixels.extend_from_slice(&values[..3]),
                    png::ColorType::GrayscaleAlpha => {
                        pixels.extend_from_slice(&[values[0], values[3]])
                    }
                    png::ColorType::Rgba => pixels.extend_from_slice(&values),
                    png::ColorType::Indexed => unreachable!(),
                }
            }
        }
        let mut output = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut output, width, height);
            encoder.set_color(color);
            encoder.set_depth(png::BitDepth::Eight);
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&pixels)
                .unwrap();
        }
        output
    }

    #[test]
    fn stealth_round_trip_and_wrong_password() {
        let source = carrier(256, 256);
        let mut options = StealthOptions::new(Zeroizing::new("correct horse".into()));
        options.label = "private".into();
        options.created_at = 1_700_000_000;
        let hidden = conceal_png(&source, "hello, dünya", &options).unwrap();

        assert!(!hidden.bytes.windows(8).any(|window| window == b"INVITEXT"));
        assert!(
            !hidden
                .bytes
                .windows(8)
                .any(|window| window == ENVELOPE_MAGIC)
        );
        assert!(hidden.changed_channels <= hidden.analysis.maximum_changed_channels);
        assert!(matches!(
            reveal_png(&hidden.bytes, "wrong"),
            Err(InvitextError::DecryptionFailed)
        ));
        let note = reveal_png(&hidden.bytes, "correct horse").unwrap();
        assert_eq!(note.text, "hello, dünya");
        assert_eq!(note.label, "private");
        assert_eq!(note.created_at, 1_700_000_000);
    }

    #[test]
    fn changes_only_color_lsb_and_preserves_alpha() {
        let source = carrier(256, 256);
        let options = StealthOptions::new(Zeroizing::new("password".into()));
        let hidden = conceal_png(&source, &"text ".repeat(300), &options).unwrap();
        let before = decode_png(&source).unwrap();
        let after = decode_png(&hidden.bytes).unwrap();
        let mut changes = 0;
        for (index, (left, right)) in before.pixels.iter().zip(&after.pixels).enumerate() {
            if index % 4 == 3 {
                assert_eq!(left, right);
            } else {
                assert!(left.abs_diff(*right) <= 1);
                changes += usize::from(left != right);
            }
        }
        assert_eq!(changes, hidden.changed_channels);
    }

    #[test]
    fn supports_each_documented_eight_bit_color_layout() {
        for color in [
            png::ColorType::Grayscale,
            png::ColorType::Rgb,
            png::ColorType::GrayscaleAlpha,
            png::ColorType::Rgba,
        ] {
            let source = carrier_for_color(color);
            let options = StealthOptions::new(Zeroizing::new("password".into()));
            let hidden = conceal_png(&source, "layout test", &options).unwrap();
            assert_eq!(
                reveal_png(&hidden.bytes, "password").unwrap().text,
                "layout test"
            );
        }
    }

    #[test]
    fn rejects_indexed_color_png() {
        let mut source = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut source, 128, 128);
            encoder.set_color(png::ColorType::Indexed);
            encoder.set_depth(png::BitDepth::Eight);
            encoder.set_palette(vec![0, 0, 0, 255, 255, 255]);
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&vec![0; 128 * 128])
                .unwrap();
        }
        assert!(matches!(
            analyze_png(&source),
            Err(InvitextError::UnsupportedStealthCarrier(_))
        ));
    }

    #[test]
    fn small_carrier_reports_capacity_error() {
        let source = carrier(32, 32);
        let options = StealthOptions::new(Zeroizing::new("password".into()));
        assert!(matches!(
            conceal_png(&source, "note", &options),
            Err(InvitextError::InsufficientCapacity { .. })
        ));
    }

    #[test]
    fn rejects_trailing_data_instead_of_discarding_it() {
        let mut source = carrier(256, 256);
        source.extend_from_slice(b"important trailing bytes");
        let options = StealthOptions::new(Zeroizing::new("password".into()));
        assert!(matches!(
            conceal_png(&source, "note", &options),
            Err(InvitextError::UnsupportedStealthCarrier(_))
        ));
    }
}
