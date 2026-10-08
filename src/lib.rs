//! Authenticated text and binary file containers for Invitext.
//!
//! The public API is intentionally small. The CLI is the primary interface, but
//! keeping the container implementation here makes the format testable and lets
//! other Rust programs integrate without spawning a process.

pub mod container;
pub mod content;
pub mod error;
pub mod io;
pub mod stealth;

pub use container::{
    EmbedOptions, EmbeddedNote, EncryptionOptions, KdfConfig, NoteInfo, ScanResult,
    build_file_record, build_record, embed_bytes, reveal_content, reveal_content_reader,
    reveal_note, reveal_note_reader, scan, scan_reader,
};
pub use content::{EmbeddedContent, EmbeddedFile, MAX_ATTACHMENT_BYTES};
pub use error::{InvitextError, Result};
pub use stealth::{
    MAX_STEALTH_PNG_BYTES, StealthAnalysis, StealthOptions, StealthOutput, analyze_png,
    conceal_file_png, conceal_png, reveal_png, reveal_png_content,
};

/// Current on-disk format version.
pub const FORMAT_VERSION: u16 = 1;
