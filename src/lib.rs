//! Core file format and I/O primitives for Invitext.
//!
//! The public API is intentionally small. The CLI is the primary interface, but
//! keeping the container implementation here makes the format testable and lets
//! other Rust programs integrate without spawning a process.

pub mod container;
pub mod error;
pub mod io;
pub mod stealth;

pub use container::{
    EmbedOptions, EmbeddedNote, EncryptionOptions, KdfConfig, NoteInfo, ScanResult, build_record,
    embed_bytes, reveal_note, reveal_note_reader, scan, scan_reader,
};
pub use error::{InvitextError, Result};
pub use stealth::{
    MAX_STEALTH_PNG_BYTES, StealthAnalysis, StealthOptions, StealthOutput, analyze_png,
    conceal_png, reveal_png,
};

/// Current on-disk format version.
pub const FORMAT_VERSION: u16 = 1;
