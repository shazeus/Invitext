use thiserror::Error;

pub type Result<T> = std::result::Result<T, InvitextError>;

#[derive(Debug, Error)]
pub enum InvitextError {
    #[error("no Invitext note was found in this file")]
    NoNote,

    #[error("the Invitext footer is damaged or incomplete")]
    DamagedFooter,

    #[error("the hidden payload is damaged or was modified")]
    DamagedPayload,

    #[error("the carrier data was modified after the note was added")]
    CarrierModified,

    #[error("the password is incorrect or the encrypted note is damaged")]
    DecryptionFailed,

    #[error("this note is encrypted; provide its password")]
    PasswordRequired,

    #[error("this note is not encrypted")]
    NotEncrypted,

    #[error("this payload contains a file; use itx extract with --output")]
    FilePayload,

    #[error("this payload contains text; use itx reveal")]
    TextPayload,

    #[error("unsupported Invitext format version {0}")]
    UnsupportedVersion(u16),

    #[error("note index {requested} is out of range (file contains {available} note(s))")]
    InvalidIndex { requested: usize, available: usize },

    #[error("hidden text is not valid UTF-8")]
    InvalidUtf8,

    #[error("invalid format: {0}")]
    InvalidFormat(&'static str),

    #[error("operation would exceed the configured {kind} limit of {limit} bytes")]
    SizeLimit { kind: &'static str, limit: u64 },

    #[error("the carrier has {available} bytes of stealth capacity; {required} bytes are required")]
    InsufficientCapacity { available: usize, required: usize },

    #[error("unsupported stealth carrier: {0}")]
    UnsupportedStealthCarrier(&'static str),

    #[error("could not process PNG carrier: {0}")]
    Png(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("cryptographic operation failed")]
    Crypto,
}
