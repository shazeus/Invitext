use std::env;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use invitext::container::{EmbedOptions, EncryptionOptions, KdfConfig};
use invitext::io::{
    copy_prefix_atomic, default_clean_path, default_hidden_path, embed_file_atomic, file_len,
    read_file_limited, write_atomic,
};
use invitext::{
    InvitextError, MAX_STEALTH_PNG_BYTES, StealthAnalysis, StealthOptions, analyze_png,
    conceal_png, reveal_note_reader, reveal_png, scan_reader,
};
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "invitext",
    bin_name = "itx",
    version,
    about = "Hide encrypted text inside files",
    long_about = "Invitext conceals encrypted text inside supported PNG color data or appends authenticated notes to images, archives, documents, media, and other files. Use --mode stealth for low-density PNG embedding or the default append mode for broad compatibility."
)]
struct Cli {
    /// Print machine-readable JSON where supported
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Add a hidden text note to a carrier file
    #[command(alias = "embed", alias = "encode")]
    Hide(HideArgs),

    /// Read a hidden note
    #[command(alias = "decode", alias = "extract", alias = "show")]
    Reveal(RevealArgs),

    /// List append-mode notes without decrypting them
    #[command(alias = "ls")]
    List(FileArgs),

    /// Verify append hashes or authenticate a stealth note
    #[command(alias = "check")]
    Verify(VerifyArgs),

    /// Remove the latest append note or all appended Invitext data
    #[command(alias = "clean", alias = "remove")]
    Strip(StripArgs),

    /// Show carrier type, size, compatibility, and note summary
    #[command(alias = "info")]
    Inspect(FileArgs),

    /// Generate shell completion scripts
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Args, Debug)]
struct FileArgs {
    /// File containing one or more Invitext notes
    file: PathBuf,
}

#[derive(Args, Debug)]
struct HideArgs {
    /// Carrier file (image, archive, document, media, or any regular file)
    file: PathBuf,

    /// Text to hide. Omit to read from stdin
    #[arg(short = 'm', long, conflicts_with = "message_file")]
    message: Option<String>,

    /// Read the hidden text from a UTF-8 file
    #[arg(short = 'f', long, value_name = "PATH", conflicts_with = "message")]
    message_file: Option<PathBuf>,

    /// A label stored inside the note body
    #[arg(short = 'l', long, default_value = "")]
    label: String,

    /// Encrypt an append note; stealth mode is always encrypted
    #[arg(short = 'e', long)]
    encrypt: bool,

    #[command(flatten)]
    password: PasswordArgs,

    /// Storage method: compatible appended record or low-density PNG embedding
    #[arg(long, value_enum, default_value_t = StorageMode::Append)]
    mode: StorageMode,

    /// Output path. Defaults to `<name>.invitext.<ext>`
    #[arg(short, long, conflicts_with = "in_place")]
    output: Option<PathBuf>,

    /// Replace the carrier atomically instead of creating a copy
    #[arg(long, conflicts_with = "output")]
    in_place: bool,

    /// Disable zstd compression in append mode
    #[arg(long)]
    no_compress: bool,

    /// Replace an existing output file
    #[arg(long)]
    force: bool,

    /// Argon2id memory cost preset for append mode
    #[arg(long, value_enum, default_value_t = KdfPreset::Standard)]
    kdf: KdfPreset,
}

#[derive(Args, Debug, Default)]
struct PasswordArgs {
    /// Password value (convenient, but visible in shell history)
    #[arg(long, value_name = "PASSWORD", conflicts_with_all = ["password_file", "password_env"])]
    password: Option<String>,

    /// Read the password from the first line of a file
    #[arg(long, value_name = "PATH", conflicts_with_all = ["password", "password_env"])]
    password_file: Option<PathBuf>,

    /// Read the password from an environment variable
    #[arg(long, value_name = "NAME", conflicts_with_all = ["password", "password_file"])]
    password_env: Option<String>,
}

#[derive(Args, Debug)]
struct RevealArgs {
    file: PathBuf,

    /// Storage method used when the note was hidden
    #[arg(long, value_enum, default_value_t = StorageMode::Append)]
    mode: StorageMode,

    /// One-based note index (oldest is 1). Defaults to the latest note
    #[arg(short, long, conflicts_with = "all")]
    index: Option<usize>,

    /// Reveal all notes in chronological order
    #[arg(long, conflicts_with = "index")]
    all: bool,

    /// Write revealed text to a file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Replace an existing output file
    #[arg(long)]
    force: bool,

    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    file: PathBuf,

    /// Storage method used when the note was hidden
    #[arg(long, value_enum, default_value_t = StorageMode::Append)]
    mode: StorageMode,

    /// Also decrypt an append note; stealth verification is always deep
    #[arg(short, long)]
    deep: bool,

    /// Note to decrypt during --deep verification (defaults to latest)
    #[arg(short, long, requires = "deep")]
    index: Option<usize>,

    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args, Debug)]
struct StripArgs {
    file: PathBuf,

    /// Remove only the newest note, preserving older notes
    #[arg(long)]
    latest: bool,

    /// Output path. Defaults to `<name>.clean.<ext>`
    #[arg(short, long, conflicts_with = "in_place")]
    output: Option<PathBuf>,

    /// Replace the input atomically
    #[arg(long, conflicts_with = "output")]
    in_place: bool,

    /// Replace an existing output file
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum StorageMode {
    /// Authenticated trailer; works with almost any file type but is identifiable
    Append,
    /// Password-keyed, low-density embedding for supported PNG images
    Stealth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KdfPreset {
    Interactive,
    Standard,
    Hardened,
}

impl KdfPreset {
    fn config(self) -> KdfConfig {
        match self {
            Self::Interactive => KdfConfig {
                memory_kib: 32 * 1024,
                iterations: 2,
                parallelism: 1,
            },
            Self::Standard => KdfConfig::default(),
            Self::Hardened => KdfConfig {
                memory_kib: 128 * 1024,
                iterations: 4,
                parallelism: 1,
            },
        }
    }
}

#[derive(Serialize)]
struct ActionResult<'a> {
    status: &'a str,
    input: String,
    output: Option<String>,
    notes: usize,
    bytes: u64,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Hide(args) => hide(args, cli.json),
        Command::Reveal(args) => reveal(args, cli.json),
        Command::List(args) => list(args.file, cli.json),
        Command::Verify(args) => verify(args, cli.json),
        Command::Strip(args) => strip(args, cli.json),
        Command::Inspect(args) => inspect(args.file, cli.json),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "itx", &mut io::stdout());
            Ok(())
        }
    }
}

fn hide(mut args: HideArgs, json: bool) -> anyhow::Result<()> {
    ensure_distinct_password_sources(&args.password)?;
    let text = read_message(args.message.take(), args.message_file.take())?;
    if text.is_empty() {
        bail!("refusing to hide an empty message");
    }

    let supplied_password = resolve_password(&args.password, false)?;
    if args.mode == StorageMode::Stealth {
        return hide_stealth(args, text, supplied_password, json);
    }
    let encryption = if args.encrypt || supplied_password.is_some() {
        let password = match supplied_password {
            Some(password) => password,
            None => prompt_new_password()?,
        };
        if password.is_empty() {
            bail!("password cannot be empty");
        }
        Some(EncryptionOptions {
            password,
            kdf: args.kdf.config(),
        })
    } else {
        None
    };

    let carrier_len = file_len(&args.file)
        .with_context(|| format!("could not inspect {}", args.file.display()))?;
    let existing_notes = {
        let mut file = File::open(&args.file)?;
        match scan_reader(&mut file, carrier_len, true) {
            Ok(result) => {
                if result.notes.iter().any(|note| !note.intact) {
                    return Err(InvitextError::CarrierModified.into());
                }
                result.notes.len()
            }
            Err(InvitextError::NoNote) => 0,
            Err(error) => return Err(error.into()),
        }
    };
    let options = EmbedOptions {
        label: args.label,
        compression: !args.no_compress,
        encryption,
        ..EmbedOptions::default()
    };
    let note_count = existing_notes + 1;
    let output = if args.in_place {
        args.file.clone()
    } else {
        args.output
            .unwrap_or_else(|| default_hidden_path(&args.file))
    };
    if !args.in_place && paths_refer_to_same_file(&args.file, &output) {
        bail!("output resolves to the carrier; use --in-place explicitly");
    }
    let overwrite = args.in_place || args.force;
    let output_size = embed_file_atomic(&args.file, &output, &text, &options, overwrite)
        .with_context(|| format!("could not write {}", output.display()))?;

    let result = ActionResult {
        status: "hidden",
        input: args.file.display().to_string(),
        output: Some(output.display().to_string()),
        notes: note_count,
        bytes: output_size,
    };
    if json {
        print_json(&result)?;
    } else {
        println!("Hidden note #{note_count} in {}", output.display());
        println!(
            "{} total · {}",
            human_size(output_size),
            encryption_status(&options)
        );
    }
    Ok(())
}

fn hide_stealth(
    args: HideArgs,
    text: String,
    supplied_password: Option<Zeroizing<String>>,
    json: bool,
) -> anyhow::Result<()> {
    if args.no_compress {
        bail!(
            "--no-compress is not available in stealth mode; Invitext selects the safer representation automatically"
        );
    }
    if args.kdf != KdfPreset::Standard {
        bail!("PNG stealth format v1 uses its fixed standard Argon2id profile");
    }
    let password = match supplied_password {
        Some(password) => password,
        None => prompt_new_password()?,
    };
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    let output = if args.in_place {
        args.file.clone()
    } else {
        args.output
            .unwrap_or_else(|| default_hidden_path(&args.file))
    };
    if !args.in_place && paths_refer_to_same_file(&args.file, &output) {
        bail!("output resolves to the carrier; use --in-place explicitly");
    }
    let carrier = read_stealth_png(&args.file)
        .with_context(|| format!("could not read {}", args.file.display()))?;
    let mut options = StealthOptions::new(password);
    options.label = args.label;
    let concealed = conceal_png(&carrier, &text, &options)?;
    write_atomic(&output, &concealed.bytes, args.in_place || args.force)
        .with_context(|| format!("could not write {}", output.display()))?;

    if json {
        #[derive(Serialize)]
        struct StealthAction {
            status: &'static str,
            mode: &'static str,
            input: String,
            output: String,
            bytes: usize,
            envelope_bytes: usize,
            changed_channels: usize,
            maximum_change_percent: f64,
        }
        print_json(&StealthAction {
            status: "hidden",
            mode: "stealth",
            input: args.file.display().to_string(),
            output: output.display().to_string(),
            bytes: concealed.bytes.len(),
            envelope_bytes: concealed.envelope_bytes,
            changed_channels: concealed.changed_channels,
            maximum_change_percent: concealed.analysis.maximum_change_percent,
        })?;
    } else {
        println!("Concealed one encrypted note in {}", output.display());
        println!(
            "{} total · {} channel changes · {:.3}% policy ceiling",
            human_size(concealed.bytes.len() as u64),
            concealed.changed_channels,
            concealed.analysis.maximum_change_percent
        );
    }
    Ok(())
}

fn reveal(args: RevealArgs, json: bool) -> anyhow::Result<()> {
    ensure_distinct_password_sources(&args.password)?;
    if args.mode == StorageMode::Stealth {
        return reveal_stealth(args, json);
    }
    let total_size = file_len(&args.file)?;
    let mut file = File::open(&args.file)
        .with_context(|| format!("could not read {}", args.file.display()))?;
    let result = scan_reader(&mut file, total_size, false)?;
    let indexes: Vec<usize> = if args.all {
        (1..=result.notes.len()).collect()
    } else {
        vec![args.index.unwrap_or(result.notes.len())]
    };

    let needs_password = indexes.iter().any(|index| {
        result
            .notes
            .get(index.saturating_sub(1))
            .is_some_and(|note| note.encrypted)
    });
    let mut password = resolve_password(&args.password, false)?;
    if needs_password && password.is_none() {
        password = Some(Zeroizing::new(rpassword::prompt_password("Password: ")?));
    }

    let mut notes = Vec::with_capacity(indexes.len());
    for index in indexes {
        notes.push((
            index,
            reveal_note_reader(
                &mut file,
                total_size,
                index,
                password.as_deref().map(|value| value.as_str()),
            )?,
        ));
    }

    if json {
        #[derive(Serialize)]
        struct JsonNote<'a> {
            index: usize,
            label: &'a str,
            text: &'a str,
            created_at: String,
            encrypted: bool,
            compressed: bool,
        }
        let output: Vec<_> = notes
            .iter()
            .map(|(index, note)| JsonNote {
                index: *index,
                label: &note.label,
                text: &note.text,
                created_at: format_time(note.created_at),
                encrypted: note.encrypted,
                compressed: note.compressed,
            })
            .collect();
        print_json(&output)?;
        return Ok(());
    }

    let rendered = if notes.len() == 1 {
        notes[0].1.text.clone()
    } else {
        notes
            .iter()
            .map(|(index, note)| {
                let label = if note.label.is_empty() {
                    String::new()
                } else {
                    format!(" · {}", note.label)
                };
                format!("--- note #{index}{label} ---\n{}", note.text)
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    };

    if let Some(output) = args.output {
        if paths_refer_to_same_file(&args.file, &output) {
            bail!("refusing to overwrite the carrier with revealed text");
        }
        write_atomic(&output, rendered.as_bytes(), args.force)
            .with_context(|| format!("could not write {}", output.display()))?;
        eprintln!("Revealed {} note(s) to {}", notes.len(), output.display());
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

fn reveal_stealth(args: RevealArgs, json: bool) -> anyhow::Result<()> {
    if args.all || args.index.is_some_and(|index| index != 1) {
        bail!("stealth mode stores one note; --all and indexes other than 1 are not available");
    }
    let mut password = resolve_password(&args.password, false)?;
    if password.is_none() {
        password = Some(Zeroizing::new(rpassword::prompt_password("Password: ")?));
    }
    let password = password.ok_or(InvitextError::PasswordRequired)?;
    let data = read_stealth_png(&args.file)
        .with_context(|| format!("could not read {}", args.file.display()))?;
    let note = reveal_png(&data, &password)?;

    if json {
        #[derive(Serialize)]
        struct JsonNote<'a> {
            index: usize,
            mode: &'static str,
            label: &'a str,
            text: &'a str,
            created_at: String,
            encrypted: bool,
            compressed: bool,
        }
        print_json(&[JsonNote {
            index: 1,
            mode: "stealth",
            label: &note.label,
            text: &note.text,
            created_at: format_time(note.created_at),
            encrypted: true,
            compressed: note.compressed,
        }])?;
        return Ok(());
    }

    if let Some(output) = args.output {
        if paths_refer_to_same_file(&args.file, &output) {
            bail!("refusing to overwrite the carrier with revealed text");
        }
        write_atomic(&output, note.text.as_bytes(), args.force)
            .with_context(|| format!("could not write {}", output.display()))?;
        eprintln!("Revealed one stealth note to {}", output.display());
    } else {
        print!("{}", note.text);
        if !note.text.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

fn list(file: PathBuf, json: bool) -> anyhow::Result<()> {
    let total_size = file_len(&file)?;
    let mut input =
        File::open(&file).with_context(|| format!("could not read {}", file.display()))?;
    let result = scan_reader(&mut input, total_size, true)?;
    if json {
        print_json(&result)?;
        return Ok(());
    }

    println!("{} note(s) in {}", result.notes.len(), file.display());
    for note in &result.notes {
        println!(
            "  #{:<3} {:<10} {:<10} {} · {}",
            note.index,
            if note.encrypted { "encrypted" } else { "plain" },
            if note.intact { "intact" } else { "modified" },
            format_time(note.created_at),
            human_size(note.stored_bytes)
        );
    }
    Ok(())
}

fn verify(args: VerifyArgs, json: bool) -> anyhow::Result<()> {
    ensure_distinct_password_sources(&args.password)?;
    if args.mode == StorageMode::Stealth {
        return verify_stealth(args, json);
    }
    let total_size = file_len(&args.file)?;
    let mut file = File::open(&args.file)
        .with_context(|| format!("could not read {}", args.file.display()))?;
    let result = scan_reader(&mut file, total_size, true)?;
    if result.notes.iter().any(|note| !note.intact) {
        return Err(InvitextError::CarrierModified.into());
    }

    let mut deep_verified = None;
    if args.deep {
        let index = args.index.unwrap_or(result.notes.len());
        let encrypted = result
            .notes
            .get(index.saturating_sub(1))
            .ok_or(InvitextError::InvalidIndex {
                requested: index,
                available: result.notes.len(),
            })?
            .encrypted;
        let mut password = resolve_password(&args.password, false)?;
        if encrypted && password.is_none() {
            password = Some(Zeroizing::new(rpassword::prompt_password("Password: ")?));
        }
        reveal_note_reader(
            &mut file,
            total_size,
            index,
            password.as_deref().map(|value| value.as_str()),
        )?;
        deep_verified = Some(index);
    }

    if json {
        #[derive(Serialize)]
        struct Verification {
            valid: bool,
            notes: usize,
            deep_verified: Option<usize>,
        }
        print_json(&Verification {
            valid: true,
            notes: result.notes.len(),
            deep_verified,
        })?;
    } else {
        println!("OK · {} structurally valid note(s)", result.notes.len());
        if let Some(index) = deep_verified {
            println!("OK · note #{index} decrypted and decoded successfully");
        }
    }
    Ok(())
}

fn verify_stealth(args: VerifyArgs, json: bool) -> anyhow::Result<()> {
    if args.index.is_some_and(|index| index != 1) {
        bail!("stealth mode stores one note; only index 1 is valid");
    }
    let mut password = resolve_password(&args.password, false)?;
    if password.is_none() {
        password = Some(Zeroizing::new(rpassword::prompt_password("Password: ")?));
    }
    let password = password.ok_or(InvitextError::PasswordRequired)?;
    let data = read_stealth_png(&args.file)
        .with_context(|| format!("could not read {}", args.file.display()))?;
    reveal_png(&data, &password)?;
    if json {
        #[derive(Serialize)]
        struct Verification {
            valid: bool,
            mode: &'static str,
            notes: usize,
            deep_verified: usize,
        }
        print_json(&Verification {
            valid: true,
            mode: "stealth",
            notes: 1,
            deep_verified: 1,
        })?;
    } else {
        println!("OK · stealth envelope decrypted and authenticated");
        println!("OK · embedded note decoded successfully");
    }
    Ok(())
}

fn strip(args: StripArgs, json: bool) -> anyhow::Result<()> {
    let total_size = file_len(&args.file)?;
    let result = {
        let mut file = File::open(&args.file)
            .with_context(|| format!("could not read {}", args.file.display()))?;
        scan_reader(&mut file, total_size, true)?
    };
    if result.notes.iter().any(|note| !note.intact) {
        return Err(InvitextError::CarrierModified.into());
    }
    let keep_length = if args.latest {
        result.notes.last().unwrap().carrier_bytes
    } else {
        result.original_size
    };
    let output = if args.in_place {
        args.file.clone()
    } else {
        args.output
            .unwrap_or_else(|| default_clean_path(&args.file))
    };
    if !args.in_place && paths_refer_to_same_file(&args.file, &output) {
        bail!("output resolves to the input; use --in-place explicitly");
    }
    copy_prefix_atomic(
        &args.file,
        &output,
        keep_length,
        args.in_place || args.force,
    )
    .with_context(|| format!("could not write {}", output.display()))?;
    let remaining = if args.latest {
        result.notes.len() - 1
    } else {
        0
    };
    let action = ActionResult {
        status: "stripped",
        input: args.file.display().to_string(),
        output: Some(output.display().to_string()),
        notes: remaining,
        bytes: keep_length,
    };
    if json {
        print_json(&action)?;
    } else {
        println!(
            "Removed {} note(s) → {}",
            result.notes.len() - remaining,
            output.display()
        );
        println!("{remaining} note(s) remain · {}", human_size(keep_length));
    }
    Ok(())
}

fn inspect(file: PathBuf, json: bool) -> anyhow::Result<()> {
    let total_size = file_len(&file)?;
    let mut input =
        File::open(&file).with_context(|| format!("could not read {}", file.display()))?;
    let mut header = vec![0u8; usize::try_from(total_size.min(8192)).unwrap_or(8192)];
    input.read_exact(&mut header)?;
    let kind = infer::get(&header).map(|kind| (kind.mime_type(), kind.extension()));
    let notes = match scan_reader(&mut input, total_size, false) {
        Ok(result) => Some(result),
        Err(InvitextError::NoNote) => None,
        Err(error) => return Err(error.into()),
    };
    let extension = file
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let compatibility = compatibility(extension);
    let (stealth, stealth_unavailable) = if kind.is_some_and(|value| value.0 == "image/png") {
        match analyze_png(&read_stealth_png(&file)?) {
            Ok(analysis) => (Some(analysis), None),
            Err(InvitextError::UnsupportedStealthCarrier(reason)) => (None, Some(reason)),
            Err(error) => return Err(error.into()),
        }
    } else {
        (None, None)
    };

    if json {
        #[derive(Serialize)]
        struct Inspection<'a> {
            file: String,
            bytes: u64,
            mime: Option<&'a str>,
            detected_extension: Option<&'a str>,
            compatibility: &'a str,
            notes: usize,
            stealth: Option<StealthAnalysis>,
            stealth_unavailable: Option<&'a str>,
        }
        print_json(&Inspection {
            file: file.display().to_string(),
            bytes: total_size,
            mime: kind.map(|value| value.0),
            detected_extension: kind.map(|value| value.1),
            compatibility,
            notes: notes.as_ref().map_or(0, |value| value.notes.len()),
            stealth,
            stealth_unavailable,
        })?;
        return Ok(());
    }

    println!("File          {}", file.display());
    println!("Size          {}", human_size(total_size));
    println!("Type          {}", kind.map_or("unknown", |value| value.0));
    println!("Compatibility {compatibility}");
    println!(
        "Notes         {}",
        notes.as_ref().map_or(0, |value| value.notes.len())
    );
    if let Some(stealth) = stealth {
        println!("Stealth       supported ({})", stealth.format);
        println!(
            "Capacity      about {} encrypted payload",
            human_size(stealth.payload_capacity_bytes as u64)
        );
        println!(
            "Change limit  {:.3}% of eligible color channels",
            stealth.maximum_change_percent
        );
    } else if let Some(reason) = stealth_unavailable {
        println!("Stealth       unavailable ({reason})");
    }
    Ok(())
}

fn read_message(message: Option<String>, file: Option<PathBuf>) -> anyhow::Result<String> {
    if let Some(message) = message {
        return Ok(message);
    }
    if let Some(file) = file {
        return fs::read_to_string(&file)
            .with_context(|| format!("could not read UTF-8 text from {}", file.display()));
    }

    if io::stdin().is_terminal() {
        eprint!("Text to hide: ");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_owned());
    }
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(input)
}

fn read_stealth_png(path: &Path) -> invitext::Result<Vec<u8>> {
    read_file_limited(path, MAX_STEALTH_PNG_BYTES, "PNG input")
}

fn ensure_distinct_password_sources(args: &PasswordArgs) -> anyhow::Result<()> {
    let count = usize::from(args.password.is_some())
        + usize::from(args.password_file.is_some())
        + usize::from(args.password_env.is_some());
    if count > 1 {
        bail!("choose only one password source");
    }
    Ok(())
}

fn resolve_password(
    args: &PasswordArgs,
    required: bool,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    let value = if let Some(password) = &args.password {
        Some(password.clone())
    } else if let Some(path) = &args.password_file {
        let contents = Zeroizing::new(
            fs::read_to_string(path)
                .with_context(|| format!("could not read password file {}", path.display()))?,
        );
        Some(contents.lines().next().unwrap_or_default().to_owned())
    } else if let Some(name) = &args.password_env {
        Some(env::var(name).with_context(|| format!("environment variable {name} is not set"))?)
    } else {
        None
    };
    if required && value.is_none() {
        bail!("a password is required");
    }
    Ok(value.map(Zeroizing::new))
}

fn prompt_new_password() -> anyhow::Result<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        bail!(
            "cannot prompt for a password without a terminal; use --password-file or --password-env"
        );
    }
    let first = Zeroizing::new(rpassword::prompt_password("New password: ")?);
    let second = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
    if *first != *second {
        bail!("passwords do not match");
    }
    Ok(first)
}

fn compatibility(extension: &str) -> &'static str {
    match extension.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "tif" | "tiff" | "pdf" | "zip"
        | "rar" | "7z" | "tar" | "gz" | "mp3" | "wav" | "flac" | "mp4" | "m4v" | "mov" | "avi"
        | "mkv" | "docx" | "xlsx" | "pptx" => "high (trailing data is commonly tolerated)",
        "exe" | "dll" | "dylib" | "so" | "app" | "apk" | "jar" => {
            "caution (signatures or checksums may break)"
        }
        _ => "unknown (test the carrier in its normal application)",
    }
}

fn format_time(timestamp: i64) -> String {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        .unwrap_or_else(|| timestamp.to_string())
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn encryption_status(options: &EmbedOptions) -> &'static str {
    if options.encryption.is_some() {
        "encrypted"
    } else {
        "not encrypted"
    }
}

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}
