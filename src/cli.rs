use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::asym::cli::AssymCommand;
use crate::error::{AppError, Result};

#[derive(Debug, Parser)]
#[command(
    name = "fcrypt",
    version,
    about = "Encrypt and decrypt files with password-based and asymmetric PQC encryption.",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt a file.
    #[command(visible_alias = "encode")]
    Encrypt(LegacyEncryptArgs),
    /// Decrypt a file.
    #[command(visible_alias = "decode")]
    Decrypt(LegacyDecryptArgs),
    /// Use asymmetric post-quantum .fe file encryption.
    #[command(name = "asym", visible_alias = "assym")]
    Assym {
        #[command(subcommand)]
        command: AssymCommand,
    },
    /// Generate random passwords or passphrases.
    Keygen(KeygenArgs),
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Password length. Preserves the classic `fcrypt keygen <N>` form.
    #[arg(value_name = "N")]
    pub length: Option<usize>,
    #[command(subcommand)]
    pub command: Option<KeygenCommand>,
}

#[derive(Debug, Subcommand)]
pub enum KeygenCommand {
    /// Generate a cryptographically random phrase from the embedded EFF large wordlist.
    Phrase {
        /// Number of words in the phrase.
        #[arg(value_name = "N")]
        word_count: usize,
        /// Word separator. Defaults to '-'. `-sep` is accepted as an alias for --sep.
        #[arg(long = "sep", short = 's', value_name = "SEP", default_value = "-")]
        separator: String,
    },
}

#[derive(Debug, Args)]
pub struct LegacyEncryptArgs {
    /// Path to the input file to encrypt.
    #[arg(value_name = "INPUT", required_unless_present = "input_flag")]
    pub input: Option<PathBuf>,
    /// Path to the input file to encrypt.
    #[arg(
        long = "input",
        short = 'i',
        value_name = "FILE",
        conflicts_with = "input"
    )]
    pub input_flag: Option<PathBuf>,
    /// Use high-resource Argon2id and AES-GCM-then-Serpent-EAX cascade encryption.
    #[arg(long = "paranoic", alias = "paranoid", short = 'p')]
    pub paranoic: bool,
    /// Overwrite the destination file without asking.
    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct LegacyDecryptArgs {
    /// Path to the input file to decrypt.
    #[arg(value_name = "INPUT", required_unless_present = "input_flag")]
    pub input: Option<PathBuf>,
    /// Path to the input file to decrypt.
    #[arg(
        long = "input",
        short = 'i',
        value_name = "FILE",
        conflicts_with = "input"
    )]
    pub input_flag: Option<PathBuf>,
    /// Overwrite the destination file without asking.
    #[arg(long, short = 'f')]
    pub force: bool,
}

impl LegacyEncryptArgs {
    pub fn input_path(&self) -> Result<PathBuf> {
        resolve_legacy_input(self.input.as_ref(), self.input_flag.as_ref())
    }
}

impl LegacyDecryptArgs {
    pub fn input_path(&self) -> Result<PathBuf> {
        resolve_legacy_input(self.input.as_ref(), self.input_flag.as_ref())
    }
}

fn resolve_legacy_input(
    positional: Option<&PathBuf>,
    flagged: Option<&PathBuf>,
) -> Result<PathBuf> {
    match (positional, flagged) {
        (Some(input), None) | (None, Some(input)) => Ok(input.clone()),
        _ => Err(AppError::InvalidArgument(
            "exactly one input path must be provided".to_string(),
        )),
    }
}
