use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::asym::cli::AssymCommand;
use crate::error::{AppError, Result};

#[derive(Debug, Parser)]
#[command(
    name = "fcrypt",
    version,
    about = "Encrypt files with passwords or post-quantum recipient keys.",
    long_about = None,
    after_help = "Start here:\n  fcrypt encrypt report.pdf\n  fcrypt identity create alice\n  fcrypt encrypt report.pdf --recipient ./alice_recipient_default.pub\n\nFull reference:\n  fcrypt help-all"
)]
pub struct Cli {
    /// Suppress success messages and progress output.
    #[arg(long, short = 'q', global = true, conflicts_with = "json")]
    pub quiet: bool,
    /// Print a single machine-readable JSON result to stdout.
    #[arg(long, global = true, conflicts_with = "quiet")]
    pub json: bool,
    /// Disable progress indicators while keeping normal output.
    #[arg(long, global = true)]
    pub no_progress: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt a file with a password or a recipient public key.
    #[command(visible_alias = "encode")]
    Encrypt(EncryptArgs),
    /// Decrypt a password or recipient-key encrypted file.
    #[command(visible_alias = "decode")]
    Decrypt(DecryptArgs),
    /// Create a detached ML-DSA-87 signature.
    Sign(SignArgs),
    /// Verify a detached ML-DSA-87 signature without decrypting.
    Verify(VerifyArgs),
    /// Create, list, and inspect recipient and signing identities.
    Identity(IdentityArgs),
    /// Generate a random password.
    Password(PasswordArgs),
    /// Generate a random EFF Diceware-style phrase.
    Phrase(PhraseArgs),
    /// Use the legacy asymmetric command group.
    #[command(name = "asym", alias = "assym")]
    Asym {
        #[command(subcommand)]
        command: AssymCommand,
    },
    /// Legacy password, phrase, and key-pair generation commands.
    #[command(hide = true)]
    Keygen(KeygenArgs),
    /// Print the extended command reference.
    HelpAll,
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    /// Input file to encrypt.
    #[arg(value_name = "INPUT", required_unless_present = "input_flag")]
    pub input: Option<PathBuf>,
    /// Input file to encrypt.
    #[arg(
        long = "input",
        short = 'i',
        value_name = "FILE",
        conflicts_with = "input"
    )]
    pub input_flag: Option<PathBuf>,
    /// Destination file. Defaults to <INPUT>.bin.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Encrypt for this recipient public key instead of using a password.
    #[arg(
        long = "recipient",
        short = 'r',
        visible_alias = "recipient-public",
        value_name = "FILE",
        conflicts_with_all = ["new_identity", "password_file"]
    )]
    pub recipient: Option<PathBuf>,
    /// Create a named recipient and signing identity, then encrypt for it.
    #[arg(
        long = "new-identity",
        value_name = "NAME",
        conflicts_with_all = ["recipient", "password_file"]
    )]
    pub new_identity: Option<String>,
    /// Directory for a newly created identity.
    #[arg(
        long = "keys-dir",
        short = 'k',
        value_name = "DIR",
        conflicts_with = "password_file"
    )]
    pub keys_dir: Option<PathBuf>,
    /// Create a detached signature. Requires --sign-key or --new-identity.
    #[arg(long, short = 's', conflicts_with = "password_file")]
    pub sign: bool,
    /// Signing secret key. Implies asymmetric encryption.
    #[arg(
        long = "sign-key",
        short = 'S',
        value_name = "FILE",
        conflicts_with = "password_file"
    )]
    pub sign_key: Option<PathBuf>,
    /// Read the password from a file instead of prompting.
    #[arg(long = "password-file", value_name = "FILE", conflicts_with_all = ["recipient", "new_identity", "keys_dir", "sign", "sign_key"])]
    pub password_file: Option<PathBuf>,
    /// Overwrite the destination without asking.
    #[arg(long, short = 'f')]
    pub force: bool,
}

impl EncryptArgs {
    pub fn input_path(&self) -> Result<PathBuf> {
        resolve_input(self.input.as_ref(), self.input_flag.as_ref())
    }

    pub fn uses_pqc(&self) -> bool {
        self.recipient.is_some()
            || self.new_identity.is_some()
            || self.keys_dir.is_some()
            || self.sign
            || self.sign_key.is_some()
    }
}

#[derive(Debug, Args)]
pub struct DecryptArgs {
    /// Input file to decrypt.
    #[arg(value_name = "INPUT", required_unless_present = "input_flag")]
    pub input: Option<PathBuf>,
    /// Input file to decrypt. Short -i is reserved for --identity.
    #[arg(long = "input", value_name = "FILE", conflicts_with = "input")]
    pub input_flag: Option<PathBuf>,
    /// Destination file. Defaults to INPUT without .bin.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Recipient secret key bundle for asymmetric decryption.
    #[arg(
        long,
        short = 'i',
        value_name = "FILE",
        conflicts_with = "password_file"
    )]
    pub identity: Option<PathBuf>,
    /// Directory for recipient secret key auto-discovery.
    #[arg(
        long = "keys-dir",
        short = 'k',
        value_name = "DIR",
        conflicts_with = "password_file"
    )]
    pub keys_dir: Option<PathBuf>,
    /// Verify a detached signature with this public key before decrypting.
    #[arg(
        long,
        short = 'v',
        value_name = "FILE",
        conflicts_with = "password_file"
    )]
    pub verify: Option<PathBuf>,
    /// Legacy alias for requiring a signature. A verification key is still required.
    #[arg(long = "require-signature", short = 'R', hide = true)]
    pub require_signature: bool,
    /// Read the password from a file instead of prompting.
    #[arg(long = "password-file", value_name = "FILE", conflicts_with_all = ["identity", "keys_dir", "verify", "require_signature"])]
    pub password_file: Option<PathBuf>,
    /// Overwrite the destination without asking.
    #[arg(long, short = 'f')]
    pub force: bool,
}

impl DecryptArgs {
    pub fn input_path(&self) -> Result<PathBuf> {
        resolve_input(self.input.as_ref(), self.input_flag.as_ref())
    }

    pub fn uses_pqc(&self) -> bool {
        self.identity.is_some()
            || self.keys_dir.is_some()
            || self.verify.is_some()
            || self.require_signature
    }
}

#[derive(Debug, Args)]
pub struct SignArgs {
    /// Ciphertext file to sign.
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,
    /// Signing secret key bundle.
    #[arg(long, short = 'k', value_name = "FILE")]
    pub key: PathBuf,
    /// Detached signature path. Defaults to <INPUT>.sig.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Overwrite the destination without asking.
    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Ciphertext file whose detached signature will be verified.
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,
    /// Signing public key bundle.
    #[arg(long, short = 'k', value_name = "FILE")]
    pub key: PathBuf,
}

#[derive(Debug, Args)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub command: IdentityCommand,
}

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Create recipient and signing key pairs.
    Create {
        /// Identity name used as a file-name prefix.
        #[arg(value_name = "NAME")]
        name: String,
        /// Directory for generated keys. Defaults to the current directory.
        #[arg(
            long = "keys-dir",
            short = 'k',
            value_name = "DIR",
            default_value = "."
        )]
        keys_dir: PathBuf,
        /// Optional lifetime in days.
        #[arg(long = "lifetime-days", value_name = "DAYS")]
        lifetime_days: Option<u64>,
        /// Overwrite existing key files without asking.
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// List safe metadata for key files in a directory.
    List {
        #[arg(
            long = "keys-dir",
            short = 'k',
            value_name = "DIR",
            default_value = "."
        )]
        keys_dir: PathBuf,
    },
    /// Inspect safe metadata for one key file.
    Inspect {
        #[arg(value_name = "KEY")]
        key: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct PasswordArgs {
    #[command(subcommand)]
    pub command: PasswordCommand,
}

#[derive(Debug, Subcommand)]
pub enum PasswordCommand {
    /// Generate a random password.
    Generate {
        #[arg(long, short = 'l', value_name = "N")]
        length: usize,
    },
}

#[derive(Debug, Args)]
pub struct PhraseArgs {
    #[command(subcommand)]
    pub command: PhraseCommand,
}

#[derive(Debug, Subcommand)]
pub enum PhraseCommand {
    /// Generate a random phrase from the embedded EFF wordlist.
    Generate {
        #[arg(long, short = 'w', value_name = "N")]
        words: usize,
        #[arg(
            long = "separator",
            short = 's',
            value_name = "SEP",
            default_value = "-"
        )]
        separator: String,
    },
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
        #[arg(value_name = "N")]
        word_count: usize,
        #[arg(long = "sep", short = 's', value_name = "SEP", default_value = "-")]
        separator: String,
    },
    /// Generate recipient and signing public/secret key files.
    Pair {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(value_name = "LIFETIME_DAYS")]
        lifetime_days: Option<u64>,
    },
}

fn resolve_input(positional: Option<&PathBuf>, flagged: Option<&PathBuf>) -> Result<PathBuf> {
    match (positional, flagged) {
        (Some(input), None) | (None, Some(input)) => Ok(input.clone()),
        _ => Err(AppError::InvalidArgument(
            "exactly one input path must be provided".to_string(),
        )),
    }
}
