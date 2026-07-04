use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "fcrypt",
    version,
    about = "Encrypt and decrypt files with password-based encryption, and generate random passwords.",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt a file.
    Encrypt {
        /// Path to the input file to encrypt.
        #[arg(long, short = 'i', value_name = "FILE")]
        input: PathBuf,
        /// Use high-resource Argon2id and AES-GCM-then-Serpent-EAX cascade encryption.
        #[arg(long = "paranoic", alias = "paranoid", short = 'p')]
        paranoic: bool,
        /// Overwrite the destination file without asking.
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Decrypt a file.
    Decrypt {
        /// Path to the input file to decrypt.
        #[arg(long, short = 'i', value_name = "FILE")]
        input: PathBuf,
        /// Overwrite the destination file without asking.
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Generate a random password.
    Keygen {
        /// Password length.
        #[arg(value_name = "N")]
        length: usize,
    },
}
