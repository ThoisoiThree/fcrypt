use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum AssymCommand {
    /// Encrypt a file into the asymmetric opaque format.
    #[command(visible_alias = "encode")]
    Encrypt(AssymEncryptArgs),
    /// Decrypt an asymmetric opaque file.
    #[command(visible_alias = "decode")]
    Decrypt(AssymDecryptArgs),
    /// Create a detached signature for an encrypted file.
    Sign(AssymSignArgs),
}

#[derive(Debug, Args)]
pub struct AssymEncryptArgs {
    /// Path to the input file to encrypt.
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,
    /// Destination encrypted file. Defaults to <INPUT>.bin.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Recipient public key bundle.
    #[arg(long = "recipient-public", short = 'r', value_name = "FILE")]
    pub recipient_public: Option<PathBuf>,
    /// Directory for generated or discovered keys.
    #[arg(long = "keys-dir", short = 'k', value_name = "DIR")]
    pub keys_dir: Option<PathBuf>,
    /// Create a detached ML-DSA-87 signature next to the encrypted file.
    #[arg(long, short = 's')]
    pub sign: bool,
    /// Signing secret key. Implies --sign.
    #[arg(long = "sign-key", short = 'S', value_name = "FILE")]
    pub sign_key: Option<PathBuf>,
    /// Overwrite the destination file without asking.
    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct AssymDecryptArgs {
    /// Path to the encrypted input file.
    #[arg(value_name = "INPUT.bin")]
    pub input: PathBuf,
    /// Destination plaintext file. Defaults to <INPUT.bin without .bin>.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Recipient secret key bundle.
    #[arg(long, short = 'i', value_name = "FILE")]
    pub identity: Option<PathBuf>,
    /// Directory for recipient secret key auto-discovery.
    #[arg(long = "keys-dir", short = 'k', value_name = "DIR")]
    pub keys_dir: Option<PathBuf>,
    /// Signing public key used to verify a detached signature.
    #[arg(long, short = 'v', value_name = "FILE")]
    pub verify: Option<PathBuf>,
    /// Require a valid signature before decrypting.
    #[arg(long = "require-signature", short = 'R')]
    pub require_signature: bool,
    /// Overwrite the destination file without asking.
    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct AssymSignArgs {
    /// Path to the encrypted input file.
    #[arg(value_name = "INPUT.bin")]
    pub input: PathBuf,
    /// Detached signature output file.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Signing secret key bundle. Generated if omitted.
    #[arg(long = "sign-key", short = 'S', value_name = "FILE")]
    pub sign_key: Option<PathBuf>,
    /// Directory for generated signing keys.
    #[arg(long = "keys-dir", short = 'k', value_name = "DIR")]
    pub keys_dir: Option<PathBuf>,
    /// Unsupported for opaque files.
    #[arg(long, short = 'e')]
    pub embed: bool,
    /// Overwrite the destination file without asking.
    #[arg(long, short = 'f')]
    pub force: bool,
}
