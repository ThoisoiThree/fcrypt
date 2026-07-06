use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum AssymCommand {
    /// Encrypt a file into the asymmetric .fe format.
    #[command(visible_alias = "encode")]
    Encrypt(AssymEncryptArgs),
    /// Decrypt an asymmetric .fe file.
    #[command(visible_alias = "decode")]
    Decrypt(AssymDecryptArgs),
    /// Sign an existing .fe file.
    Sign(AssymSignArgs),
}

#[derive(Debug, Args)]
pub struct AssymEncryptArgs {
    /// Path to the input file to encrypt.
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,
    /// Destination .fe file. Defaults to <INPUT>.fe.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Recipient public key bundle.
    #[arg(long = "recipient-public", short = 'r', value_name = "FILE")]
    pub recipient_public: Option<PathBuf>,
    /// Directory for generated or discovered keys.
    #[arg(long = "keys-dir", short = 'k', value_name = "DIR")]
    pub keys_dir: Option<PathBuf>,
    /// Embed an ML-DSA-87 signature in the result.
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
    /// Path to the .fe input file.
    #[arg(value_name = "INPUT.fe")]
    pub input: PathBuf,
    /// Destination plaintext file. Defaults to <INPUT.fe without .fe>.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Recipient secret key bundle.
    #[arg(long, short = 'i', value_name = "FILE")]
    pub identity: Option<PathBuf>,
    /// Directory for recipient secret key auto-discovery.
    #[arg(long = "keys-dir", short = 'k', value_name = "DIR")]
    pub keys_dir: Option<PathBuf>,
    /// Signing public key used to verify an embedded or detached signature.
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
    /// Path to the .fe input file.
    #[arg(value_name = "INPUT.fe")]
    pub input: PathBuf,
    /// Detached signature output file. With --embed, writes an embedded .fe file.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Signing secret key bundle. Generated if omitted.
    #[arg(long = "sign-key", short = 'S', value_name = "FILE")]
    pub sign_key: Option<PathBuf>,
    /// Directory for generated signing keys.
    #[arg(long = "keys-dir", short = 'k', value_name = "DIR")]
    pub keys_dir: Option<PathBuf>,
    /// Embed the signature in the .fe envelope instead of writing a detached .sig.
    #[arg(long, short = 'e')]
    pub embed: bool,
    /// Overwrite the destination file without asking.
    #[arg(long, short = 'f')]
    pub force: bool,
}
