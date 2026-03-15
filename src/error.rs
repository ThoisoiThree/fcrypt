use std::io;
use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("The input path does not have a valid file name: {0}")]
    MissingFileName(PathBuf),

    #[error("Passwords do not match.")]
    PasswordMismatch,

    #[error("Password cannot be empty.")]
    EmptyPassword,

    #[error("Output file already exists: {0}")]
    OutputExists(PathBuf),

    #[error("Output file already exists: {0}. Use --force in non-interactive mode.")]
    OutputExistsNonInteractive(PathBuf),

    #[error("Operation cancelled. The existing output file was not overwritten.")]
    UserAborted,

    #[error("Invalid encryption configuration: {0}")]
    CryptoConfig(String),

    #[error("Chunk size must be greater than zero.")]
    InvalidChunkSize,

    #[error("File is too large for this format.")]
    InputTooLarge,

    #[error("Input file changed while being processed. Please retry.")]
    InputChangedDuringProcessing,

    #[error("Encryption failed.")]
    EncryptionFailed,

    #[error("Key derivation failed.")]
    KeyDerivationFailed,

    #[error("Decryption failed: wrong password or file is corrupted.")]
    DecryptionFailed,
}
