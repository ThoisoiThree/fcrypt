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

    #[error("Generated password length must be between 1 and {0} characters.")]
    InvalidGeneratedPasswordLength(usize),

    #[error("Generated phrase word count must be between 1 and {0} words.")]
    InvalidGeneratedPhraseWordCount(usize),

    #[error("Output file already exists: {0}")]
    OutputExists(PathBuf),

    #[error("Output file already exists: {0}. Use --force in non-interactive mode.")]
    OutputExistsNonInteractive(PathBuf),

    #[error("Operation cancelled. The existing output file was not overwritten.")]
    UserAborted,

    #[error("Invalid encryption configuration: {0}")]
    CryptoConfig(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

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

    #[error("This file should be decrypted with asymmetric mode.\nUse: fcrypt asym decrypt {0} -i <recipient_default.sec>")]
    SymmetricCommandUsedForFe(String),

    #[error(
        "This file could not be opened as an asymmetric opaque file.\nUse the symmetric command if this is a password-encrypted file:\n  fcrypt decrypt {0}"
    )]
    NotAsymmetricFile(String),

    #[error("Asymmetric PQC mode was not enabled in this build.\nRebuild with feature: pqc")]
    AsymmetricUnavailable,

    #[error("unsupported asymmetric file version: {0}")]
    UnsupportedFeVersion(u16),

    #[error("invalid asymmetric file: {0}")]
    InvalidAsymmetricFile(String),

    #[error("invalid asymmetric key file: {0}")]
    InvalidAsymmetricKeyFile(String),

    #[error("No matching recipient secret key found.\nUse: fcrypt asym decrypt <file.bin> -i <recipient_default.sec>")]
    NoMatchingIdentity,

    #[error("Multiple matching recipient secret keys found. Use -i <recipient_default.sec>.")]
    MultipleMatchingIdentities,

    #[error(
        "Too many recipient secret keys found ({found}); auto-discovery limit is {limit}. Use -i <recipient_default.sec> to select one key."
    )]
    TooManyRecipientIdentities { found: usize, limit: usize },

    #[error("decryption failed: authentication failed or wrong key")]
    AsymmetricAuthenticationFailed,

    #[error("signature required but not found")]
    SignatureRequired,

    #[error("signature required but no verification key was provided")]
    SignatureVerificationKeyRequired,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("PQC operation failed: {0}")]
    Pqc(String),

    #[error("serialization failed: {0}")]
    Serialization(String),
}
