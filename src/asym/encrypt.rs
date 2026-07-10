use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;

use crate::asym::cli::AssymEncryptArgs;
use crate::asym::{envelope, keys, pqc, sign};
use crate::error::{AppError, Result};
use crate::format::opaque;
use crate::sym::crypto::{CryptoConfig, DEFAULT_CHUNK_SIZE};
use crate::sym::pathing;

pub struct EncryptOutcome {
    pub output: PathBuf,
    pub keys_dir: PathBuf,
    pub generated_recipient_public: Option<PathBuf>,
    pub generated_recipient_secret: Option<PathBuf>,
    pub generated_signer_public: Option<PathBuf>,
    pub generated_signer_secret: Option<PathBuf>,
    pub detached_signature: Option<PathBuf>,
}

pub fn encrypt_file<F>(
    args: &AssymEncryptArgs,
    config: &CryptoConfig,
    on_progress: F,
) -> Result<EncryptOutcome>
where
    F: FnMut(u64),
{
    pqc::ensure_enabled()?;
    let output = args
        .output
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_encryption_output_path(&args.input))?;
    if output.exists() && !args.force {
        return Err(AppError::OutputExists(output));
    }

    let keys_dir = args
        .keys_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_default_keys_dir_for_plain_input(&args.input))?;

    let mut generated_recipient_public = None;
    let mut generated_recipient_secret = None;
    let recipient = if let Some(path) = &args.recipient_public {
        keys::read_recipient_public_key(path)?
    } else {
        let generated = keys::generate_recipient_key_files(&keys_dir, args.force)?;
        generated_recipient_public = Some(generated.public_path);
        generated_recipient_secret = Some(generated.secret_path);
        generated.public
    };

    let input_file = File::open(&args.input)?;
    let plaintext_len = input_file.metadata()?.len();
    let mut reader = BufReader::with_capacity(DEFAULT_CHUNK_SIZE.max(64 * 1024), input_file);

    let chunk_size = config.chunk_size.max(1);
    let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| AppError::InputTooLarge)?;
    if chunk_count(plaintext_len, chunk_size_u64)? == 0 {
        return Err(AppError::InputTooLarge);
    }

    let mut generated_signer_public = None;
    let mut generated_signer_secret = None;
    let signer = if let Some(path) = &args.sign_key {
        Some(keys::read_signing_secret_key(path)?)
    } else if args.sign {
        let generated = keys::generate_signing_key_files(&keys_dir, args.force)?;
        generated_signer_public = Some(generated.public_path);
        generated_signer_secret = Some(generated.secret_path);
        Some(generated.secret)
    } else {
        None
    };
    let detached_signature = if signer.is_some() {
        Some(envelope::detached_signature_path(&output)?)
    } else {
        None
    };
    if let Some(path) = &detached_signature {
        if path.exists() && !args.force {
            return Err(AppError::OutputExists(path.clone()));
        }
    }

    let output_dir = envelope::output_parent_dir(&output);
    fs::create_dir_all(&output_dir)?;
    let mut temp_output = NamedTempFile::new_in(&output_dir)?;
    {
        let writer_capacity = chunk_size
            .checked_add(opaque::TAG_LEN)
            .ok_or(AppError::InputTooLarge)?
            .max(64 * 1024);
        let mut writer = BufWriter::with_capacity(writer_capacity, temp_output.as_file_mut());
        opaque::encrypt_pqc_stream(
            &mut reader,
            &mut writer,
            plaintext_len,
            &recipient,
            config,
            on_progress,
        )?;
        writer.flush()?;
    }
    temp_output.as_file_mut().sync_all()?;
    let prepared_signature = if let Some(signer) = signer.as_ref() {
        let ciphertext_len = temp_output.as_file().metadata()?.len();
        Some(sign::create_detached_signature_from_reader(
            temp_output.as_file_mut(),
            ciphertext_len,
            signer,
        )?)
    } else {
        None
    };
    envelope::persist_temp_file(temp_output, &output, args.force)?;
    if let (Some(signature), Some(detached_signature)) =
        (prepared_signature.as_ref(), detached_signature.as_ref())
    {
        sign::write_detached_signature(signature, detached_signature, args.force)?;
    }

    Ok(EncryptOutcome {
        output,
        keys_dir,
        generated_recipient_public,
        generated_recipient_secret,
        generated_signer_public,
        generated_signer_secret,
        detached_signature,
    })
}

fn chunk_count(plaintext_len: u64, chunk_size: u64) -> Result<u64> {
    if chunk_size == 0 {
        return Err(AppError::InvalidChunkSize);
    }
    if plaintext_len == 0 {
        return Ok(1);
    }
    Ok(plaintext_len / chunk_size + u64::from(plaintext_len % chunk_size != 0))
}
