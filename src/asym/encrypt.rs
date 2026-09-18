use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;

use crate::asym::cli::AssymEncryptArgs;
use crate::asym::{envelope, keys, pqc, sign};
use crate::error::{AppError, Result};
use crate::format::opaque;
use crate::sym::crypto::CryptoConfig;
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
    encrypt_file_impl(args, None, config, on_progress)
}

/// Create an identity and publish its keys together with the encrypted file.
/// Key overwrite permission is independent of ciphertext/signature permission.
pub fn encrypt_file_with_new_identity<F>(
    args: &AssymEncryptArgs,
    name: &str,
    overwrite_keys: bool,
    config: &CryptoConfig,
    on_progress: F,
) -> Result<EncryptOutcome>
where
    F: FnMut(u64),
{
    if args.recipient_public.is_some() {
        return Err(AppError::InvalidArgument(
            "a new identity cannot be combined with an existing recipient".to_string(),
        ));
    }
    encrypt_file_impl(args, Some((name, overwrite_keys)), config, on_progress)
}

fn encrypt_file_impl<F>(
    args: &AssymEncryptArgs,
    new_identity: Option<(&str, bool)>,
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

    // Open the input before generating keys. Keys remain staged until every
    // output, including the detached signature, is ready to commit.
    let input_file = File::open(&args.input)?;
    let plaintext_len = input_file.metadata()?.len();
    // opaque owns a zeroizing plaintext chunk buffer. Reading directly from
    // the file avoids retaining another plaintext copy in BufReader.
    let mut reader = input_file;
    let mut staged_files = Vec::new();
    let mut generated_recipient_public = None;
    let mut generated_recipient_secret = None;
    let mut generated_signer_public = None;
    let mut generated_signer_secret = None;
    let mut identity_signer = None;
    let recipient = if let Some((name, overwrite_keys)) = new_identity {
        let prepared = keys::prepare_named_key_pair_files(&keys_dir, name, None, overwrite_keys)?;
        let use_identity_signer =
            args.sign || args.sign_key.as_ref() == Some(&prepared.paths.signing_secret_path);
        generated_recipient_public = Some(prepared.paths.recipient_public_path);
        generated_recipient_secret = Some(prepared.paths.recipient_secret_path);
        generated_signer_public = Some(prepared.paths.signing_public_path);
        generated_signer_secret = Some(prepared.paths.signing_secret_path);
        if use_identity_signer {
            identity_signer = Some(prepared.signer);
        }
        staged_files.extend(prepared.staged_files);
        prepared.recipient
    } else if let Some(path) = &args.recipient_public {
        keys::read_recipient_public_key(path)?
    } else {
        let (generated, files) = keys::prepare_recipient_key_files(&keys_dir)?;
        staged_files.extend(files);
        generated_recipient_public = Some(generated.public_path);
        generated_recipient_secret = Some(generated.secret_path);
        generated.public
    };

    let chunk_size = config.chunk_size.max(1);
    let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| AppError::InputTooLarge)?;
    if chunk_count(plaintext_len, chunk_size_u64)? == 0 {
        return Err(AppError::InputTooLarge);
    }

    let signer = if let Some(signer) = identity_signer {
        Some(signer)
    } else if let Some(path) = &args.sign_key {
        Some(keys::read_signing_secret_key(path)?)
    } else if args.sign {
        let (generated, files) = keys::prepare_signing_key_files(&keys_dir)?;
        staged_files.extend(files);
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
        opaque::encrypt_pqc_stream_with_signer(
            &mut reader,
            &mut writer,
            plaintext_len,
            &recipient,
            signer.as_ref().map(|signer| signer.key_id.as_str()),
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
    staged_files.push(envelope::StagedFile::new(temp_output, &output));
    if let (Some(signature), Some(detached_signature)) =
        (prepared_signature.as_ref(), detached_signature.as_ref())
    {
        staged_files.push(sign::stage_detached_signature(
            signature,
            detached_signature,
        )?);
    }
    envelope::persist_staged_files(staged_files, args.force)?;

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
