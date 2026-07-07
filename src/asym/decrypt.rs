use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;

use crate::asym::cli::AssymDecryptArgs;
use crate::asym::{envelope, keys, pqc, sign};
use crate::error::{AppError, Result};
use crate::format::opaque;
use crate::sym::crypto::DEFAULT_CHUNK_SIZE;
use crate::sym::pathing;

pub fn decrypt_file<F>(args: &AssymDecryptArgs, on_progress: F) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    pqc::ensure_enabled()?;
    verify_signature_policy(args)?;

    let output = args
        .output
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_decryption_output_path(&args.input))?;
    if output.exists() && !args.force {
        return Err(AppError::OutputExists(output));
    }

    let identities = resolve_identities(args)?;
    let input_file = File::open(&args.input)?;
    let encrypted_len = input_file.metadata()?.len();

    let output_dir = envelope::output_parent_dir(&output);
    fs::create_dir_all(&output_dir)?;
    let mut temp_output = NamedTempFile::new_in(&output_dir)?;
    {
        let mut reader = BufReader::with_capacity(DEFAULT_CHUNK_SIZE.max(64 * 1024), input_file);
        let mut writer =
            BufWriter::with_capacity(DEFAULT_CHUNK_SIZE.max(64 * 1024), temp_output.as_file_mut());
        opaque::decrypt_pqc_stream(
            &mut reader,
            &mut writer,
            encrypted_len,
            &identities,
            on_progress,
        )?;
        writer.flush()?;
    }

    temp_output.as_file_mut().sync_all()?;
    envelope::persist_temp_file(temp_output, &output, args.force)?;
    Ok(output)
}

fn resolve_identities(args: &AssymDecryptArgs) -> Result<Vec<keys::RecipientSecretKeyBundle>> {
    if let Some(identity) = &args.identity {
        return Ok(vec![keys::read_recipient_secret_key(identity)?]);
    }

    let keys_dir = args
        .keys_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_default_keys_dir_for_encrypted_input(&args.input))?;
    keys::read_recipient_secret_keys(&keys_dir)
}

fn verify_signature_policy(args: &AssymDecryptArgs) -> Result<()> {
    if args.verify.is_none() && !args.require_signature {
        return Ok(());
    }
    let verify_key = args
        .verify
        .as_ref()
        .ok_or(AppError::SignatureVerificationKeyRequired)?;
    sign::verify_detached_signature(&args.input, verify_key)
}
