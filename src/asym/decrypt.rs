use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
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
    Ok(decrypt_file_with_diagnostics(args, on_progress)?.output)
}

pub struct DecryptOutcome {
    pub output: PathBuf,
    pub skipped_identity_files: Vec<PathBuf>,
}

pub fn decrypt_file_with_diagnostics<F>(
    args: &AssymDecryptArgs,
    on_progress: F,
) -> Result<DecryptOutcome>
where
    F: FnMut(u64),
{
    pqc::ensure_enabled()?;

    let output = args
        .output
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_decryption_output_path(&args.input))?;
    if output.exists() && !args.force {
        return Err(AppError::OutputExists(output));
    }

    let mut input_file = File::open(&args.input)?;
    let encrypted_len = input_file.metadata()?.len();
    verify_signature_policy(args, &mut input_file, encrypted_len)?;
    input_file.seek(SeekFrom::Start(0))?;
    let (identities, skipped_identity_files) = resolve_identities(args)?;

    decrypt_open_file(
        input_file,
        encrypted_len,
        &identities,
        &output,
        args.force,
        on_progress,
    )?;
    Ok(DecryptOutcome {
        output,
        skipped_identity_files,
    })
}

fn decrypt_open_file<F>(
    input_file: File,
    encrypted_len: u64,
    identities: &[keys::RecipientSecretKeyBundle],
    output: &std::path::Path,
    force: bool,
    on_progress: F,
) -> Result<()>
where
    F: FnMut(u64),
{
    let output_dir = envelope::output_parent_dir(output);
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
            identities,
            on_progress,
        )?;
        writer.flush()?;
    }

    temp_output.as_file_mut().sync_all()?;
    envelope::persist_temp_file(temp_output, output, force)
}

fn resolve_identities(
    args: &AssymDecryptArgs,
) -> Result<(Vec<keys::RecipientSecretKeyBundle>, Vec<PathBuf>)> {
    if let Some(identity) = &args.identity {
        return Ok((vec![keys::read_recipient_secret_key(identity)?], Vec::new()));
    }

    let keys_dir = args
        .keys_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_default_keys_dir_for_encrypted_input(&args.input))?;
    let loaded = keys::read_recipient_secret_keys_with_diagnostics(&keys_dir)?;
    Ok((loaded.identities, loaded.skipped_paths))
}

fn verify_signature_policy(
    args: &AssymDecryptArgs,
    input_file: &mut File,
    encrypted_len: u64,
) -> Result<()> {
    if args.verify.is_none() && !args.require_signature {
        return Ok(());
    }
    let verify_key = args
        .verify
        .as_ref()
        .ok_or(AppError::SignatureVerificationKeyRequired)?;
    sign::verify_detached_signature(&args.input, verify_key, input_file, encrypted_len)
}

#[cfg(all(test, feature = "pqc", unix))]
mod tests {
    use super::*;
    use crate::asym::cli::AssymEncryptArgs;
    use crate::asym::{encrypt, keys};
    use crate::sym::crypto::CryptoConfig;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn verified_file_handle_is_decrypted_after_path_replacement() {
        let dir = tempdir().expect("tempdir must be created");
        let recipient_public = dir.path().join("recipient.pub");
        let recipient_secret = dir.path().join("recipient.sec");
        let signing_public = dir.path().join("signing.pub");
        let signing_secret = dir.path().join("signing.sec");
        let keys_dir = dir.path().join("keys");
        let generated = keys::generate_named_key_pair_files(&keys_dir, "alice", None, false)
            .expect("key pair must be generated");
        fs::rename(generated.recipient_public_path, &recipient_public)
            .expect("recipient public key must be moved");
        fs::rename(generated.recipient_secret_path, &recipient_secret)
            .expect("recipient secret key must be moved");
        fs::rename(generated.signing_public_path, &signing_public)
            .expect("signing public key must be moved");
        fs::rename(generated.signing_secret_path, &signing_secret)
            .expect("signing secret key must be moved");

        let signed_plaintext = dir.path().join("signed.txt");
        let replacement_plaintext = dir.path().join("replacement.txt");
        let encrypted = dir.path().join("signed.bin");
        let replacement = dir.path().join("replacement.bin");
        let output = dir.path().join("output.txt");
        fs::write(&signed_plaintext, b"signed plaintext").expect("plaintext must be written");
        fs::write(&replacement_plaintext, b"replacement plaintext")
            .expect("replacement must be written");

        let config = CryptoConfig { chunk_size: 64 };
        encrypt::encrypt_file(
            &AssymEncryptArgs {
                input: signed_plaintext,
                output: Some(encrypted.clone()),
                recipient_public: Some(recipient_public.clone()),
                keys_dir: None,
                sign: false,
                sign_key: Some(signing_secret),
                force: false,
            },
            &config,
            |_| {},
        )
        .expect("signed file must be encrypted");
        encrypt::encrypt_file(
            &AssymEncryptArgs {
                input: replacement_plaintext,
                output: Some(replacement.clone()),
                recipient_public: Some(recipient_public),
                keys_dir: None,
                sign: false,
                sign_key: None,
                force: false,
            },
            &config,
            |_| {},
        )
        .expect("replacement file must be encrypted");

        let args = AssymDecryptArgs {
            input: encrypted.clone(),
            output: Some(output.clone()),
            identity: Some(recipient_secret.clone()),
            keys_dir: None,
            verify: Some(signing_public),
            require_signature: true,
            force: false,
        };
        let mut verified_file = File::open(&encrypted).expect("ciphertext must open");
        let encrypted_len = verified_file
            .metadata()
            .expect("ciphertext metadata must read")
            .len();
        verify_signature_policy(&args, &mut verified_file, encrypted_len)
            .expect("original open file must verify");

        fs::rename(&replacement, &encrypted).expect("path must be replaced after verification");
        let identities = vec![keys::read_recipient_secret_key(&recipient_secret)
            .expect("recipient secret key must be readable")];
        decrypt_open_file(
            verified_file,
            encrypted_len,
            &identities,
            &output,
            false,
            |_| {},
        )
        .expect("the verified open file must decrypt");

        assert_eq!(
            fs::read(output).expect("output must read"),
            b"signed plaintext"
        );
    }
}
