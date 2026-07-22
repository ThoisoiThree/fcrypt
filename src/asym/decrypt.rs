use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Seek, SeekFrom, Write};
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
    pub recipient_key_expired: bool,
    pub signer_key_expired: bool,
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
    let verification_key = resolve_verification_key(args)?;
    let signer_key_expired = verification_key
        .as_ref()
        .is_some_and(keys::SigningPublicKeyBundle::is_expired);
    verify_signature_policy(
        args,
        verification_key.as_ref(),
        &mut input_file,
        encrypted_len,
    )?;
    input_file.seek(SeekFrom::Start(0))?;
    let (identities, skipped_identity_files) = resolve_identities(args)?;
    let recipient_key_expired = args.identity.is_some()
        && identities
            .first()
            .is_some_and(keys::RecipientSecretKeyBundle::is_expired);

    decrypt_open_file(
        input_file,
        encrypted_len,
        &identities,
        verification_key.as_ref(),
        &output,
        args.force,
        on_progress,
    )?;
    Ok(DecryptOutcome {
        output,
        skipped_identity_files,
        recipient_key_expired,
        signer_key_expired,
    })
}

fn decrypt_open_file<F>(
    input_file: File,
    encrypted_len: u64,
    identities: &[keys::RecipientSecretKeyBundle],
    verification_key: Option<&keys::SigningPublicKeyBundle>,
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
    let metadata;
    {
        let mut reader = BufReader::with_capacity(DEFAULT_CHUNK_SIZE.max(64 * 1024), input_file);
        let mut writer =
            BufWriter::with_capacity(DEFAULT_CHUNK_SIZE.max(64 * 1024), temp_output.as_file_mut());
        metadata = opaque::decrypt_pqc_stream(
            &mut reader,
            &mut writer,
            encrypted_len,
            identities,
            on_progress,
        )?;
        writer.flush()?;
    }

    enforce_signature_requirement(&metadata, verification_key)?;
    temp_output.as_file_mut().sync_all()?;
    envelope::persist_temp_file(temp_output, output, force)
}

fn enforce_signature_requirement(
    metadata: &opaque::PqcDecryptMetadata,
    verification_key: Option<&keys::SigningPublicKeyBundle>,
) -> Result<()> {
    let Some(required_signer_key_id) = &metadata.required_signer_key_id else {
        return Ok(());
    };
    let verification_key = verification_key.ok_or(AppError::SignatureVerificationKeyRequired)?;
    if verification_key.key_id != *required_signer_key_id {
        return Err(AppError::SignatureVerificationFailed);
    }
    Ok(())
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
    verification_key: Option<&keys::SigningPublicKeyBundle>,
    input_file: &mut File,
    encrypted_len: u64,
) -> Result<()> {
    if let Some(verification_key) = verification_key {
        return sign::verify_detached_signature(
            &args.input,
            verification_key,
            input_file,
            encrypted_len,
        );
    }
    Ok(())
}

fn resolve_verification_key(
    args: &AssymDecryptArgs,
) -> Result<Option<keys::SigningPublicKeyBundle>> {
    if let Some(verify_key) = &args.verify {
        return keys::read_signing_public_key(verify_key).map(Some);
    }
    if args.require_signature {
        return Err(AppError::SignatureVerificationKeyRequired);
    }

    let detached_path = envelope::detached_signature_path(&args.input)?;
    match fs::symlink_metadata(detached_path) {
        Ok(_) => Err(AppError::SignatureVerificationKeyRequired),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(AppError::Io(error)),
    }
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
        let verification_key = keys::read_signing_public_key(
            args.verify
                .as_ref()
                .expect("verification key path must exist"),
        )
        .expect("verification key must load");
        verify_signature_policy(
            &args,
            Some(&verification_key),
            &mut verified_file,
            encrypted_len,
        )
        .expect("original open file must verify");

        fs::rename(&replacement, &encrypted).expect("path must be replaced after verification");
        let identities = vec![keys::read_recipient_secret_key(&recipient_secret)
            .expect("recipient secret key must be readable")];
        decrypt_open_file(
            verified_file,
            encrypted_len,
            &identities,
            Some(&verification_key),
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
