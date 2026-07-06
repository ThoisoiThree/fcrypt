use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

use crate::asym::cli::AssymDecryptArgs;
use crate::asym::{encrypt, envelope, kdf, keys, pqc};
use crate::error::{AppError, Result};
use crate::sym::pathing;

pub fn decrypt_file<F>(args: &AssymDecryptArgs, on_progress: F) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    pqc::ensure_enabled()?;
    if !envelope::is_fe_file(&args.input)? {
        return Err(AppError::NotAsymmetricFile(
            args.input.display().to_string(),
        ));
    }

    let output = args
        .output
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_decryption_output_path(&args.input))?;
    if output.exists() && !args.force {
        return Err(AppError::OutputExists(output));
    }

    let envelope_reader = envelope::read_envelope(&args.input)?;
    envelope::validate_header(&envelope_reader.header)?;
    let plaintext_len = envelope_reader.header.plaintext_len.ok_or_else(|| {
        AppError::InvalidAsymmetricFile("plaintext length is required".to_string())
    })?;
    let chunk_size =
        usize::try_from(envelope_reader.header.chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let expected_payload_len = envelope::expected_payload_len(plaintext_len, chunk_size)?;
    let actual_payload_len = envelope::payload_len(&envelope_reader)?;
    if actual_payload_len != expected_payload_len {
        return Err(AppError::AsymmetricAuthenticationFailed);
    }

    let identity = resolve_identity(args, &envelope_reader.header.recipient.key_id)?;
    if identity.key_id != envelope_reader.header.recipient.key_id {
        return Err(AppError::InvalidAsymmetricKeyFile(
            "recipient secret key_id does not match .fe recipient".to_string(),
        ));
    }

    verify_signature_policy(args, &envelope_reader)?;

    let mlkem_secret = identity.mlkem1024_secret_bytes()?;
    let hqc_secret = identity.hqc256_secret_bytes()?;
    let mlkem_ct = &envelope_reader.header.recipient.kems[0].ciphertext;
    let hqc_ct = &envelope_reader.header.recipient.kems[1].ciphertext;
    let (mut mlkem_ss, mut hqc_ss) =
        pqc::decapsulate_recipient(&mlkem_secret, &hqc_secret, mlkem_ct, hqc_ct)?;

    let wrap_keys = kdf::derive_wrap_keys(
        &envelope_reader.header.suite_id,
        &envelope_reader.header.file_id,
        mlkem_ct,
        &mlkem_ss,
        hqc_ct,
        &hqc_ss,
    )?;
    let wrap_aad = envelope::recipient_wrap_aad(&envelope_reader.header)?;
    let wrap_cipher = Aes256Gcm::new_from_slice(wrap_keys.wrap_key.as_ref())
        .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
    let file_secret = wrap_cipher
        .decrypt(
            Nonce::from_slice(&wrap_keys.wrap_nonce),
            Payload {
                msg: &envelope_reader.header.recipient.wrapped_file_secret,
                aad: &wrap_aad,
            },
        )
        .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
    if file_secret.len() != 32 {
        return Err(AppError::AsymmetricAuthenticationFailed);
    }
    let file_secret = Zeroizing::new(file_secret);
    let file_keys = kdf::derive_file_keys(
        &envelope_reader.header.suite_id,
        &envelope_reader.header.file_id,
        file_secret.as_slice(),
    )?;

    let output_dir = envelope::output_parent_dir(&output);
    fs::create_dir_all(&output_dir)?;
    let mut temp_output = NamedTempFile::new_in(&output_dir)?;
    {
        let mut payload_reader =
            envelope::open_payload_reader(&args.input, envelope_reader.payload_offset)?;
        let mut writer =
            BufWriter::with_capacity(chunk_size.max(64 * 1024), temp_output.as_file_mut());
        stream_decrypt_payload(
            &mut payload_reader,
            &mut writer,
            DecryptPayloadParams {
                plaintext_len,
                chunk_size,
                aead_key: &file_keys.aead_key,
                nonce_base: &file_keys.nonce_base,
                header_hash: &envelope_reader.header.aead.header_hash,
            },
            on_progress,
        )?;
        writer.flush()?;
    }

    temp_output.as_file_mut().sync_all()?;
    mlkem_ss.zeroize();
    hqc_ss.zeroize();
    envelope::persist_temp_file(temp_output, &output, args.force)?;
    Ok(output)
}

fn resolve_identity(
    args: &AssymDecryptArgs,
    recipient_key_id: &str,
) -> Result<keys::RecipientSecretKeyBundle> {
    if let Some(identity) = &args.identity {
        return keys::read_recipient_secret_key(identity);
    }
    let keys_dir = args
        .keys_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_default_keys_dir_for_fe_input(&args.input))?;
    keys::find_recipient_secret_key(&keys_dir, recipient_key_id)
}

fn verify_signature_policy(
    args: &AssymDecryptArgs,
    envelope_reader: &envelope::EnvelopeReader,
) -> Result<()> {
    if args.verify.is_none() && !args.require_signature {
        return Ok(());
    }
    let verify_key = args
        .verify
        .as_ref()
        .ok_or(AppError::SignatureVerificationKeyRequired)?;
    let public_key = keys::read_signing_public_key(verify_key)?;
    let signature = resolve_signature(args, &envelope_reader.header)?;
    if signature.signer_key_id != public_key.key_id {
        return Err(AppError::SignatureVerificationFailed);
    }
    if signature.alg != "ML-DSA-87" || signature.transcript_hash_alg != "SHA3-512" {
        return Err(AppError::SignatureVerificationFailed);
    }

    let mut payload_reader =
        envelope::open_payload_reader(&args.input, envelope_reader.payload_offset)?;
    let ciphertext_hash = envelope::ciphertext_hash_from_reader(&mut payload_reader)?;
    let transcript = envelope::signature_transcript(&envelope_reader.header, &ciphertext_hash)?;
    let public_key_bytes = public_key.mldsa87_public_bytes()?;
    pqc::verify_mldsa87(&public_key_bytes, &transcript, &signature.signature)
}

fn resolve_signature(
    args: &AssymDecryptArgs,
    header: &envelope::HeaderV1,
) -> Result<envelope::SignatureSection> {
    if let Some(signature) = &header.signature {
        return Ok(signature.clone());
    }

    let detached_path = envelope::detached_signature_path(&args.input)?;
    if !detached_path.exists() {
        return Err(AppError::SignatureRequired);
    }
    let file = fs::File::open(&detached_path)?;
    let detached: envelope::DetachedSignature = serde_json::from_reader(BufReader::new(file))
        .map_err(|e| {
            AppError::InvalidAsymmetricFile(format!(
                "invalid detached signature {}: {e}",
                detached_path.display()
            ))
        })?;
    envelope::detached_signature_to_section(detached)
}

struct DecryptPayloadParams<'a> {
    plaintext_len: u64,
    chunk_size: usize,
    aead_key: &'a [u8; 32],
    nonce_base: &'a [u8; 8],
    header_hash: &'a [u8],
}

fn stream_decrypt_payload<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    params: DecryptPayloadParams<'_>,
    mut on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let cipher = Aes256Gcm::new_from_slice(params.aead_key)
        .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
    let chunk_size_u64 = u64::try_from(params.chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let full_chunks = params.plaintext_len / chunk_size_u64;
    let last_plain_len = params.plaintext_len % chunk_size_u64;
    let total_chunks = if params.plaintext_len == 0 {
        1
    } else {
        full_chunks + u64::from(last_plain_len > 0)
    };
    if total_chunks > u32::MAX as u64 {
        return Err(AppError::InputTooLarge);
    }

    let full_chunk_cipher_len = params
        .chunk_size
        .checked_add(envelope::AES_GCM_TAG_LEN)
        .ok_or(AppError::InputTooLarge)?;
    let mut ciphertext_buffer = vec![0u8; full_chunk_cipher_len];

    for chunk_index in 0..total_chunks {
        let plain_len = if params.plaintext_len == 0 {
            0
        } else if chunk_index < full_chunks {
            params.chunk_size
        } else {
            usize::try_from(last_plain_len).map_err(|_| AppError::InputTooLarge)?
        };
        let current_cipher_len = plain_len
            .checked_add(envelope::AES_GCM_TAG_LEN)
            .ok_or(AppError::InputTooLarge)?;
        let chunk = &mut ciphertext_buffer[..current_cipher_len];
        reader
            .read_exact(chunk)
            .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
        let nonce = encrypt::build_nonce(params.nonce_base, chunk_index)?;
        let aad = encrypt::chunk_aad(
            params.header_hash,
            chunk_index,
            params.plaintext_len,
            plain_len,
        )?;
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
        writer.write_all(&plaintext)?;
        on_progress(current_cipher_len as u64);
        plaintext.zeroize();
        chunk.zeroize();
    }

    ciphertext_buffer.zeroize();
    writer.flush()?;
    Ok(())
}
