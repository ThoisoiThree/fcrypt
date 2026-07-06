use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Digest, Sha3_512};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

use crate::asym::cli::AssymEncryptArgs;
use crate::asym::{envelope, kdf, keys, pqc};
use crate::error::{AppError, Result};
use crate::sym::crypto::{CryptoConfig, DEFAULT_CHUNK_SIZE};
use crate::sym::pathing;

pub struct EncryptOutcome {
    pub output: PathBuf,
    pub keys_dir: PathBuf,
    pub generated_recipient_public: Option<PathBuf>,
    pub generated_recipient_secret: Option<PathBuf>,
    pub generated_signer_public: Option<PathBuf>,
    pub generated_signer_secret: Option<PathBuf>,
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

    let mut file_id = vec![0u8; 32];
    OsRng.fill_bytes(&mut file_id);
    let mut file_secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(file_secret.as_mut());

    let recipient_mlkem_public = recipient.mlkem1024_public_bytes()?;
    let recipient_hqc_public = recipient.hqc256_public_bytes()?;
    let mut encapsulated =
        pqc::encapsulate_recipient(&recipient_mlkem_public, &recipient_hqc_public)?;

    let wrap_keys = kdf::derive_wrap_keys(
        envelope::SUITE_ID,
        &file_id,
        &encapsulated.mlkem1024_ciphertext,
        &encapsulated.mlkem1024_shared_secret,
        &encapsulated.hqc256_ciphertext,
        &encapsulated.hqc256_shared_secret,
    )?;

    let chunk_size = config.chunk_size.max(1);
    let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| AppError::InputTooLarge)?;
    if chunk_count(plaintext_len, chunk_size_u64)? > u32::MAX as u64 {
        return Err(AppError::InputTooLarge);
    }

    let mut header = envelope::HeaderV1 {
        version: envelope::FORMAT_VERSION,
        suite_id: envelope::SUITE_ID.to_string(),
        file_id,
        chunk_size: chunk_size_u64,
        plaintext_len: Some(plaintext_len),
        created_at: None,
        recipient: envelope::RecipientSection {
            key_id: recipient.key_id.clone(),
            label8: Some(recipient.label8.clone()),
            kems: vec![
                envelope::KemCiphertext {
                    alg: "ML-KEM-1024".to_string(),
                    ciphertext: encapsulated.mlkem1024_ciphertext.clone(),
                },
                envelope::KemCiphertext {
                    alg: "HQC-256".to_string(),
                    ciphertext: encapsulated.hqc256_ciphertext.clone(),
                },
            ],
            wrapped_file_secret: Vec::new(),
        },
        aead: envelope::AeadSection {
            alg: "AES-256-GCM".to_string(),
            nonce_mode: "derived-base-plus-chunk-index".to_string(),
            chunk_size: chunk_size_u64,
            header_hash: Vec::new(),
        },
        signature: None,
    };

    let wrap_aad = envelope::recipient_wrap_aad(&header)?;
    let wrap_cipher = Aes256Gcm::new_from_slice(wrap_keys.wrap_key.as_ref())
        .map_err(|_| AppError::EncryptionFailed)?;
    header.recipient.wrapped_file_secret = wrap_cipher
        .encrypt(
            Nonce::from_slice(&wrap_keys.wrap_nonce),
            Payload {
                msg: file_secret.as_ref(),
                aad: &wrap_aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)?;

    let header_hash = envelope::header_hash(&header)?;
    header.aead.header_hash = header_hash.clone();
    envelope::validate_header(&header)?;

    let file_keys = kdf::derive_file_keys(&header.suite_id, &header.file_id, file_secret.as_ref())?;
    let payload_dir = envelope::output_parent_dir(&output);
    fs::create_dir_all(&payload_dir)?;
    let mut payload_temp = NamedTempFile::new_in(&payload_dir)?;
    let ciphertext_hash = {
        let mut writer = BufWriter::with_capacity(
            chunk_size
                .checked_add(envelope::AES_GCM_TAG_LEN)
                .ok_or(AppError::InputTooLarge)?
                .max(64 * 1024),
            payload_temp.as_file_mut(),
        );
        stream_encrypt_payload(
            &mut reader,
            &mut writer,
            EncryptPayloadParams {
                plaintext_len,
                chunk_size,
                aead_key: &file_keys.aead_key,
                nonce_base: &file_keys.nonce_base,
                header_hash: &header_hash,
            },
            on_progress,
        )?
    };
    payload_temp.as_file_mut().sync_all()?;

    let mut generated_signer_public = None;
    let mut generated_signer_secret = None;
    if args.sign || args.sign_key.is_some() {
        let signer = if let Some(sign_key) = &args.sign_key {
            keys::read_signing_secret_key(sign_key)?
        } else {
            let generated = keys::generate_signing_key_files(&keys_dir, args.force)?;
            generated_signer_public = Some(generated.public_path);
            generated_signer_secret = Some(generated.secret_path);
            generated.secret
        };
        let signing_secret = signer.mldsa87_secret_bytes()?;
        let transcript = envelope::signature_transcript(&header, &ciphertext_hash)?;
        let signature = pqc::sign_mldsa87(&signing_secret, &transcript)?;
        header.signature = Some(envelope::SignatureSection {
            alg: "ML-DSA-87".to_string(),
            signer_key_id: signer.key_id,
            transcript_hash_alg: "SHA3-512".to_string(),
            signature,
        });
    }

    write_final_envelope(&output, &header, &mut payload_temp, args.force)?;

    encapsulated.mlkem1024_shared_secret.zeroize();
    encapsulated.hqc256_shared_secret.zeroize();

    Ok(EncryptOutcome {
        output,
        keys_dir,
        generated_recipient_public,
        generated_recipient_secret,
        generated_signer_public,
        generated_signer_secret,
    })
}

struct EncryptPayloadParams<'a> {
    plaintext_len: u64,
    chunk_size: usize,
    aead_key: &'a [u8; 32],
    nonce_base: &'a [u8; 8],
    header_hash: &'a [u8],
}

fn stream_encrypt_payload<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    params: EncryptPayloadParams<'_>,
    mut on_progress: F,
) -> Result<Vec<u8>>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let cipher =
        Aes256Gcm::new_from_slice(params.aead_key).map_err(|_| AppError::EncryptionFailed)?;
    let mut ciphertext_hash = Sha3_512::new();
    let mut buffer = vec![0u8; params.chunk_size];
    let mut chunk_index = 0u64;
    let mut bytes_read_total = 0u64;

    if params.plaintext_len == 0 {
        let ciphertext = encrypt_chunk(
            &cipher,
            params.nonce_base,
            params.header_hash,
            0,
            params.plaintext_len,
            &[],
        )?;
        ciphertext_hash.update(&ciphertext);
        writer.write_all(&ciphertext)?;
        writer.flush()?;
        return Ok(ciphertext_hash.finalize().to_vec());
    }

    loop {
        let read_bytes = reader.read(&mut buffer)?;
        if read_bytes == 0 {
            break;
        }
        bytes_read_total = bytes_read_total
            .checked_add(read_bytes as u64)
            .ok_or(AppError::InputTooLarge)?;
        let ciphertext = encrypt_chunk(
            &cipher,
            params.nonce_base,
            params.header_hash,
            chunk_index,
            params.plaintext_len,
            &buffer[..read_bytes],
        )?;
        ciphertext_hash.update(&ciphertext);
        writer.write_all(&ciphertext)?;
        on_progress(read_bytes as u64);
        buffer[..read_bytes].zeroize();
        chunk_index = chunk_index.checked_add(1).ok_or(AppError::InputTooLarge)?;
    }

    buffer.zeroize();
    if bytes_read_total != params.plaintext_len {
        return Err(AppError::InputChangedDuringProcessing);
    }
    writer.flush()?;
    Ok(ciphertext_hash.finalize().to_vec())
}

fn encrypt_chunk(
    cipher: &Aes256Gcm,
    nonce_base: &[u8; 8],
    header_hash: &[u8],
    chunk_index: u64,
    plaintext_len: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = build_nonce(nonce_base, chunk_index)?;
    let aad = chunk_aad(header_hash, chunk_index, plaintext_len, plaintext.len())?;
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)
}

pub(crate) fn build_nonce(nonce_base: &[u8; 8], chunk_index: u64) -> Result<[u8; 12]> {
    let chunk_index = u32::try_from(chunk_index).map_err(|_| AppError::InputTooLarge)?;
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(nonce_base);
    nonce[8..].copy_from_slice(&chunk_index.to_be_bytes());
    Ok(nonce)
}

pub(crate) fn chunk_aad(
    header_hash: &[u8],
    chunk_index: u64,
    plaintext_len: u64,
    chunk_len: usize,
) -> Result<Vec<u8>> {
    let chunk_len = u32::try_from(chunk_len).map_err(|_| AppError::InputTooLarge)?;
    let mut aad = Vec::with_capacity(header_hash.len() + 8 + 8 + 4);
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(&chunk_len.to_be_bytes());
    Ok(aad)
}

fn write_final_envelope(
    output: &Path,
    header: &envelope::HeaderV1,
    payload_temp: &mut NamedTempFile,
    force: bool,
) -> Result<()> {
    payload_temp.as_file_mut().seek(SeekFrom::Start(0))?;
    let output_dir = envelope::output_parent_dir(output);
    let mut final_temp = NamedTempFile::new_in(&output_dir)?;
    {
        let mut writer = BufWriter::new(final_temp.as_file_mut());
        envelope::write_envelope(&mut writer, header)?;
        std::io::copy(payload_temp.as_file_mut(), &mut writer)?;
        writer.flush()?;
    }
    final_temp.as_file_mut().sync_all()?;
    envelope::persist_temp_file(final_temp, output, force)
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
