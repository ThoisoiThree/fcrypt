use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AppError, Result};

pub const SALT_LEN: usize = 16;
pub const NONCE_PREFIX_LEN: usize = 8;
pub const LENGTH_LEN: usize = 8;
pub const FILE_PREFIX_LEN: usize = SALT_LEN + NONCE_PREFIX_LEN + LENGTH_LEN;
pub const TAG_LEN: usize = 16;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub chunk_size: usize,
    pub argon_memory_kib: u32,
    pub argon_time_cost: u32,
    pub argon_parallelism: u32,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            argon_memory_kib: 65_536,
            argon_time_cost: 3,
            argon_parallelism: 1,
        }
    }
}

pub fn expected_ciphertext_payload_len(plaintext_len: u64, chunk_size: usize) -> Result<u64> {
    validate_chunk_size(chunk_size)?;

    let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let full_chunks = plaintext_len / chunk_size_u64;
    let last_plain_len = plaintext_len % chunk_size_u64;
    let full_chunk_cipher_len = chunk_size_u64
        .checked_add(TAG_LEN as u64)
        .ok_or(AppError::InputTooLarge)?;

    let mut total = full_chunks
        .checked_mul(full_chunk_cipher_len)
        .ok_or(AppError::InputTooLarge)?;

    if last_plain_len > 0 {
        total = total
            .checked_add(last_plain_len + TAG_LEN as u64)
            .ok_or(AppError::InputTooLarge)?;
    }

    Ok(total)
}

pub fn encrypt_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    plaintext_len: u64,
    password: &str,
    config: &CryptoConfig,
    mut on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    validate_chunk_size(config.chunk_size)?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_prefix);
    let length_bytes = plaintext_len.to_le_bytes();

    writer.write_all(&salt)?;
    writer.write_all(&nonce_prefix)?;
    writer.write_all(&length_bytes)?;

    let key = derive_key(password, &salt, config)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| AppError::EncryptionFailed)?;

    let mut buffer = vec![0u8; config.chunk_size];
    let mut chunk_index = 0u64;
    let mut bytes_read_total = 0u64;

    loop {
        let read_bytes = reader.read(&mut buffer)?;
        if read_bytes == 0 {
            break;
        }

        bytes_read_total = bytes_read_total
            .checked_add(read_bytes as u64)
            .ok_or(AppError::InputTooLarge)?;

        let nonce_bytes = build_nonce(&nonce_prefix, chunk_index)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &buffer[..read_bytes],
                    aad: &length_bytes,
                },
            )
            .map_err(|_| AppError::EncryptionFailed)?;

        writer.write_all(&ciphertext)?;
        on_progress(read_bytes as u64);

        buffer[..read_bytes].zeroize();
        chunk_index = chunk_index.checked_add(1).ok_or(AppError::InputTooLarge)?;
    }

    buffer.zeroize();

    if bytes_read_total != plaintext_len {
        return Err(AppError::InputChangedDuringProcessing);
    }

    writer.flush()?;
    Ok(())
}

pub fn decrypt_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    encrypted_len: u64,
    password: &str,
    config: &CryptoConfig,
    mut on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    validate_chunk_size(config.chunk_size)?;

    if encrypted_len < FILE_PREFIX_LEN as u64 {
        return Err(AppError::DecryptionFailed);
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    let mut length_bytes = [0u8; LENGTH_LEN];

    if reader.read_exact(&mut salt).is_err() {
        return Err(AppError::DecryptionFailed);
    }
    if reader.read_exact(&mut nonce_prefix).is_err() {
        return Err(AppError::DecryptionFailed);
    }
    if reader.read_exact(&mut length_bytes).is_err() {
        return Err(AppError::DecryptionFailed);
    }

    let plaintext_len = u64::from_le_bytes(length_bytes);
    let actual_payload_len = encrypted_len - FILE_PREFIX_LEN as u64;
    let expected_payload_len = expected_ciphertext_payload_len(plaintext_len, config.chunk_size)?;
    if actual_payload_len != expected_payload_len {
        return Err(AppError::DecryptionFailed);
    }

    let key = derive_key(password, &salt, config)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| AppError::DecryptionFailed)?;

    let chunk_size_u64 = u64::try_from(config.chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let full_chunks = plaintext_len / chunk_size_u64;
    let last_plain_len = plaintext_len % chunk_size_u64;
    let total_chunks = full_chunks + u64::from(last_plain_len > 0);
    let full_chunk_cipher_len = config
        .chunk_size
        .checked_add(TAG_LEN)
        .ok_or(AppError::InputTooLarge)?;
    let mut ciphertext_buffer = vec![0u8; full_chunk_cipher_len];

    for chunk_index in 0..total_chunks {
        let current_cipher_len = if chunk_index < full_chunks {
            full_chunk_cipher_len
        } else {
            usize::try_from(last_plain_len)
                .map_err(|_| AppError::InputTooLarge)?
                .checked_add(TAG_LEN)
                .ok_or(AppError::InputTooLarge)?
        };

        let chunk = &mut ciphertext_buffer[..current_cipher_len];
        if reader.read_exact(chunk).is_err() {
            return Err(AppError::DecryptionFailed);
        }

        let nonce_bytes = build_nonce(&nonce_prefix, chunk_index)?;
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: chunk,
                    aad: &length_bytes,
                },
            )
            .map_err(|_| AppError::DecryptionFailed)?;

        writer.write_all(&plaintext)?;
        on_progress(current_cipher_len as u64);

        plaintext.zeroize();
        chunk.zeroize();
    }

    ciphertext_buffer.zeroize();
    writer.flush()?;
    Ok(())
}

fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    config: &CryptoConfig,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(
        config.argon_memory_kib,
        config.argon_time_cost,
        config.argon_parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| AppError::CryptoConfig(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(key)
}

fn build_nonce(prefix: &[u8; NONCE_PREFIX_LEN], chunk_index: u64) -> Result<[u8; NONCE_LEN]> {
    let chunk_index_u32 = u32::try_from(chunk_index).map_err(|_| AppError::InputTooLarge)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&chunk_index_u32.to_be_bytes());
    Ok(nonce)
}

fn validate_chunk_size(chunk_size: usize) -> Result<()> {
    if chunk_size == 0 {
        return Err(AppError::InvalidChunkSize);
    }
    Ok(())
}
