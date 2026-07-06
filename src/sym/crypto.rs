use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use eax::Eax;
use rand::rngs::OsRng;
use rand::RngCore;
use serpent::Serpent;
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AppError, Result};

pub const SALT_LEN: usize = 16;
pub const NONCE_PREFIX_LEN: usize = 8;
pub const LENGTH_LEN: usize = 8;
pub const FILE_PREFIX_LEN: usize = SALT_LEN + NONCE_PREFIX_LEN + LENGTH_LEN;
pub const TAG_LEN: usize = 16;

const KEY_LEN: usize = 32;
const SERPENT_KEY_LEN: usize = 16;
const CASCADE_KEY_LEN: usize = KEY_LEN + SERPENT_KEY_LEN;
const NONCE_LEN: usize = 12;
const SERPENT_NONCE_LEN: usize = 16;
pub const PARANOID_ARGON_MEMORY_KIB: u32 = 1_048_576;
pub const PARANOID_ARGON_TIME_COST: u32 = 6;
pub const PARANOID_ARGON_PARALLELISM: u32 = 4;
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

const HEADER_MAGIC: &[u8; 8] = b"FCRYPTH1";
pub const VERSIONED_HEADER_LEN: usize = 72;
pub const PARANOID_FLAG: u8 = 0x01;
const FORMAT_VERSION: u8 = 1;
const ALGORITHM_AES_GCM_SERPENT_EAX: u8 = 1;
const CASCADE_LAYER_COUNT: u8 = 2;
const MAX_HEADER_CHUNK_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_HEADER_ARGON_MEMORY_KIB: u32 = PARANOID_ARGON_MEMORY_KIB;
const MAX_HEADER_ARGON_TIME_COST: u32 = 10;
const MAX_HEADER_ARGON_PARALLELISM: u32 = 16;

type SerpentEax = Eax<Serpent>;

#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub chunk_size: usize,
    pub argon_memory_kib: u32,
    pub argon_time_cost: u32,
    pub argon_parallelism: u32,
    pub paranoid_argon_memory_kib: u32,
    pub paranoid_argon_time_cost: u32,
    pub paranoid_argon_parallelism: u32,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            argon_memory_kib: 65_536,
            argon_time_cost: 3,
            argon_parallelism: 1,
            paranoid_argon_memory_kib: PARANOID_ARGON_MEMORY_KIB,
            paranoid_argon_time_cost: PARANOID_ARGON_TIME_COST,
            paranoid_argon_parallelism: PARANOID_ARGON_PARALLELISM,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    Standard,
    Paranoid,
}

pub fn expected_ciphertext_payload_len(plaintext_len: u64, chunk_size: usize) -> Result<u64> {
    expected_ciphertext_payload_len_with_tags(plaintext_len, chunk_size, 1)
}

fn expected_ciphertext_payload_len_with_tags(
    plaintext_len: u64,
    chunk_size: usize,
    tag_count: u64,
) -> Result<u64> {
    validate_chunk_size(chunk_size)?;
    let tag_overhead = (TAG_LEN as u64)
        .checked_mul(tag_count)
        .ok_or(AppError::InputTooLarge)?;

    if plaintext_len == 0 {
        return Ok(tag_overhead);
    }

    let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let full_chunks = plaintext_len / chunk_size_u64;
    let last_plain_len = plaintext_len % chunk_size_u64;
    let full_chunk_cipher_len = chunk_size_u64
        .checked_add(tag_overhead)
        .ok_or(AppError::InputTooLarge)?;

    let mut total = full_chunks
        .checked_mul(full_chunk_cipher_len)
        .ok_or(AppError::InputTooLarge)?;

    if last_plain_len > 0 {
        total = total
            .checked_add(last_plain_len + tag_overhead)
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
    on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    encrypt_stream_with_mode(
        reader,
        writer,
        plaintext_len,
        password,
        config,
        CryptoMode::Standard,
        on_progress,
    )
}

pub fn encrypt_stream_with_mode<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    plaintext_len: u64,
    password: &str,
    config: &CryptoConfig,
    mode: CryptoMode,
    on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    match mode {
        CryptoMode::Standard => {
            encrypt_standard_stream(reader, writer, plaintext_len, password, config, on_progress)
        }
        CryptoMode::Paranoid => {
            encrypt_paranoid_stream(reader, writer, plaintext_len, password, config, on_progress)
        }
    }
}

fn encrypt_standard_stream<R, W, F>(
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

    if plaintext_len == 0 {
        let nonce_bytes = build_nonce(&nonce_prefix, 0)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &[],
                    aad: &length_bytes,
                },
            )
            .map_err(|_| AppError::EncryptionFailed)?;

        writer.write_all(&ciphertext)?;
        writer.flush()?;
        return Ok(());
    }

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

fn encrypt_paranoid_stream<R, W, F>(
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
    let mut aes_nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    let mut serpent_nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut aes_nonce_prefix);
    OsRng.fill_bytes(&mut serpent_nonce_prefix);

    let header = VersionedHeader {
        flags: PARANOID_FLAG,
        algorithm: ALGORITHM_AES_GCM_SERPENT_EAX,
        layer_count: CASCADE_LAYER_COUNT,
        chunk_size: u64::try_from(config.chunk_size).map_err(|_| AppError::InputTooLarge)?,
        argon_memory_kib: config.paranoid_argon_memory_kib,
        argon_time_cost: config.paranoid_argon_time_cost,
        argon_parallelism: config.paranoid_argon_parallelism,
        plaintext_len,
        salt,
        aes_nonce_prefix,
        serpent_nonce_prefix,
    };
    header.validate()?;
    let header_bytes = header.to_bytes();
    writer.write_all(&header_bytes)?;

    let argon_config = CryptoConfig {
        chunk_size: config.chunk_size,
        argon_memory_kib: config.paranoid_argon_memory_kib,
        argon_time_cost: config.paranoid_argon_time_cost,
        argon_parallelism: config.paranoid_argon_parallelism,
        paranoid_argon_memory_kib: config.paranoid_argon_memory_kib,
        paranoid_argon_time_cost: config.paranoid_argon_time_cost,
        paranoid_argon_parallelism: config.paranoid_argon_parallelism,
    };
    let keys = derive_cascade_keys(password, &salt, &argon_config)?;
    let aes_cipher =
        Aes256Gcm::new_from_slice(&keys[..KEY_LEN]).map_err(|_| AppError::EncryptionFailed)?;
    let serpent_cipher =
        SerpentEax::new_from_slice(&keys[KEY_LEN..]).map_err(|_| AppError::EncryptionFailed)?;

    if plaintext_len == 0 {
        let ciphertext = encrypt_paranoid_chunk(
            &aes_cipher,
            &serpent_cipher,
            &aes_nonce_prefix,
            &serpent_nonce_prefix,
            0,
            &[],
            &header_bytes,
        )?;
        writer.write_all(&ciphertext)?;
        writer.flush()?;
        return Ok(());
    }

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

        let ciphertext = encrypt_paranoid_chunk(
            &aes_cipher,
            &serpent_cipher,
            &aes_nonce_prefix,
            &serpent_nonce_prefix,
            chunk_index,
            &buffer[..read_bytes],
            &header_bytes,
        )?;

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
    on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    if encrypted_len < HEADER_MAGIC.len() as u64 {
        return Err(AppError::DecryptionFailed);
    }

    let mut first_bytes = [0u8; 8];
    if reader.read_exact(&mut first_bytes).is_err() {
        return Err(AppError::DecryptionFailed);
    }

    if &first_bytes == HEADER_MAGIC {
        decrypt_versioned_stream(
            reader,
            writer,
            encrypted_len,
            password,
            first_bytes,
            on_progress,
        )
    } else {
        decrypt_legacy_stream(
            reader,
            writer,
            encrypted_len,
            password,
            config,
            first_bytes,
            on_progress,
        )
    }
}

fn decrypt_legacy_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    encrypted_len: u64,
    password: &str,
    config: &CryptoConfig,
    first_salt_bytes: [u8; 8],
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
    salt[..8].copy_from_slice(&first_salt_bytes);
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    let mut length_bytes = [0u8; LENGTH_LEN];

    if reader.read_exact(&mut salt[8..]).is_err() {
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
    let legacy_empty_without_tag = plaintext_len == 0 && actual_payload_len == 0;
    if actual_payload_len != expected_payload_len && !legacy_empty_without_tag {
        return Err(AppError::DecryptionFailed);
    }

    if legacy_empty_without_tag {
        on_progress(FILE_PREFIX_LEN as u64);
        writer.flush()?;
        return Ok(());
    }

    on_progress(FILE_PREFIX_LEN as u64);

    let key = derive_key(password, &salt, config)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| AppError::DecryptionFailed)?;

    let chunk_size_u64 = u64::try_from(config.chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let full_chunks = plaintext_len / chunk_size_u64;
    let last_plain_len = plaintext_len % chunk_size_u64;
    let total_chunks = if plaintext_len == 0 {
        1
    } else {
        full_chunks + u64::from(last_plain_len > 0)
    };
    let full_chunk_cipher_len = config
        .chunk_size
        .checked_add(TAG_LEN)
        .ok_or(AppError::InputTooLarge)?;
    let mut ciphertext_buffer = vec![0u8; full_chunk_cipher_len];

    for chunk_index in 0..total_chunks {
        let current_cipher_len = if plaintext_len == 0 {
            TAG_LEN
        } else if chunk_index < full_chunks {
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

fn decrypt_versioned_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    encrypted_len: u64,
    password: &str,
    first_header_bytes: [u8; 8],
    mut on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    if encrypted_len < VERSIONED_HEADER_LEN as u64 {
        return Err(AppError::DecryptionFailed);
    }

    let mut header_bytes = [0u8; VERSIONED_HEADER_LEN];
    header_bytes[..8].copy_from_slice(&first_header_bytes);
    if reader.read_exact(&mut header_bytes[8..]).is_err() {
        return Err(AppError::DecryptionFailed);
    }

    let header = VersionedHeader::from_bytes(&header_bytes)?;
    header.validate()?;

    let chunk_size = usize::try_from(header.chunk_size).map_err(|_| AppError::InputTooLarge)?;
    validate_chunk_size(chunk_size)?;

    let actual_payload_len = encrypted_len - VERSIONED_HEADER_LEN as u64;
    let expected_payload_len =
        expected_ciphertext_payload_len_with_tags(header.plaintext_len, chunk_size, 2)?;
    if actual_payload_len != expected_payload_len {
        return Err(AppError::DecryptionFailed);
    }

    on_progress(VERSIONED_HEADER_LEN as u64);

    let argon_config = CryptoConfig {
        chunk_size,
        argon_memory_kib: header.argon_memory_kib,
        argon_time_cost: header.argon_time_cost,
        argon_parallelism: header.argon_parallelism,
        paranoid_argon_memory_kib: header.argon_memory_kib,
        paranoid_argon_time_cost: header.argon_time_cost,
        paranoid_argon_parallelism: header.argon_parallelism,
    };
    let keys = derive_cascade_keys(password, &header.salt, &argon_config)?;
    let aes_cipher =
        Aes256Gcm::new_from_slice(&keys[..KEY_LEN]).map_err(|_| AppError::DecryptionFailed)?;
    let serpent_cipher =
        SerpentEax::new_from_slice(&keys[KEY_LEN..]).map_err(|_| AppError::DecryptionFailed)?;

    let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let full_chunks = header.plaintext_len / chunk_size_u64;
    let last_plain_len = header.plaintext_len % chunk_size_u64;
    let total_chunks = if header.plaintext_len == 0 {
        1
    } else {
        full_chunks + u64::from(last_plain_len > 0)
    };
    let full_chunk_cipher_len = chunk_size
        .checked_add(TAG_LEN * 2)
        .ok_or(AppError::InputTooLarge)?;
    let mut ciphertext_buffer = vec![0u8; full_chunk_cipher_len];

    for chunk_index in 0..total_chunks {
        let current_cipher_len = if header.plaintext_len == 0 {
            TAG_LEN * 2
        } else if chunk_index < full_chunks {
            full_chunk_cipher_len
        } else {
            usize::try_from(last_plain_len)
                .map_err(|_| AppError::InputTooLarge)?
                .checked_add(TAG_LEN * 2)
                .ok_or(AppError::InputTooLarge)?
        };

        let chunk = &mut ciphertext_buffer[..current_cipher_len];
        if reader.read_exact(chunk).is_err() {
            return Err(AppError::DecryptionFailed);
        }

        let mut plaintext = decrypt_paranoid_chunk(
            &aes_cipher,
            &serpent_cipher,
            &header.aes_nonce_prefix,
            &header.serpent_nonce_prefix,
            chunk_index,
            chunk,
            &header_bytes,
        )?;

        writer.write_all(&plaintext)?;
        on_progress(current_cipher_len as u64);

        plaintext.zeroize();
        chunk.zeroize();
    }

    ciphertext_buffer.zeroize();
    writer.flush()?;
    Ok(())
}

fn encrypt_paranoid_chunk(
    aes_cipher: &Aes256Gcm,
    serpent_cipher: &SerpentEax,
    aes_nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    serpent_nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    chunk_index: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let aes_nonce_bytes = build_nonce(aes_nonce_prefix, chunk_index)?;
    let mut aes_ciphertext = aes_cipher
        .encrypt(
            Nonce::from_slice(&aes_nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)?;

    let serpent_nonce_bytes = build_serpent_nonce(serpent_nonce_prefix, chunk_index);
    let ciphertext = serpent_cipher
        .encrypt(
            Nonce::from_slice(&serpent_nonce_bytes),
            Payload {
                msg: aes_ciphertext.as_slice(),
                aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)?;
    aes_ciphertext.zeroize();
    Ok(ciphertext)
}

fn decrypt_paranoid_chunk(
    aes_cipher: &Aes256Gcm,
    serpent_cipher: &SerpentEax,
    aes_nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    serpent_nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    chunk_index: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let serpent_nonce_bytes = build_serpent_nonce(serpent_nonce_prefix, chunk_index);
    let mut aes_ciphertext = serpent_cipher
        .decrypt(
            Nonce::from_slice(&serpent_nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AppError::DecryptionFailed)?;

    let aes_nonce_bytes = build_nonce(aes_nonce_prefix, chunk_index)?;
    let plaintext = aes_cipher
        .decrypt(
            Nonce::from_slice(&aes_nonce_bytes),
            Payload {
                msg: aes_ciphertext.as_slice(),
                aad,
            },
        )
        .map_err(|_| AppError::DecryptionFailed)?;
    aes_ciphertext.zeroize();
    Ok(plaintext)
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

fn derive_cascade_keys(
    password: &str,
    salt: &[u8; SALT_LEN],
    config: &CryptoConfig,
) -> Result<Zeroizing<[u8; CASCADE_KEY_LEN]>> {
    let params = Params::new(
        config.argon_memory_kib,
        config.argon_time_cost,
        config.argon_parallelism,
        Some(CASCADE_KEY_LEN),
    )
    .map_err(|e| AppError::CryptoConfig(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut keys = Zeroizing::new([0u8; CASCADE_KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, keys.as_mut())
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(keys)
}

fn build_nonce(prefix: &[u8; NONCE_PREFIX_LEN], chunk_index: u64) -> Result<[u8; NONCE_LEN]> {
    let chunk_index_u32 = u32::try_from(chunk_index).map_err(|_| AppError::InputTooLarge)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&chunk_index_u32.to_be_bytes());
    Ok(nonce)
}

fn build_serpent_nonce(
    prefix: &[u8; NONCE_PREFIX_LEN],
    chunk_index: u64,
) -> [u8; SERPENT_NONCE_LEN] {
    let mut nonce = [0u8; SERPENT_NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

fn validate_chunk_size(chunk_size: usize) -> Result<()> {
    if chunk_size == 0 {
        return Err(AppError::InvalidChunkSize);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct VersionedHeader {
    flags: u8,
    algorithm: u8,
    layer_count: u8,
    chunk_size: u64,
    argon_memory_kib: u32,
    argon_time_cost: u32,
    argon_parallelism: u32,
    plaintext_len: u64,
    salt: [u8; SALT_LEN],
    aes_nonce_prefix: [u8; NONCE_PREFIX_LEN],
    serpent_nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl VersionedHeader {
    fn to_bytes(self) -> [u8; VERSIONED_HEADER_LEN] {
        let mut bytes = [0u8; VERSIONED_HEADER_LEN];
        bytes[..8].copy_from_slice(HEADER_MAGIC);
        bytes[8] = FORMAT_VERSION;
        bytes[9] = self.flags;
        bytes[10] = self.algorithm;
        bytes[11] = self.layer_count;
        bytes[12..20].copy_from_slice(&self.chunk_size.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.argon_memory_kib.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.argon_time_cost.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.argon_parallelism.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.plaintext_len.to_le_bytes());
        bytes[40..56].copy_from_slice(&self.salt);
        bytes[56..64].copy_from_slice(&self.aes_nonce_prefix);
        bytes[64..72].copy_from_slice(&self.serpent_nonce_prefix);
        bytes
    }

    fn from_bytes(bytes: &[u8; VERSIONED_HEADER_LEN]) -> Result<Self> {
        if &bytes[..8] != HEADER_MAGIC {
            return Err(AppError::DecryptionFailed);
        }
        if bytes[8] != FORMAT_VERSION {
            return Err(AppError::DecryptionFailed);
        }

        let mut chunk_size_bytes = [0u8; 8];
        chunk_size_bytes.copy_from_slice(&bytes[12..20]);
        let mut argon_memory_bytes = [0u8; 4];
        argon_memory_bytes.copy_from_slice(&bytes[20..24]);
        let mut argon_time_bytes = [0u8; 4];
        argon_time_bytes.copy_from_slice(&bytes[24..28]);
        let mut argon_parallelism_bytes = [0u8; 4];
        argon_parallelism_bytes.copy_from_slice(&bytes[28..32]);
        let mut plaintext_len_bytes = [0u8; 8];
        plaintext_len_bytes.copy_from_slice(&bytes[32..40]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[40..56]);
        let mut aes_nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        aes_nonce_prefix.copy_from_slice(&bytes[56..64]);
        let mut serpent_nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        serpent_nonce_prefix.copy_from_slice(&bytes[64..72]);

        Ok(Self {
            flags: bytes[9],
            algorithm: bytes[10],
            layer_count: bytes[11],
            chunk_size: u64::from_le_bytes(chunk_size_bytes),
            argon_memory_kib: u32::from_le_bytes(argon_memory_bytes),
            argon_time_cost: u32::from_le_bytes(argon_time_bytes),
            argon_parallelism: u32::from_le_bytes(argon_parallelism_bytes),
            plaintext_len: u64::from_le_bytes(plaintext_len_bytes),
            salt,
            aes_nonce_prefix,
            serpent_nonce_prefix,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.flags & PARANOID_FLAG == 0
            || self.flags & !PARANOID_FLAG != 0
            || self.algorithm != ALGORITHM_AES_GCM_SERPENT_EAX
            || self.layer_count != CASCADE_LAYER_COUNT
            || self.chunk_size == 0
            || self.chunk_size > MAX_HEADER_CHUNK_SIZE
            || self.argon_memory_kib == 0
            || self.argon_memory_kib > MAX_HEADER_ARGON_MEMORY_KIB
            || self.argon_time_cost == 0
            || self.argon_time_cost > MAX_HEADER_ARGON_TIME_COST
            || self.argon_parallelism == 0
            || self.argon_parallelism > MAX_HEADER_ARGON_PARALLELISM
        {
            return Err(AppError::DecryptionFailed);
        }

        Ok(())
    }
}
