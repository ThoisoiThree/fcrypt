//! Opaque encrypted file container.
//!
//! The on-disk layout intentionally has no magic bytes, cleartext version, or
//! cleartext algorithm identifiers. All fixed regions are random-looking:
//!
//! ```text
//! 32 bytes        file nonce
//! 8 * 16384      recipient slots
//! 4112 bytes     encrypted manifest
//! rest           encrypted payload chunks
//! ```
//!
//! Format versioning, chunk parameters, file length, and payload keys are inside
//! the encrypted manifest. The fixed prelude size is the price paid for hiding
//! the normal "this is an encrypted fcrypt file" metadata surface.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

use crate::asym::{keys, pqc};
use crate::error::{AppError, Result};
use crate::sym::crypto::CryptoConfig;

pub const FILE_NONCE_LEN: usize = 32;
pub const SLOT_COUNT: usize = 8;
pub const SLOT_LEN: usize = 16 * 1024;
pub const SLOT_AREA_LEN: usize = SLOT_COUNT * SLOT_LEN;
pub const TAG_LEN: usize = 16;
pub const SLOT_BODY_LEN: usize = 96;
pub const SLOT_CIPHERTEXT_LEN: usize = SLOT_BODY_LEN + TAG_LEN;
pub const MANIFEST_PLAINTEXT_LEN: usize = 4096;
pub const MANIFEST_CIPHERTEXT_LEN: usize = MANIFEST_PLAINTEXT_LEN + TAG_LEN;
pub const PRELUDE_LEN: usize = FILE_NONCE_LEN + SLOT_AREA_LEN + MANIFEST_CIPHERTEXT_LEN;
pub const OPAQUE_V1_ARGON_MEMORY_KIB: u32 = 131_072;
pub const OPAQUE_V1_ARGON_TIME_COST: u32 = 3;
pub const OPAQUE_V1_ARGON_PARALLELISM: u32 = 1;

const FORMAT_VERSION: u16 = 1;
const INTERNAL_MAGIC: &[u8; 16] = b"fcrypt opaque v1";
const ROLE_PASSWORD: u8 = 1;
const ROLE_PQC: u8 = 2;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const PAYLOAD_NONCE_BASE_LEN: usize = 4;
const MAX_CHUNK_SIZE: u64 = 1024 * 1024 * 1024;

const MLKEM1024_CT_LEN: usize = 1568;
const HQC256_CT_LEN: usize = 14421;
const PQC_WRAP_OFFSET: usize = MLKEM1024_CT_LEN + HQC256_CT_LEN;
const PQC_SLOT_MIN_LEN: usize = PQC_WRAP_OFFSET + SLOT_CIPHERTEXT_LEN;

type HkdfSha3_512 = Hkdf<Sha3_512>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManifestV1 {
    version: u16,
    #[serde(with = "serde_bytes")]
    magic: Vec<u8>,
    plaintext_len: u64,
    chunk_size: u64,
    chunk_count: u64,
    tag_len: u16,
    #[serde(with = "serde_bytes")]
    file_secret: Vec<u8>,
}

#[derive(Debug)]
struct OpenedPrelude {
    file_nonce: [u8; FILE_NONCE_LEN],
    manifest_ciphertext: Vec<u8>,
    manifest: ManifestV1,
    payload_offset: u64,
}

pub fn expected_payload_len(plaintext_len: u64, chunk_size: usize) -> Result<u64> {
    validate_chunk_size(chunk_size)?;
    let tag_len = TAG_LEN as u64;
    if plaintext_len == 0 {
        return Ok(tag_len);
    }

    let chunk_size = u64::try_from(chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let full_chunks = plaintext_len / chunk_size;
    let last_plain_len = plaintext_len % chunk_size;
    let full_chunk_cipher_len = chunk_size
        .checked_add(tag_len)
        .ok_or(AppError::InputTooLarge)?;
    let mut total = full_chunks
        .checked_mul(full_chunk_cipher_len)
        .ok_or(AppError::InputTooLarge)?;
    if last_plain_len > 0 {
        total = total
            .checked_add(last_plain_len + tag_len)
            .ok_or(AppError::InputTooLarge)?;
    }
    Ok(total)
}

pub fn encrypt_password_stream<R, W, F>(
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
    validate_chunk_size(config.chunk_size)?;

    let mut file_nonce = [0u8; FILE_NONCE_LEN];
    let mut manifest_key = Zeroizing::new([0u8; KEY_LEN]);
    let mut file_secret = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut file_nonce);
    OsRng.fill_bytes(manifest_key.as_mut());
    OsRng.fill_bytes(file_secret.as_mut());

    let chunk_size = u64::try_from(config.chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let chunk_count = chunk_count(plaintext_len, chunk_size)?;
    expected_payload_len(plaintext_len, config.chunk_size)?;
    let manifest = ManifestV1 {
        version: FORMAT_VERSION,
        magic: INTERNAL_MAGIC.to_vec(),
        plaintext_len,
        chunk_size,
        chunk_count,
        tag_len: TAG_LEN as u16,
        file_secret: file_secret.as_ref().to_vec(),
    };
    let manifest_ciphertext = seal_manifest(&file_nonce, &manifest_key, &manifest)?;

    let mut slots = vec![0u8; SLOT_AREA_LEN];
    OsRng.fill_bytes(&mut slots);
    seal_password_slot(
        &mut slots[..SLOT_LEN],
        0,
        &file_nonce,
        &manifest_key,
        password,
    )?;

    writer.write_all(&file_nonce)?;
    writer.write_all(&slots)?;
    writer.write_all(&manifest_ciphertext)?;
    stream_encrypt_payload(
        reader,
        writer,
        PayloadEncryptParams {
            file_nonce: &file_nonce,
            manifest_ciphertext: &manifest_ciphertext,
            plaintext_len,
            chunk_size: config.chunk_size,
            chunk_count,
            file_secret: &file_secret,
        },
        on_progress,
    )
}

pub fn decrypt_password_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    encrypted_len: u64,
    password: &str,
    mut on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let prelude = read_prelude(reader, encrypted_len).map_err(|_| AppError::DecryptionFailed)?;
    let manifest_key = open_password_slots(&prelude.slots, &prelude.file_nonce, password)
        .map_err(|_| AppError::DecryptionFailed)?;
    let opened = open_prelude_with_manifest_key(
        prelude.file_nonce,
        prelude.manifest_ciphertext,
        &manifest_key,
    )
    .map_err(|_| AppError::DecryptionFailed)?;
    on_progress(PRELUDE_LEN as u64);
    decrypt_payload_after_prelude(
        reader,
        writer,
        encrypted_len,
        opened,
        AuthFailure::Password,
        on_progress,
    )
}

pub fn encrypt_pqc_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    plaintext_len: u64,
    recipient: &keys::RecipientPublicKeyBundle,
    config: &CryptoConfig,
    on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    pqc::ensure_enabled()?;
    validate_chunk_size(config.chunk_size)?;

    let mut file_nonce = [0u8; FILE_NONCE_LEN];
    let mut manifest_key = Zeroizing::new([0u8; KEY_LEN]);
    let mut file_secret = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut file_nonce);
    OsRng.fill_bytes(manifest_key.as_mut());
    OsRng.fill_bytes(file_secret.as_mut());

    let chunk_size = u64::try_from(config.chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let chunk_count = chunk_count(plaintext_len, chunk_size)?;
    expected_payload_len(plaintext_len, config.chunk_size)?;
    let manifest = ManifestV1 {
        version: FORMAT_VERSION,
        magic: INTERNAL_MAGIC.to_vec(),
        plaintext_len,
        chunk_size,
        chunk_count,
        tag_len: TAG_LEN as u16,
        file_secret: file_secret.as_ref().to_vec(),
    };
    let manifest_ciphertext = seal_manifest(&file_nonce, &manifest_key, &manifest)?;

    let mut slots = vec![0u8; SLOT_AREA_LEN];
    OsRng.fill_bytes(&mut slots);
    seal_pqc_slot(
        &mut slots[..SLOT_LEN],
        0,
        &file_nonce,
        &manifest_key,
        recipient,
    )?;

    writer.write_all(&file_nonce)?;
    writer.write_all(&slots)?;
    writer.write_all(&manifest_ciphertext)?;
    stream_encrypt_payload(
        reader,
        writer,
        PayloadEncryptParams {
            file_nonce: &file_nonce,
            manifest_ciphertext: &manifest_ciphertext,
            plaintext_len,
            chunk_size: config.chunk_size,
            chunk_count,
            file_secret: &file_secret,
        },
        on_progress,
    )
}

pub fn decrypt_pqc_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    encrypted_len: u64,
    identities: &[keys::RecipientSecretKeyBundle],
    mut on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    if identities.is_empty() {
        return Err(AppError::NoMatchingIdentity);
    }

    let prelude = read_prelude(reader, encrypted_len)
        .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
    let manifest_key = open_pqc_slots(&prelude.slots, &prelude.file_nonce, identities)?;
    let opened = open_prelude_with_manifest_key(
        prelude.file_nonce,
        prelude.manifest_ciphertext,
        &manifest_key,
    )
    .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
    on_progress(PRELUDE_LEN as u64);
    decrypt_payload_after_prelude(
        reader,
        writer,
        encrypted_len,
        opened,
        AuthFailure::Pqc,
        on_progress,
    )
}

struct RawPrelude {
    file_nonce: [u8; FILE_NONCE_LEN],
    slots: Vec<u8>,
    manifest_ciphertext: Vec<u8>,
}

fn read_prelude<R: Read>(reader: &mut R, encrypted_len: u64) -> Result<RawPrelude> {
    let min_len = (PRELUDE_LEN + TAG_LEN) as u64;
    if encrypted_len < min_len {
        return Err(AppError::DecryptionFailed);
    }

    let mut file_nonce = [0u8; FILE_NONCE_LEN];
    reader.read_exact(&mut file_nonce)?;
    let mut slots = vec![0u8; SLOT_AREA_LEN];
    reader.read_exact(&mut slots)?;
    let mut manifest_ciphertext = vec![0u8; MANIFEST_CIPHERTEXT_LEN];
    reader.read_exact(&mut manifest_ciphertext)?;
    Ok(RawPrelude {
        file_nonce,
        slots,
        manifest_ciphertext,
    })
}

fn open_prelude_with_manifest_key(
    file_nonce: [u8; FILE_NONCE_LEN],
    manifest_ciphertext: Vec<u8>,
    manifest_key: &[u8; KEY_LEN],
) -> Result<OpenedPrelude> {
    let manifest = open_manifest(&file_nonce, manifest_key, &manifest_ciphertext)?;
    validate_manifest(&manifest)?;
    Ok(OpenedPrelude {
        file_nonce,
        manifest_ciphertext,
        manifest,
        payload_offset: PRELUDE_LEN as u64,
    })
}

fn seal_password_slot(
    slot: &mut [u8],
    slot_index: usize,
    file_nonce: &[u8; FILE_NONCE_LEN],
    manifest_key: &[u8; KEY_LEN],
    password: &str,
) -> Result<()> {
    let root = derive_password_root(password, file_nonce)?;
    let slot_key = derive_key(root.as_ref(), file_nonce, slot_index, b"password slot key")?;
    let nonce = derive_nonce(
        root.as_ref(),
        file_nonce,
        slot_index,
        b"password slot nonce",
    )?;
    let aad = slot_aad(b"password", file_nonce, slot_index, &[]);
    let mut body = build_slot_body(ROLE_PASSWORD, manifest_key);
    let cipher =
        Aes256Gcm::new_from_slice(slot_key.as_ref()).map_err(|_| AppError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &body,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)?;
    slot[..ciphertext.len()].copy_from_slice(&ciphertext);
    body.zeroize();
    Ok(())
}

fn open_password_slots(
    slots: &[u8],
    file_nonce: &[u8; FILE_NONCE_LEN],
    password: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let root = derive_password_root(password, file_nonce)?;
    for slot_index in 0..SLOT_COUNT {
        let slot = slot_slice(slots, slot_index)?;
        let slot_key = derive_key(root.as_ref(), file_nonce, slot_index, b"password slot key")?;
        let nonce = derive_nonce(
            root.as_ref(),
            file_nonce,
            slot_index,
            b"password slot nonce",
        )?;
        let aad = slot_aad(b"password", file_nonce, slot_index, &[]);
        let cipher =
            Aes256Gcm::new_from_slice(slot_key.as_ref()).map_err(|_| AppError::DecryptionFailed)?;
        let Ok(mut body) = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &slot[..SLOT_CIPHERTEXT_LEN],
                aad: &aad,
            },
        ) else {
            continue;
        };
        let parsed = parse_slot_body(&body, ROLE_PASSWORD);
        body.zeroize();
        if let Some(key) = parsed {
            return Ok(key);
        }
    }
    Err(AppError::DecryptionFailed)
}

fn seal_pqc_slot(
    slot: &mut [u8],
    slot_index: usize,
    file_nonce: &[u8; FILE_NONCE_LEN],
    manifest_key: &[u8; KEY_LEN],
    recipient: &keys::RecipientPublicKeyBundle,
) -> Result<()> {
    if slot.len() < PQC_SLOT_MIN_LEN {
        return Err(AppError::InputTooLarge);
    }
    let recipient_mlkem_public = recipient.mlkem1024_public_bytes()?;
    let recipient_hqc_public = recipient.hqc256_public_bytes()?;
    let mut encapsulated =
        pqc::encapsulate_recipient(&recipient_mlkem_public, &recipient_hqc_public)?;
    if encapsulated.mlkem1024_ciphertext.len() != MLKEM1024_CT_LEN
        || encapsulated.hqc256_ciphertext.len() != HQC256_CT_LEN
    {
        return Err(AppError::EncryptionFailed);
    }

    slot[..MLKEM1024_CT_LEN].copy_from_slice(&encapsulated.mlkem1024_ciphertext);
    slot[MLKEM1024_CT_LEN..PQC_WRAP_OFFSET].copy_from_slice(&encapsulated.hqc256_ciphertext);

    let slot_key = derive_pqc_slot_key(
        file_nonce,
        slot_index,
        &encapsulated.mlkem1024_ciphertext,
        &encapsulated.mlkem1024_shared_secret,
        &encapsulated.hqc256_ciphertext,
        &encapsulated.hqc256_shared_secret,
        b"pqc slot key",
    )?;
    let nonce = derive_pqc_slot_nonce(
        file_nonce,
        slot_index,
        &encapsulated.mlkem1024_ciphertext,
        &encapsulated.mlkem1024_shared_secret,
        &encapsulated.hqc256_ciphertext,
        &encapsulated.hqc256_shared_secret,
        b"pqc slot nonce",
    )?;
    let aad = slot_aad(b"pqc", file_nonce, slot_index, &slot[..PQC_WRAP_OFFSET]);
    let mut body = build_slot_body(ROLE_PQC, manifest_key);
    let cipher =
        Aes256Gcm::new_from_slice(slot_key.as_ref()).map_err(|_| AppError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &body,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)?;
    slot[PQC_WRAP_OFFSET..PQC_WRAP_OFFSET + ciphertext.len()].copy_from_slice(&ciphertext);

    body.zeroize();
    encapsulated.mlkem1024_shared_secret.zeroize();
    encapsulated.hqc256_shared_secret.zeroize();
    Ok(())
}

fn open_pqc_slots(
    slots: &[u8],
    file_nonce: &[u8; FILE_NONCE_LEN],
    identities: &[keys::RecipientSecretKeyBundle],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    for identity in identities {
        let mlkem_secret = identity.mlkem1024_secret_bytes()?;
        let hqc_secret = identity.hqc256_secret_bytes()?;
        for slot_index in 0..SLOT_COUNT {
            let slot = slot_slice(slots, slot_index)?;
            let mlkem_ct = &slot[..MLKEM1024_CT_LEN];
            let hqc_ct = &slot[MLKEM1024_CT_LEN..PQC_WRAP_OFFSET];
            let Ok((mut mlkem_ss, mut hqc_ss)) =
                pqc::decapsulate_recipient(&mlkem_secret, &hqc_secret, mlkem_ct, hqc_ct)
            else {
                continue;
            };

            let result = open_pqc_slot_body(
                slot, slot_index, file_nonce, mlkem_ct, &mlkem_ss, hqc_ct, &hqc_ss,
            );
            mlkem_ss.zeroize();
            hqc_ss.zeroize();
            if let Some(key) = result? {
                return Ok(key);
            }
        }
    }
    Err(AppError::NoMatchingIdentity)
}

fn open_pqc_slot_body(
    slot: &[u8],
    slot_index: usize,
    file_nonce: &[u8; FILE_NONCE_LEN],
    mlkem_ct: &[u8],
    mlkem_ss: &[u8],
    hqc_ct: &[u8],
    hqc_ss: &[u8],
) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
    let slot_key = derive_pqc_slot_key(
        file_nonce,
        slot_index,
        mlkem_ct,
        mlkem_ss,
        hqc_ct,
        hqc_ss,
        b"pqc slot key",
    )?;
    let nonce = derive_pqc_slot_nonce(
        file_nonce,
        slot_index,
        mlkem_ct,
        mlkem_ss,
        hqc_ct,
        hqc_ss,
        b"pqc slot nonce",
    )?;
    let aad = slot_aad(b"pqc", file_nonce, slot_index, &slot[..PQC_WRAP_OFFSET]);
    let wrap = &slot[PQC_WRAP_OFFSET..PQC_WRAP_OFFSET + SLOT_CIPHERTEXT_LEN];
    let cipher = Aes256Gcm::new_from_slice(slot_key.as_ref())
        .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
    let Ok(mut body) = cipher.decrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: wrap,
            aad: &aad,
        },
    ) else {
        return Ok(None);
    };
    let parsed = parse_slot_body(&body, ROLE_PQC);
    body.zeroize();
    Ok(parsed)
}

fn build_slot_body(role: u8, manifest_key: &[u8; KEY_LEN]) -> [u8; SLOT_BODY_LEN] {
    let mut body = [0u8; SLOT_BODY_LEN];
    OsRng.fill_bytes(&mut body);
    body[..INTERNAL_MAGIC.len()].copy_from_slice(INTERNAL_MAGIC);
    body[16..18].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    body[18] = role;
    body[19..19 + KEY_LEN].copy_from_slice(manifest_key);
    body
}

fn parse_slot_body(body: &[u8], expected_role: u8) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    if body.len() != SLOT_BODY_LEN
        || &body[..INTERNAL_MAGIC.len()] != INTERNAL_MAGIC
        || u16::from_be_bytes(body[16..18].try_into().ok()?) != FORMAT_VERSION
        || body[18] != expected_role
    {
        return None;
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&body[19..19 + KEY_LEN]);
    Some(key)
}

fn seal_manifest(
    file_nonce: &[u8; FILE_NONCE_LEN],
    manifest_key: &[u8; KEY_LEN],
    manifest: &ManifestV1,
) -> Result<Vec<u8>> {
    let mut plaintext = encode_manifest_plaintext(manifest)?;
    let nonce = derive_nonce(manifest_key, file_nonce, 0, b"manifest nonce")?;
    let aad = manifest_aad(file_nonce);
    let cipher = Aes256Gcm::new_from_slice(manifest_key).map_err(|_| AppError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)?;
    plaintext.zeroize();
    if ciphertext.len() != MANIFEST_CIPHERTEXT_LEN {
        return Err(AppError::EncryptionFailed);
    }
    Ok(ciphertext)
}

fn open_manifest(
    file_nonce: &[u8; FILE_NONCE_LEN],
    manifest_key: &[u8; KEY_LEN],
    ciphertext: &[u8],
) -> Result<ManifestV1> {
    if ciphertext.len() != MANIFEST_CIPHERTEXT_LEN {
        return Err(AppError::DecryptionFailed);
    }
    let nonce = derive_nonce(manifest_key, file_nonce, 0, b"manifest nonce")?;
    let aad = manifest_aad(file_nonce);
    let cipher = Aes256Gcm::new_from_slice(manifest_key).map_err(|_| AppError::DecryptionFailed)?;
    let mut plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| AppError::DecryptionFailed)?;
    let manifest = decode_manifest_plaintext(&plaintext)?;
    plaintext.zeroize();
    Ok(manifest)
}

fn encode_manifest_plaintext(manifest: &ManifestV1) -> Result<[u8; MANIFEST_PLAINTEXT_LEN]> {
    let encoded = encode_cbor(manifest)?;
    if encoded.len() > u16::MAX as usize || encoded.len() + 2 > MANIFEST_PLAINTEXT_LEN {
        return Err(AppError::InputTooLarge);
    }
    let mut out = [0u8; MANIFEST_PLAINTEXT_LEN];
    OsRng.fill_bytes(&mut out);
    let len = encoded.len() as u16;
    out[..2].copy_from_slice(&len.to_be_bytes());
    out[2..2 + encoded.len()].copy_from_slice(&encoded);
    Ok(out)
}

fn decode_manifest_plaintext(plaintext: &[u8]) -> Result<ManifestV1> {
    if plaintext.len() != MANIFEST_PLAINTEXT_LEN {
        return Err(AppError::DecryptionFailed);
    }
    let mut len_bytes = [0u8; 2];
    len_bytes.copy_from_slice(&plaintext[..2]);
    let len = u16::from_be_bytes(len_bytes) as usize;
    if len == 0 || len + 2 > plaintext.len() {
        return Err(AppError::DecryptionFailed);
    }
    decode_cbor(&plaintext[2..2 + len])
}

fn validate_manifest(manifest: &ManifestV1) -> Result<()> {
    if manifest.version != FORMAT_VERSION
        || manifest.magic.as_slice() != INTERNAL_MAGIC
        || manifest.chunk_size == 0
        || manifest.chunk_size > MAX_CHUNK_SIZE
        || manifest.tag_len != TAG_LEN as u16
        || manifest.file_secret.len() != KEY_LEN
        || manifest.chunk_count != chunk_count(manifest.plaintext_len, manifest.chunk_size)?
    {
        return Err(AppError::DecryptionFailed);
    }
    Ok(())
}

struct PayloadEncryptParams<'a> {
    file_nonce: &'a [u8; FILE_NONCE_LEN],
    manifest_ciphertext: &'a [u8],
    plaintext_len: u64,
    chunk_size: usize,
    chunk_count: u64,
    file_secret: &'a [u8; KEY_LEN],
}

fn stream_encrypt_payload<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    params: PayloadEncryptParams<'_>,
    mut on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let payload_key = derive_key(params.file_secret, params.file_nonce, 0, b"payload key")?;
    let nonce_base = derive_payload_nonce_base(params.file_secret, params.file_nonce)?;
    let cipher =
        Aes256Gcm::new_from_slice(payload_key.as_ref()).map_err(|_| AppError::EncryptionFailed)?;
    let manifest_hash = Sha3_512::digest(params.manifest_ciphertext);
    let mut buffer = vec![0u8; params.chunk_size];
    let mut chunk_index = 0u64;
    let mut bytes_read_total = 0u64;

    if params.plaintext_len == 0 {
        let ciphertext = encrypt_payload_chunk(
            &cipher,
            &nonce_base,
            &manifest_hash,
            PayloadChunkAuth {
                chunk_index,
                plaintext_len: params.plaintext_len,
                chunk_count: params.chunk_count,
                is_final: true,
            },
            &[],
        )?;
        writer.write_all(&ciphertext)?;
        writer.flush()?;
        return Ok(());
    }

    loop {
        let read_bytes = read_plaintext_chunk(reader, &mut buffer)?;
        if read_bytes == 0 {
            break;
        }
        bytes_read_total = bytes_read_total
            .checked_add(read_bytes as u64)
            .ok_or(AppError::InputTooLarge)?;
        let is_final = chunk_index + 1 == params.chunk_count;
        let ciphertext = encrypt_payload_chunk(
            &cipher,
            &nonce_base,
            &manifest_hash,
            PayloadChunkAuth {
                chunk_index,
                plaintext_len: params.plaintext_len,
                chunk_count: params.chunk_count,
                is_final,
            },
            &buffer[..read_bytes],
        )?;
        writer.write_all(&ciphertext)?;
        on_progress(read_bytes as u64);
        buffer[..read_bytes].zeroize();
        chunk_index = chunk_index.checked_add(1).ok_or(AppError::InputTooLarge)?;
    }

    buffer.zeroize();
    if bytes_read_total != params.plaintext_len || chunk_index != params.chunk_count {
        return Err(AppError::InputChangedDuringProcessing);
    }
    writer.flush()?;
    Ok(())
}

fn read_plaintext_chunk<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize> {
    let mut read_total = 0usize;
    while read_total < buffer.len() {
        let read_bytes = reader.read(&mut buffer[read_total..])?;
        if read_bytes == 0 {
            break;
        }
        read_total = read_total
            .checked_add(read_bytes)
            .ok_or(AppError::InputTooLarge)?;
    }
    Ok(read_total)
}

fn decrypt_payload_after_prelude<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    encrypted_len: u64,
    opened: OpenedPrelude,
    auth_failure: AuthFailure,
    on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let chunk_size =
        usize::try_from(opened.manifest.chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let expected = expected_payload_len(opened.manifest.plaintext_len, chunk_size)?;
    let actual = encrypted_len
        .checked_sub(opened.payload_offset)
        .ok_or(AppError::InputTooLarge)?;
    if actual != expected {
        return Err(auth_failure.error());
    }
    let file_secret = slice_to_key(&opened.manifest.file_secret)?;
    stream_decrypt_payload(
        reader,
        writer,
        PayloadDecryptParams {
            file_nonce: &opened.file_nonce,
            manifest_ciphertext: &opened.manifest_ciphertext,
            plaintext_len: opened.manifest.plaintext_len,
            chunk_size,
            chunk_count: opened.manifest.chunk_count,
            file_secret: &file_secret,
            auth_failure,
        },
        on_progress,
    )
}

#[derive(Clone, Copy)]
enum AuthFailure {
    Password,
    Pqc,
}

impl AuthFailure {
    fn error(self) -> AppError {
        match self {
            Self::Password => AppError::DecryptionFailed,
            Self::Pqc => AppError::AsymmetricAuthenticationFailed,
        }
    }
}

struct PayloadDecryptParams<'a> {
    file_nonce: &'a [u8; FILE_NONCE_LEN],
    manifest_ciphertext: &'a [u8],
    plaintext_len: u64,
    chunk_size: usize,
    chunk_count: u64,
    file_secret: &'a [u8; KEY_LEN],
    auth_failure: AuthFailure,
}

fn stream_decrypt_payload<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    params: PayloadDecryptParams<'_>,
    mut on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    let payload_key = derive_key(params.file_secret, params.file_nonce, 0, b"payload key")?;
    let nonce_base = derive_payload_nonce_base(params.file_secret, params.file_nonce)?;
    let cipher =
        Aes256Gcm::new_from_slice(payload_key.as_ref()).map_err(|_| params.auth_failure.error())?;
    let manifest_hash = Sha3_512::digest(params.manifest_ciphertext);
    let chunk_size_u64 = u64::try_from(params.chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let full_chunks = params.plaintext_len / chunk_size_u64;
    let last_plain_len = params.plaintext_len % chunk_size_u64;
    let full_chunk_cipher_len = params
        .chunk_size
        .checked_add(TAG_LEN)
        .ok_or(AppError::InputTooLarge)?;
    let mut ciphertext_buffer = vec![0u8; full_chunk_cipher_len];

    for chunk_index in 0..params.chunk_count {
        let plain_len = if params.plaintext_len == 0 {
            0
        } else if chunk_index < full_chunks {
            params.chunk_size
        } else {
            usize::try_from(last_plain_len).map_err(|_| AppError::InputTooLarge)?
        };
        let current_cipher_len = plain_len
            .checked_add(TAG_LEN)
            .ok_or(AppError::InputTooLarge)?;
        let chunk = &mut ciphertext_buffer[..current_cipher_len];
        reader
            .read_exact(chunk)
            .map_err(|_| params.auth_failure.error())?;
        let is_final = chunk_index + 1 == params.chunk_count;
        let nonce = build_payload_nonce(&nonce_base, chunk_index);
        let aad = payload_aad(
            &manifest_hash,
            chunk_index,
            params.plaintext_len,
            params.chunk_count,
            plain_len as u64,
            is_final,
        );
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .map_err(|_| params.auth_failure.error())?;
        writer.write_all(&plaintext)?;
        on_progress(current_cipher_len as u64);
        plaintext.zeroize();
        chunk.zeroize();
    }

    ciphertext_buffer.zeroize();
    writer.flush()?;
    Ok(())
}

struct PayloadChunkAuth {
    chunk_index: u64,
    plaintext_len: u64,
    chunk_count: u64,
    is_final: bool,
}

fn encrypt_payload_chunk(
    cipher: &Aes256Gcm,
    nonce_base: &[u8; PAYLOAD_NONCE_BASE_LEN],
    manifest_hash: &[u8],
    auth: PayloadChunkAuth,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = build_payload_nonce(nonce_base, auth.chunk_index);
    let aad = payload_aad(
        manifest_hash,
        auth.chunk_index,
        auth.plaintext_len,
        auth.chunk_count,
        plaintext.len() as u64,
        auth.is_final,
    );
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

fn build_payload_nonce(
    nonce_base: &[u8; PAYLOAD_NONCE_BASE_LEN],
    chunk_index: u64,
) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..PAYLOAD_NONCE_BASE_LEN].copy_from_slice(nonce_base);
    nonce[PAYLOAD_NONCE_BASE_LEN..].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

fn payload_aad(
    manifest_hash: &[u8],
    chunk_index: u64,
    plaintext_len: u64,
    chunk_count: u64,
    chunk_plain_len: u64,
    is_final: bool,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + manifest_hash.len() + 8 * 4 + 1);
    aad.extend_from_slice(b"fcrypt opaque v1 payload chunk");
    aad.extend_from_slice(manifest_hash);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(&chunk_count.to_be_bytes());
    aad.extend_from_slice(&chunk_plain_len.to_be_bytes());
    aad.push(u8::from(is_final));
    aad
}

fn derive_password_root(
    password: &str,
    file_nonce: &[u8; FILE_NONCE_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(
        OPAQUE_V1_ARGON_MEMORY_KIB,
        OPAQUE_V1_ARGON_TIME_COST,
        OPAQUE_V1_ARGON_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|e| AppError::CryptoConfig(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), &file_nonce[..16], key.as_mut())
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(key)
}

fn derive_key(
    ikm: &[u8],
    file_nonce: &[u8; FILE_NONCE_LEN],
    index: usize,
    label: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let hk = HkdfSha3_512::new(Some(&kdf_salt(file_nonce, index)), ikm);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(label, out.as_mut())
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(out)
}

fn derive_nonce(
    ikm: &[u8],
    file_nonce: &[u8; FILE_NONCE_LEN],
    index: usize,
    label: &[u8],
) -> Result<[u8; NONCE_LEN]> {
    let hk = HkdfSha3_512::new(Some(&kdf_salt(file_nonce, index)), ikm);
    let mut out = [0u8; NONCE_LEN];
    hk.expand(label, &mut out)
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(out)
}

fn derive_payload_nonce_base(
    ikm: &[u8],
    file_nonce: &[u8; FILE_NONCE_LEN],
) -> Result<[u8; PAYLOAD_NONCE_BASE_LEN]> {
    let hk = HkdfSha3_512::new(Some(file_nonce), ikm);
    let mut out = [0u8; PAYLOAD_NONCE_BASE_LEN];
    hk.expand(b"payload nonce base", &mut out)
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(out)
}

fn derive_pqc_slot_key(
    file_nonce: &[u8; FILE_NONCE_LEN],
    slot_index: usize,
    mlkem_ct: &[u8],
    mlkem_ss: &[u8],
    hqc_ct: &[u8],
    hqc_ss: &[u8],
    label: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let hk = HkdfSha3_512::new(
        Some(&pqc_slot_salt(file_nonce, slot_index, mlkem_ct, hqc_ct)),
        &pqc_slot_ikm(mlkem_ss, hqc_ss),
    );
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(label, out.as_mut())
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(out)
}

fn derive_pqc_slot_nonce(
    file_nonce: &[u8; FILE_NONCE_LEN],
    slot_index: usize,
    mlkem_ct: &[u8],
    mlkem_ss: &[u8],
    hqc_ct: &[u8],
    hqc_ss: &[u8],
    label: &[u8],
) -> Result<[u8; NONCE_LEN]> {
    let hk = HkdfSha3_512::new(
        Some(&pqc_slot_salt(file_nonce, slot_index, mlkem_ct, hqc_ct)),
        &pqc_slot_ikm(mlkem_ss, hqc_ss),
    );
    let mut out = [0u8; NONCE_LEN];
    hk.expand(label, &mut out)
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(out)
}

fn kdf_salt(file_nonce: &[u8; FILE_NONCE_LEN], index: usize) -> Vec<u8> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(b"fcrypt opaque v1");
    salt.extend_from_slice(file_nonce);
    salt.extend_from_slice(&(index as u64).to_be_bytes());
    salt
}

fn pqc_slot_salt(
    file_nonce: &[u8; FILE_NONCE_LEN],
    slot_index: usize,
    mlkem_ct: &[u8],
    hqc_ct: &[u8],
) -> Vec<u8> {
    let mut salt = Vec::with_capacity(64 + mlkem_ct.len() + hqc_ct.len());
    salt.extend_from_slice(b"fcrypt opaque v1 pqc slot");
    salt.extend_from_slice(file_nonce);
    salt.extend_from_slice(&(slot_index as u64).to_be_bytes());
    salt.extend_from_slice(mlkem_ct);
    salt.extend_from_slice(hqc_ct);
    salt
}

fn pqc_slot_ikm(mlkem_ss: &[u8], hqc_ss: &[u8]) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(mlkem_ss.len() + hqc_ss.len() + 16);
    ikm.extend_from_slice(&(mlkem_ss.len() as u64).to_be_bytes());
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(&(hqc_ss.len() as u64).to_be_bytes());
    ikm.extend_from_slice(hqc_ss);
    ikm
}

fn manifest_aad(file_nonce: &[u8; FILE_NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(b"fcrypt opaque v1 manifest");
    aad.extend_from_slice(file_nonce);
    aad
}

fn slot_aad(
    domain: &[u8],
    file_nonce: &[u8; FILE_NONCE_LEN],
    slot_index: usize,
    slot_public_material: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + slot_public_material.len());
    aad.extend_from_slice(b"fcrypt opaque v1 slot");
    aad.extend_from_slice(domain);
    aad.extend_from_slice(file_nonce);
    aad.extend_from_slice(&(slot_index as u64).to_be_bytes());
    aad.extend_from_slice(slot_public_material);
    aad
}

fn slot_slice(slots: &[u8], slot_index: usize) -> Result<&[u8]> {
    let start = slot_index
        .checked_mul(SLOT_LEN)
        .ok_or(AppError::InputTooLarge)?;
    let end = start.checked_add(SLOT_LEN).ok_or(AppError::InputTooLarge)?;
    slots.get(start..end).ok_or(AppError::DecryptionFailed)
}

fn slice_to_key(bytes: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if bytes.len() != KEY_LEN {
        return Err(AppError::DecryptionFailed);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(bytes);
    Ok(key)
}

fn validate_chunk_size(chunk_size: usize) -> Result<()> {
    if chunk_size == 0 {
        return Err(AppError::InvalidChunkSize);
    }
    let chunk_size = u64::try_from(chunk_size).map_err(|_| AppError::InputTooLarge)?;
    if chunk_size > MAX_CHUNK_SIZE {
        return Err(AppError::InputTooLarge);
    }
    Ok(())
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

fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|e| AppError::Serialization(e.to_string()))?;
    Ok(bytes)
}

fn decode_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    ciborium::de::from_reader(bytes).map_err(|e| AppError::Serialization(e.to_string()))
}
