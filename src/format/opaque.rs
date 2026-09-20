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

use aes_gcm::aead::{Aead, AeadInPlace, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::fmt;
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

use crate::asym::{keys, pqc};
use crate::error::{AppError, Result};
use crate::sym::crypto::CryptoConfig;
use crate::sym::parallel;

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
/// Maximum ciphertext chunk held in memory while decrypting opaque v1 files.
/// AES-GCM authentication requires one complete chunk, so larger chunks are
/// rejected before allocation. This is a reader resource policy, not a format
/// change: the opaque v1 manifest still accepts chunk sizes up to 1 GiB.
pub const MAX_DECRYPT_CHUNK_BUFFER_LEN: usize = 64 * 1024 * 1024;
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
const SIGNATURE_REQUIREMENT_OFFSET: usize = 19 + KEY_LEN;
const SIGNATURE_REQUIREMENT_MARKER: &[u8; 13] = b"fcrypt-sig-v1";
const SIGNER_KEY_ID_LEN: usize = 32;
const SIGNER_KEY_ID_OFFSET: usize =
    SIGNATURE_REQUIREMENT_OFFSET + SIGNATURE_REQUIREMENT_MARKER.len();

type HkdfSha3_512 = Hkdf<Sha3_512>;

#[derive(Serialize, Deserialize)]
struct ManifestV1 {
    version: u16,
    #[serde(with = "serde_bytes")]
    magic: Vec<u8>,
    plaintext_len: u64,
    chunk_size: u64,
    chunk_count: u64,
    tag_len: u16,
    file_secret: SecretKey,
}

struct SecretKey([u8; KEY_LEN]);

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecretKeyVisitor;

        impl<'de> Visitor<'de> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "exactly {KEY_LEN} secret-key bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: DeError,
            {
                let bytes: [u8; KEY_LEN] = value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))?;
                Ok(SecretKey(bytes))
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> std::result::Result<Self::Value, E>
            where
                E: DeError,
            {
                let value = Zeroizing::new(value);
                self.visit_bytes(value.as_ref())
            }
        }

        deserializer.deserialize_bytes(SecretKeyVisitor)
    }
}

impl fmt::Debug for ManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestV1")
            .field("version", &self.version)
            .field("magic", &self.magic)
            .field("plaintext_len", &self.plaintext_len)
            .field("chunk_size", &self.chunk_size)
            .field("chunk_count", &self.chunk_count)
            .field("tag_len", &self.tag_len)
            .field("file_secret", &"<redacted>")
            .finish()
    }
}

impl Drop for ManifestV1 {
    fn drop(&mut self) {
        self.magic.zeroize();
    }
}

#[derive(Debug)]
struct OpenedPrelude {
    file_nonce: [u8; FILE_NONCE_LEN],
    manifest_ciphertext: Vec<u8>,
    manifest: ManifestV1,
    payload_offset: u64,
}

pub struct PqcDecryptMetadata {
    pub required_signer_key_id: Option<String>,
}

struct OpenedPqcSlot {
    manifest_key: Zeroizing<[u8; KEY_LEN]>,
    required_signer_key_id: Option<String>,
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
    if password.is_empty() {
        return Err(AppError::EmptyPassword);
    }
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
        file_secret: SecretKey(*file_secret),
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
    encrypt_pqc_stream_with_signer(
        reader,
        writer,
        plaintext_len,
        recipient,
        None,
        config,
        on_progress,
    )
}

pub fn encrypt_pqc_stream_with_signer<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    plaintext_len: u64,
    recipient: &keys::RecipientPublicKeyBundle,
    required_signer_key_id: Option<&str>,
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
    let required_signer_key_id = required_signer_key_id
        .map(decode_signer_key_id)
        .transpose()?;

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
        file_secret: SecretKey(*file_secret),
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
        required_signer_key_id.as_ref(),
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
) -> Result<PqcDecryptMetadata>
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
    let opened_slot = open_pqc_slots(&prelude.slots, &prelude.file_nonce, identities)?;
    let opened = open_prelude_with_manifest_key(
        prelude.file_nonce,
        prelude.manifest_ciphertext,
        &opened_slot.manifest_key,
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
    )?;
    Ok(PqcDecryptMetadata {
        required_signer_key_id: opened_slot.required_signer_key_id,
    })
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
    let body = Zeroizing::new(build_slot_body(ROLE_PASSWORD, manifest_key));
    let cipher =
        Aes256Gcm::new_from_slice(slot_key.as_ref()).map_err(|_| AppError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: body.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)?;
    slot[..ciphertext.len()].copy_from_slice(&ciphertext);
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
        let Ok(body) = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &slot[..SLOT_CIPHERTEXT_LEN],
                aad: &aad,
            },
        ) else {
            continue;
        };
        let body = Zeroizing::new(body);
        let parsed = parse_slot_body(body.as_ref(), ROLE_PASSWORD);
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
    required_signer_key_id: Option<&[u8; SIGNER_KEY_ID_LEN]>,
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
    let mut body = Zeroizing::new(build_slot_body(ROLE_PQC, manifest_key));
    if let Some(signer_key_id) = required_signer_key_id {
        body[SIGNATURE_REQUIREMENT_OFFSET..SIGNER_KEY_ID_OFFSET]
            .copy_from_slice(SIGNATURE_REQUIREMENT_MARKER);
        body[SIGNER_KEY_ID_OFFSET..SIGNER_KEY_ID_OFFSET + SIGNER_KEY_ID_LEN]
            .copy_from_slice(signer_key_id);
    }
    let cipher =
        Aes256Gcm::new_from_slice(slot_key.as_ref()).map_err(|_| AppError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: body.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)?;
    slot[PQC_WRAP_OFFSET..PQC_WRAP_OFFSET + ciphertext.len()].copy_from_slice(&ciphertext);

    encapsulated.mlkem1024_shared_secret.zeroize();
    encapsulated.hqc256_shared_secret.zeroize();
    Ok(())
}

fn open_pqc_slots(
    slots: &[u8],
    file_nonce: &[u8; FILE_NONCE_LEN],
    identities: &[keys::RecipientSecretKeyBundle],
) -> Result<OpenedPqcSlot> {
    for identity in identities {
        let mlkem_secret = identity.mlkem1024_secret_bytes()?;
        let hqc_secret = identity.hqc256_secret_bytes()?;
        for slot_index in 0..SLOT_COUNT {
            let slot = slot_slice(slots, slot_index)?;
            let mlkem_ct = &slot[..MLKEM1024_CT_LEN];
            let hqc_ct = &slot[MLKEM1024_CT_LEN..PQC_WRAP_OFFSET];
            let Ok((mut mlkem_ss, mut hqc_ss)) = pqc::decapsulate_recipient(
                mlkem_secret.as_ref(),
                hqc_secret.as_ref(),
                mlkem_ct,
                hqc_ct,
            ) else {
                continue;
            };

            let result = open_pqc_slot_body(
                slot, slot_index, file_nonce, mlkem_ct, &mlkem_ss, hqc_ct, &hqc_ss,
            );
            mlkem_ss.zeroize();
            hqc_ss.zeroize();
            if let Some(opened) = result? {
                return Ok(opened);
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
) -> Result<Option<OpenedPqcSlot>> {
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
    let Ok(body) = cipher.decrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: wrap,
            aad: &aad,
        },
    ) else {
        return Ok(None);
    };
    let body = Zeroizing::new(body);
    let parsed = parse_pqc_slot_body(body.as_ref());
    Ok(parsed)
}

fn parse_pqc_slot_body(body: &[u8]) -> Option<OpenedPqcSlot> {
    let manifest_key = parse_slot_body(body, ROLE_PQC)?;
    let required_signer_key_id = (&body[SIGNATURE_REQUIREMENT_OFFSET..SIGNER_KEY_ID_OFFSET]
        == SIGNATURE_REQUIREMENT_MARKER)
        .then(|| {
            hex::encode(&body[SIGNER_KEY_ID_OFFSET..SIGNER_KEY_ID_OFFSET + SIGNER_KEY_ID_LEN])
        });
    Some(OpenedPqcSlot {
        manifest_key,
        required_signer_key_id,
    })
}

fn decode_signer_key_id(key_id: &str) -> Result<[u8; SIGNER_KEY_ID_LEN]> {
    let mut bytes = [0u8; SIGNER_KEY_ID_LEN];
    hex::decode_to_slice(key_id, &mut bytes).map_err(|_| {
        AppError::InvalidAsymmetricKeyFile(
            "signing key_id must contain exactly 64 hexadecimal characters".to_string(),
        )
    })?;
    Ok(bytes)
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
    let plaintext = encode_manifest_plaintext(manifest)?;
    let nonce = derive_nonce(manifest_key, file_nonce, 0, b"manifest nonce")?;
    let aad = manifest_aad(file_nonce);
    let cipher = Aes256Gcm::new_from_slice(manifest_key).map_err(|_| AppError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| AppError::EncryptionFailed)?;
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
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| AppError::DecryptionFailed)?,
    );
    decode_manifest_plaintext(plaintext.as_ref())
}

fn encode_manifest_plaintext(
    manifest: &ManifestV1,
) -> Result<Zeroizing<[u8; MANIFEST_PLAINTEXT_LEN]>> {
    let encoded = Zeroizing::new(encode_cbor(manifest)?);
    if encoded.len() > u16::MAX as usize || encoded.len() + 2 > MANIFEST_PLAINTEXT_LEN {
        return Err(AppError::InputTooLarge);
    }
    let mut out = Zeroizing::new([0u8; MANIFEST_PLAINTEXT_LEN]);
    OsRng.fill_bytes(out.as_mut());
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

    let buffer_len = usize::try_from(
        params
            .plaintext_len
            .min(u64::try_from(params.chunk_size).map_err(|_| AppError::InputTooLarge)?),
    )
    .map_err(|_| AppError::InputTooLarge)?;
    let workers = parallel::workers(buffer_len.saturating_add(TAG_LEN), params.chunk_count);
    if workers > 1 {
        parallel::ordered(
            params.chunk_count,
            workers,
            |index| {
                let remaining = params.plaintext_len - index * params.chunk_size as u64;
                let len = remaining.min(params.chunk_size as u64) as usize;
                let mut buffer = Zeroizing::new(Vec::new());
                buffer
                    .try_reserve_exact(len)
                    .map_err(|_| AppError::InputTooLarge)?;
                buffer.resize(len, 0);
                if read_plaintext_chunk(reader, &mut buffer)? != len {
                    return Err(AppError::InputChangedDuringProcessing);
                }
                Ok(buffer)
            },
            |index, buffer| {
                let len = buffer.len();
                let ciphertext = encrypt_payload_chunk(
                    &cipher,
                    &nonce_base,
                    &manifest_hash,
                    PayloadChunkAuth {
                        chunk_index: index,
                        plaintext_len: params.plaintext_len,
                        chunk_count: params.chunk_count,
                        is_final: index + 1 == params.chunk_count,
                    },
                    &buffer,
                )?;
                Ok((ciphertext, len))
            },
            |(ciphertext, len)| {
                writer.write_all(&ciphertext)?;
                on_progress(len as u64);
                Ok(())
            },
        )?;
        let mut extra = Zeroizing::new([0u8; 1]);
        if read_plaintext_chunk(reader, extra.as_mut())? != 0 {
            return Err(AppError::InputChangedDuringProcessing);
        }
        writer.flush()?;
        return Ok(());
    }
    let mut buffer = Zeroizing::new(Vec::new());
    buffer
        .try_reserve_exact(buffer_len)
        .map_err(|_| AppError::InputTooLarge)?;
    buffer.resize(buffer_len, 0);

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
    let file_secret = slice_to_key(opened.manifest.file_secret.as_ref())?;
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
    let mut ciphertext_buffer = Zeroizing::new(Vec::new());

    if params.plaintext_len == 0 {
        decrypt_payload_chunk(
            reader,
            writer,
            &cipher,
            &nonce_base,
            &manifest_hash,
            &mut ciphertext_buffer,
            &params,
            0,
            0,
            true,
        )?;
        on_progress(TAG_LEN as u64);
        writer.flush()?;
        return Ok(());
    }

    let max_plain = params.plaintext_len.min(chunk_size_u64) as usize;
    let workers = parallel::workers(max_plain.saturating_add(TAG_LEN), params.chunk_count);
    if workers > 1 {
        parallel::ordered(
            params.chunk_count,
            workers,
            |index| {
                let len =
                    (params.plaintext_len - index * chunk_size_u64).min(chunk_size_u64) as usize;
                let mut buffer = Zeroizing::new(Vec::new());
                resize_decryption_buffer(&mut buffer, len + TAG_LEN)?;
                reader
                    .read_exact(&mut buffer)
                    .map_err(|_| params.auth_failure.error())?;
                Ok(buffer)
            },
            |index, mut buffer| {
                let cipher_len = buffer.len();
                let nonce = build_payload_nonce(&nonce_base, index);
                let aad = payload_aad(
                    &manifest_hash,
                    index,
                    params.plaintext_len,
                    params.chunk_count,
                    (cipher_len - TAG_LEN) as u64,
                    index + 1 == params.chunk_count,
                );
                cipher
                    .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut *buffer)
                    .map_err(|_| params.auth_failure.error())?;
                Ok((buffer, cipher_len))
            },
            |(buffer, cipher_len)| {
                writer.write_all(&buffer)?;
                on_progress(cipher_len as u64);
                Ok(())
            },
        )?;
        writer.flush()?;
        return Ok(());
    }

    for chunk_index in 0..params.chunk_count {
        let chunk_offset = chunk_index
            .checked_mul(chunk_size_u64)
            .ok_or(AppError::InputTooLarge)?;
        let remaining = params
            .plaintext_len
            .checked_sub(chunk_offset)
            .ok_or_else(|| params.auth_failure.error())?;
        let plain_len =
            usize::try_from(remaining.min(chunk_size_u64)).map_err(|_| AppError::InputTooLarge)?;
        let current_cipher_len = plain_len
            .checked_add(TAG_LEN)
            .ok_or(AppError::InputTooLarge)?;
        let is_final = chunk_index + 1 == params.chunk_count;
        decrypt_payload_chunk(
            reader,
            writer,
            &cipher,
            &nonce_base,
            &manifest_hash,
            &mut ciphertext_buffer,
            &params,
            chunk_index,
            plain_len,
            is_final,
        )?;
        on_progress(current_cipher_len as u64);
    }

    ciphertext_buffer.zeroize();
    writer.flush()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decrypt_payload_chunk<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cipher: &Aes256Gcm,
    nonce_base: &[u8; PAYLOAD_NONCE_BASE_LEN],
    manifest_hash: &[u8],
    ciphertext_buffer: &mut Vec<u8>,
    params: &PayloadDecryptParams<'_>,
    chunk_index: u64,
    plain_len: usize,
    is_final: bool,
) -> Result<()> {
    let cipher_len = plain_len
        .checked_add(TAG_LEN)
        .ok_or(AppError::InputTooLarge)?;
    resize_decryption_buffer(ciphertext_buffer, cipher_len)?;
    reader
        .read_exact(ciphertext_buffer)
        .map_err(|_| params.auth_failure.error())?;
    let nonce = build_payload_nonce(nonce_base, chunk_index);
    let aad = payload_aad(
        manifest_hash,
        chunk_index,
        params.plaintext_len,
        params.chunk_count,
        plain_len as u64,
        is_final,
    );
    cipher
        .decrypt_in_place(Nonce::from_slice(&nonce), &aad, ciphertext_buffer)
        .map_err(|_| params.auth_failure.error())?;
    debug_assert_eq!(ciphertext_buffer.len(), plain_len);
    let write_result = writer.write_all(ciphertext_buffer);
    ciphertext_buffer.zeroize();
    write_result?;
    Ok(())
}

fn resize_decryption_buffer(buffer: &mut Vec<u8>, required: usize) -> Result<()> {
    if required > MAX_DECRYPT_CHUNK_BUFFER_LEN {
        return Err(AppError::DecryptionMemoryLimitExceeded {
            required,
            limit: MAX_DECRYPT_CHUNK_BUFFER_LEN,
        });
    }
    if required > buffer.capacity() {
        buffer
            .try_reserve_exact(required - buffer.len())
            .map_err(|_| AppError::DecryptionMemoryLimitExceeded {
                required,
                limit: MAX_DECRYPT_CHUNK_BUFFER_LEN,
            })?;
    }
    buffer.resize(required, 0);
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
    let ikm = Zeroizing::new(pqc_slot_ikm(mlkem_ss, hqc_ss));
    let hk = HkdfSha3_512::new(
        Some(&pqc_slot_salt(file_nonce, slot_index, mlkem_ct, hqc_ct)),
        ikm.as_ref(),
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
    let ikm = Zeroizing::new(pqc_slot_ikm(mlkem_ss, hqc_ss));
    let hk = HkdfSha3_512::new(
        Some(&pqc_slot_salt(file_nonce, slot_index, mlkem_ct, hqc_ct)),
        ikm.as_ref(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct LegacyManifestEncoding {
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

    #[test]
    fn manifest_secret_is_redacted_and_keeps_v1_encoding() {
        let manifest = ManifestV1 {
            version: FORMAT_VERSION,
            magic: INTERNAL_MAGIC.to_vec(),
            plaintext_len: 1,
            chunk_size: 4096,
            chunk_count: 1,
            tag_len: TAG_LEN as u16,
            file_secret: SecretKey([0xa5; KEY_LEN]),
        };
        let legacy = LegacyManifestEncoding {
            version: FORMAT_VERSION,
            magic: INTERNAL_MAGIC.to_vec(),
            plaintext_len: 1,
            chunk_size: 4096,
            chunk_count: 1,
            tag_len: TAG_LEN as u16,
            file_secret: vec![0xa5; KEY_LEN],
        };

        let debug = format!("{manifest:?}");
        assert!(debug.contains("file_secret: \"<redacted>\""));
        assert!(!debug.contains("165"));

        let encoded = encode_cbor(&manifest).expect("manifest must encode");
        let legacy_encoded = encode_cbor(&legacy).expect("legacy manifest must encode");
        assert_eq!(encoded, legacy_encoded);

        let decoded: ManifestV1 = decode_cbor(&encoded).expect("manifest must decode");
        assert_eq!(decoded.file_secret.as_ref(), &[0xa5; KEY_LEN]);
    }

    #[test]
    fn decryption_buffer_uses_actual_chunk_length() {
        let mut buffer = Vec::new();

        resize_decryption_buffer(&mut buffer, TAG_LEN).expect("empty payload tag must fit");
        assert_eq!(buffer.len(), TAG_LEN);

        resize_decryption_buffer(&mut buffer, TAG_LEN + 1)
            .expect("one-byte payload chunk must fit");
        assert_eq!(buffer.len(), TAG_LEN + 1);
    }

    #[test]
    fn oversized_decryption_buffer_is_rejected_before_allocation() {
        let mut buffer = Vec::new();
        let required = MAX_DECRYPT_CHUNK_BUFFER_LEN + 1;

        let error = resize_decryption_buffer(&mut buffer, required)
            .expect_err("chunk above the memory budget must be rejected");

        assert!(matches!(
            error,
            AppError::DecryptionMemoryLimitExceeded {
                required: actual,
                limit: MAX_DECRYPT_CHUNK_BUFFER_LEN,
            } if actual == required
        ));
        assert!(buffer.is_empty());
        assert_eq!(buffer.capacity(), 0);
    }

    #[test]
    fn parallel_payload_is_byte_identical_and_detects_changed_input() {
        let file_nonce = [7u8; FILE_NONCE_LEN];
        let manifest_ciphertext = [11u8; MANIFEST_CIPHERTEXT_LEN];
        let file_secret = [13u8; KEY_LEN];
        for len in [0, 1, 64, 65, 64 * 9, 64 * 9 + 13] {
            let plaintext = vec![42; len];
            let encrypt = |threads, data: &[u8]| {
                let mut result = Vec::new();
                parallel::with_threads(threads, || {
                    stream_encrypt_payload(
                        &mut &*data,
                        &mut result,
                        PayloadEncryptParams {
                            file_nonce: &file_nonce,
                            manifest_ciphertext: &manifest_ciphertext,
                            plaintext_len: len as u64,
                            chunk_size: 64,
                            chunk_count: chunk_count(len as u64, 64).unwrap(),
                            file_secret: &file_secret,
                        },
                        |_| {},
                    )
                })?;
                Ok::<_, AppError>(result)
            };
            assert_eq!(
                encrypt(1, &plaintext).unwrap(),
                encrypt(4, &plaintext).unwrap()
            );
            if len > 64 {
                assert!(matches!(
                    encrypt(4, &plaintext[..len - 1]),
                    Err(AppError::InputChangedDuringProcessing)
                ));
                let longer = vec![42; len + 1];
                assert!(matches!(
                    encrypt(4, &longer),
                    Err(AppError::InputChangedDuringProcessing)
                ));
            }
        }
    }

    #[test]
    fn maximum_declared_chunk_roundtrips_tiny_and_empty_payloads() {
        for plaintext in [b"".as_slice(), b"x".as_slice()] {
            let file_nonce = [7u8; FILE_NONCE_LEN];
            let manifest_ciphertext = vec![11u8; MANIFEST_CIPHERTEXT_LEN];
            let file_secret = [13u8; KEY_LEN];
            let chunk_size = MAX_CHUNK_SIZE as usize;
            let mut reader = plaintext;
            let mut encrypted = Vec::new();

            stream_encrypt_payload(
                &mut reader,
                &mut encrypted,
                PayloadEncryptParams {
                    file_nonce: &file_nonce,
                    manifest_ciphertext: &manifest_ciphertext,
                    plaintext_len: plaintext.len() as u64,
                    chunk_size,
                    chunk_count: 1,
                    file_secret: &file_secret,
                },
                |_| {},
            )
            .expect("tiny payload must encrypt without a declared-size allocation");
            assert_eq!(encrypted.len(), plaintext.len() + TAG_LEN);

            let mut encrypted_reader = encrypted.as_slice();
            let mut decrypted = Vec::new();
            stream_decrypt_payload(
                &mut encrypted_reader,
                &mut decrypted,
                PayloadDecryptParams {
                    file_nonce: &file_nonce,
                    manifest_ciphertext: &manifest_ciphertext,
                    plaintext_len: plaintext.len() as u64,
                    chunk_size,
                    chunk_count: 1,
                    file_secret: &file_secret,
                    auth_failure: AuthFailure::Password,
                },
                |_| {},
            )
            .expect("tiny payload must decrypt using its actual chunk length");
            assert_eq!(decrypted, plaintext);
        }
    }
}
