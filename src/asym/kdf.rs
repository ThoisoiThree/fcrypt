use hkdf::Hkdf;
use sha3::Sha3_512;
use zeroize::Zeroizing;

use crate::error::{AppError, Result};

type HkdfSha3_512 = Hkdf<Sha3_512>;

pub struct WrapKeys {
    pub wrap_key: Zeroizing<[u8; 32]>,
    pub wrap_nonce: [u8; 12],
}

pub struct FileKeys {
    pub aead_key: Zeroizing<[u8; 32]>,
    pub nonce_base: [u8; 8],
}

pub fn derive_wrap_keys(
    suite_id: &str,
    file_id: &[u8],
    mlkem_ciphertext: &[u8],
    mlkem_shared_secret: &[u8],
    hqc_ciphertext: &[u8],
    hqc_shared_secret: &[u8],
) -> Result<WrapKeys> {
    let mut salt = Vec::new();
    salt.extend_from_slice(b"fcrypt-fe-v1 recipient combiner");
    salt.extend_from_slice(file_id);
    salt.extend_from_slice(suite_id.as_bytes());

    let mut ikm = Zeroizing::new(Vec::new());
    append_labeled(ikm.as_mut(), b"ML-KEM-1024", mlkem_ciphertext)?;
    append_labeled(ikm.as_mut(), b"ML-KEM-1024-SS", mlkem_shared_secret)?;
    append_labeled(ikm.as_mut(), b"HQC-256", hqc_ciphertext)?;
    append_labeled(ikm.as_mut(), b"HQC-256-SS", hqc_shared_secret)?;

    let hk = HkdfSha3_512::new(Some(&salt), ikm.as_slice());
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"fcrypt-fe-v1 recipient wrap key", wrap_key.as_mut())
        .map_err(|_| AppError::KeyDerivationFailed)?;
    let mut wrap_nonce = [0u8; 12];
    hk.expand(b"fcrypt-fe-v1 recipient wrap nonce", &mut wrap_nonce)
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(WrapKeys {
        wrap_key,
        wrap_nonce,
    })
}

pub fn derive_file_keys(suite_id: &str, file_id: &[u8], file_secret: &[u8]) -> Result<FileKeys> {
    let mut salt = Vec::new();
    salt.extend_from_slice(b"fcrypt-fe-v1 file secret");
    salt.extend_from_slice(file_id);
    salt.extend_from_slice(suite_id.as_bytes());
    let hk = HkdfSha3_512::new(Some(&salt), file_secret);

    let mut aead_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"fcrypt-fe-v1 aes-256-gcm file key", aead_key.as_mut())
        .map_err(|_| AppError::KeyDerivationFailed)?;
    let mut nonce_base = [0u8; 8];
    hk.expand(b"fcrypt-fe-v1 aes-256-gcm nonce base", &mut nonce_base)
        .map_err(|_| AppError::KeyDerivationFailed)?;
    Ok(FileKeys {
        aead_key,
        nonce_base,
    })
}

fn append_labeled(out: &mut Vec<u8>, label: &[u8], value: &[u8]) -> Result<()> {
    let label_len = u64::try_from(label.len()).map_err(|_| AppError::InputTooLarge)?;
    let value_len = u64::try_from(value.len()).map_err(|_| AppError::InputTooLarge)?;
    out.extend_from_slice(&label_len.to_be_bytes());
    out.extend_from_slice(label);
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
