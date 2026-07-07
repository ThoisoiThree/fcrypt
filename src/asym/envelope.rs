use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSection {
    pub alg: String,
    pub signer_key_id: String,
    pub transcript_hash_alg: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub version: u16,
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: String,
    pub signer_key_id: String,
    pub transcript_hash_alg: String,
    pub signature: String,
}

pub fn ciphertext_hash_from_reader<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut hasher = Sha3_512::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read_bytes = reader.read(&mut buffer)?;
        if read_bytes == 0 {
            break;
        }
        hasher.update(&buffer[..read_bytes]);
    }
    Ok(hasher.finalize().to_vec())
}

pub fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)
        .map_err(|e| AppError::Serialization(e.to_string()))?;
    Ok(bytes)
}

pub fn decode_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    ciborium::de::from_reader(bytes).map_err(|e| AppError::Serialization(e.to_string()))
}

pub fn detached_signature_path(input: &Path) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .ok_or_else(|| AppError::MissingFileName(input.to_path_buf()))?;
    let mut sig_name = file_name.to_os_string();
    sig_name.push(".sig");
    Ok(input.with_file_name(sig_name))
}

pub fn detached_signature_to_section(detached: DetachedSignature) -> Result<SignatureSection> {
    if detached.version != 1
        || detached.kind != "fcrypt-opaque-detached-signature"
        || detached.alg != "ML-DSA-87"
        || detached.transcript_hash_alg != "SHA3-512"
    {
        return Err(AppError::InvalidAsymmetricFile(
            "invalid detached signature file".to_string(),
        ));
    }
    let signature = STANDARD
        .decode(detached.signature.as_bytes())
        .map_err(|_| AppError::InvalidAsymmetricFile("invalid detached signature".to_string()))?;
    Ok(SignatureSection {
        alg: detached.alg,
        signer_key_id: detached.signer_key_id,
        transcript_hash_alg: detached.transcript_hash_alg,
        signature,
    })
}

pub fn signature_section_to_detached(section: &SignatureSection) -> DetachedSignature {
    DetachedSignature {
        version: 1,
        kind: "fcrypt-opaque-detached-signature".to_string(),
        alg: section.alg.clone(),
        signer_key_id: section.signer_key_id.clone(),
        transcript_hash_alg: section.transcript_hash_alg.clone(),
        signature: STANDARD.encode(&section.signature),
    }
}

pub fn output_parent_dir(output_path: &Path) -> PathBuf {
    output_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn persist_temp_file(
    temp_file: NamedTempFile,
    output_path: &Path,
    allow_overwrite: bool,
) -> Result<()> {
    let result = if allow_overwrite {
        temp_file.persist(output_path)
    } else {
        temp_file.persist_noclobber(output_path)
    };

    result.map(|_| ()).map_err(|e| {
        if e.error.kind() == std::io::ErrorKind::AlreadyExists {
            AppError::OutputExists(output_path.to_path_buf())
        } else {
            AppError::Io(e.error)
        }
    })
}
