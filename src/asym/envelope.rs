use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::error::{AppError, Result};

pub const MAGIC: &[u8; 8] = b"FCRYPTFE";
pub const FORMAT_VERSION: u16 = 1;
pub const SUITE_ID: &str = "fcrypt-fe-v1-default-mlkem1024-hqc256-hkdfsha3-512-aes256gcm";
pub const LEGACY_PARANOID_SUITE_ID: &str =
    "fcrypt-fe-v1-paranoid-mlkem1024-hqc256-hkdfsha3-512-aes256gcm";
pub const SIGNATURE_DOMAIN: &[u8] = b"fcrypt-fe-v1 outer signature";
pub const AES_GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderV1 {
    pub version: u16,
    pub suite_id: String,
    #[serde(with = "serde_bytes")]
    pub file_id: Vec<u8>,
    pub chunk_size: u64,
    pub plaintext_len: Option<u64>,
    pub created_at: Option<String>,
    pub recipient: RecipientSection,
    pub aead: AeadSection,
    pub signature: Option<SignatureSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientSection {
    pub key_id: String,
    pub label8: Option<String>,
    pub kems: Vec<KemCiphertext>,
    #[serde(with = "serde_bytes")]
    pub wrapped_file_secret: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemCiphertext {
    pub alg: String,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadSection {
    pub alg: String,
    pub nonce_mode: String,
    pub chunk_size: u64,
    #[serde(with = "serde_bytes")]
    pub header_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSection {
    pub alg: String,
    pub signer_key_id: String,
    pub transcript_hash_alg: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientWrapContext {
    pub key_id: String,
    pub label8: Option<String>,
    pub kems: Vec<KemCiphertext>,
    pub wrap_alg: String,
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

pub struct EnvelopeReader {
    pub header: HeaderV1,
    pub payload_offset: u64,
    pub file_len: u64,
}

pub fn is_fe_file(path: &Path) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 8];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(&magic == MAGIC),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(AppError::Io(error)),
    }
}

pub fn read_envelope(path: &Path) -> Result<EnvelopeReader> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .map_err(|_| AppError::InvalidAsymmetricFile("missing FCRYPTFE magic".to_string()))?;
    if &magic != MAGIC {
        return Err(AppError::NotAsymmetricFile(path.display().to_string()));
    }

    let mut version_bytes = [0u8; 2];
    file.read_exact(&mut version_bytes)
        .map_err(|_| AppError::InvalidAsymmetricFile("missing .fe version".to_string()))?;
    let version = u16::from_be_bytes(version_bytes);
    if version != FORMAT_VERSION {
        return Err(AppError::UnsupportedFeVersion(version));
    }

    let mut header_len_bytes = [0u8; 4];
    file.read_exact(&mut header_len_bytes)
        .map_err(|_| AppError::InvalidAsymmetricFile("missing .fe header length".to_string()))?;
    let header_len = u32::from_be_bytes(header_len_bytes) as usize;
    if header_len == 0 {
        return Err(AppError::InvalidAsymmetricFile(
            "empty .fe header".to_string(),
        ));
    }

    let prelude_len = (MAGIC.len() + 2 + 4) as u64;
    let header_end = prelude_len
        .checked_add(header_len as u64)
        .ok_or(AppError::InputTooLarge)?;
    if header_end > file_len {
        return Err(AppError::InvalidAsymmetricFile(
            "truncated .fe header".to_string(),
        ));
    }

    let mut header_bytes = vec![0u8; header_len];
    file.read_exact(&mut header_bytes)
        .map_err(|_| AppError::InvalidAsymmetricFile("truncated .fe header".to_string()))?;
    let header = decode_cbor(&header_bytes)?;
    Ok(EnvelopeReader {
        header,
        payload_offset: header_end,
        file_len,
    })
}

pub fn write_envelope<W: Write>(writer: &mut W, header: &HeaderV1) -> Result<()> {
    let header_bytes = encode_cbor(header)?;
    let header_len = u32::try_from(header_bytes.len()).map_err(|_| AppError::InputTooLarge)?;
    writer.write_all(MAGIC)?;
    writer.write_all(&FORMAT_VERSION.to_be_bytes())?;
    writer.write_all(&header_len.to_be_bytes())?;
    writer.write_all(&header_bytes)?;
    Ok(())
}

pub fn open_payload_reader(path: &Path, payload_offset: u64) -> Result<BufReader<File>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(payload_offset))?;
    Ok(BufReader::new(file))
}

pub fn validate_header(header: &HeaderV1) -> Result<()> {
    if header.version != FORMAT_VERSION {
        return Err(AppError::UnsupportedFeVersion(header.version));
    }
    if header.suite_id != SUITE_ID && header.suite_id != LEGACY_PARANOID_SUITE_ID {
        return Err(AppError::InvalidAsymmetricFile(format!(
            "unsupported suite: {}",
            header.suite_id
        )));
    }
    if header.file_id.len() != 32 {
        return Err(AppError::InvalidAsymmetricFile(
            "file_id must be 32 bytes".to_string(),
        ));
    }
    if header.chunk_size == 0 || header.chunk_size > u32::MAX as u64 {
        return Err(AppError::InvalidAsymmetricFile(
            "invalid chunk size".to_string(),
        ));
    }
    if header.aead.alg != "AES-256-GCM"
        || header.aead.nonce_mode != "derived-base-plus-chunk-index"
        || header.aead.chunk_size != header.chunk_size
    {
        return Err(AppError::InvalidAsymmetricFile(
            "invalid AEAD section".to_string(),
        ));
    }
    if header.aead.header_hash.len() != 64 {
        return Err(AppError::InvalidAsymmetricFile(
            "invalid header hash length".to_string(),
        ));
    }
    if header.recipient.kems.len() != 2
        || header.recipient.kems[0].alg != "ML-KEM-1024"
        || header.recipient.kems[1].alg != "HQC-256"
    {
        return Err(AppError::InvalidAsymmetricFile(
            "invalid recipient KEM list".to_string(),
        ));
    }

    let expected = header_hash(header)?;
    if header.aead.header_hash != expected {
        return Err(AppError::InvalidAsymmetricFile(
            "header hash verification failed".to_string(),
        ));
    }
    Ok(())
}

pub fn header_hash(header: &HeaderV1) -> Result<Vec<u8>> {
    let mut unsigned = header.clone();
    unsigned.signature = None;
    unsigned.aead.header_hash.clear();
    let encoded = encode_cbor(&unsigned)?;
    Ok(Sha3_512::digest(&encoded).to_vec())
}

pub fn recipient_wrap_context(header: &HeaderV1) -> RecipientWrapContext {
    RecipientWrapContext {
        key_id: header.recipient.key_id.clone(),
        label8: header.recipient.label8.clone(),
        kems: header.recipient.kems.clone(),
        wrap_alg: "AES-256-GCM".to_string(),
    }
}

pub fn recipient_wrap_aad(header: &HeaderV1) -> Result<Vec<u8>> {
    encode_cbor(&recipient_wrap_context(header))
}

pub fn signature_transcript(header: &HeaderV1, ciphertext_hash: &[u8]) -> Result<Vec<u8>> {
    let mut unsigned = header.clone();
    unsigned.signature = None;
    let header_bytes = encode_cbor(&unsigned)?;
    let mut transcript =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + header_bytes.len() + ciphertext_hash.len());
    transcript.extend_from_slice(SIGNATURE_DOMAIN);
    transcript.extend_from_slice(&header_bytes);
    transcript.extend_from_slice(ciphertext_hash);
    Ok(transcript)
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

pub fn payload_len(reader: &EnvelopeReader) -> Result<u64> {
    reader
        .file_len
        .checked_sub(reader.payload_offset)
        .ok_or_else(|| AppError::InvalidAsymmetricFile("invalid payload offset".to_string()))
}

pub fn expected_payload_len(plaintext_len: u64, chunk_size: usize) -> Result<u64> {
    let tag_len = AES_GCM_TAG_LEN as u64;
    if plaintext_len == 0 {
        return Ok(tag_len);
    }

    let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| AppError::InputTooLarge)?;
    let full_chunks = plaintext_len / chunk_size_u64;
    let last_plain_len = plaintext_len % chunk_size_u64;
    let full_chunk_cipher_len = chunk_size_u64
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
        || detached.kind != "fcrypt-fe-detached-signature"
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
        kind: "fcrypt-fe-detached-signature".to_string(),
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
        if e.error.kind() == io::ErrorKind::AlreadyExists {
            AppError::OutputExists(output_path.to_path_buf())
        } else {
            AppError::Io(e.error)
        }
    })
}
