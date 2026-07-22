use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::collections::HashSet;
use std::fs;
use std::io;
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

pub(crate) struct StagedFile {
    output_path: PathBuf,
    temp_file: NamedTempFile,
}

impl StagedFile {
    pub(crate) fn new(temp_file: NamedTempFile, output_path: &Path) -> Self {
        Self {
            output_path: output_path.to_path_buf(),
            temp_file,
        }
    }
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
    persist_staged_files(
        vec![StagedFile::new(temp_file, output_path)],
        allow_overwrite,
    )
}

pub(crate) fn persist_staged_files(
    staged_files: Vec<StagedFile>,
    allow_overwrite: bool,
) -> Result<()> {
    let mut seen_paths = HashSet::with_capacity(staged_files.len());
    let mut output_existed = Vec::with_capacity(staged_files.len());
    for staged in &staged_files {
        if !seen_paths.insert(staged.output_path.clone()) {
            return Err(AppError::InvalidArgument(format!(
                "duplicate output path in one transaction: {}",
                staged.output_path.display()
            )));
        }
        match fs::symlink_metadata(&staged.output_path) {
            Ok(metadata) => {
                if !allow_overwrite {
                    return Err(AppError::OutputExists(staged.output_path.clone()));
                }
                if !metadata.file_type().is_file() {
                    return Err(AppError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "output path is not a regular file: {}",
                            staged.output_path.display()
                        ),
                    )));
                }
                output_existed.push(true);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => output_existed.push(false),
            Err(error) => return Err(AppError::Io(error)),
        }
    }

    let mut pending = Vec::with_capacity(staged_files.len());
    for (staged, existed) in staged_files.into_iter().zip(output_existed) {
        let backup = if existed {
            Some(stage_backup(&staged.output_path)?)
        } else {
            None
        };
        pending.push((staged, backup, existed));
    }

    let mut committed = Vec::with_capacity(pending.len());
    for (staged, backup, existed) in pending {
        let output_path = staged.output_path.clone();
        let persist_result = if existed {
            staged.temp_file.persist(&output_path)
        } else {
            staged.temp_file.persist_noclobber(&output_path)
        };
        if let Err(error) = persist_result {
            if let Err(rollback_error) = rollback_committed_files(committed) {
                return Err(AppError::Io(io::Error::new(
                    rollback_error.kind(),
                    format!(
                        "failed to publish {}: {}; rollback also failed: {}",
                        output_path.display(),
                        error.error,
                        rollback_error
                    ),
                )));
            }
            return Err(map_persist_error(error.error, output_path));
        }
        committed.push((output_path, backup));
    }
    Ok(())
}

fn stage_backup(path: &Path) -> Result<NamedTempFile> {
    let metadata = fs::metadata(path)?;
    let mut backup = NamedTempFile::new_in(output_parent_dir(path))?;
    fs::copy(path, backup.path())?;
    backup
        .as_file_mut()
        .set_permissions(metadata.permissions())?;
    backup.as_file_mut().sync_all()?;
    Ok(backup)
}

fn rollback_committed_files(
    mut committed: Vec<(PathBuf, Option<NamedTempFile>)>,
) -> io::Result<()> {
    let mut first_error = None;
    while let Some((path, backup)) = committed.pop() {
        let result = match backup {
            Some(backup) => backup.persist(&path).map(|_| ()).map_err(|e| e.error),
            None => fs::remove_file(&path),
        };
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn map_persist_error(error: io::Error, output_path: PathBuf) -> AppError {
    if error.kind() == io::ErrorKind::AlreadyExists {
        AppError::OutputExists(output_path)
    } else {
        AppError::Io(error)
    }
}
