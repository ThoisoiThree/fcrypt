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
use crate::sym::cleanup::TrackedTempFile;

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
    temp_file: TrackedTempFile,
    allow_overwrite: Option<bool>,
}

impl StagedFile {
    pub(crate) fn new(temp_file: TrackedTempFile, output_path: &Path) -> Self {
        Self {
            output_path: output_path.to_path_buf(),
            temp_file,
            allow_overwrite: None,
        }
    }

    pub(crate) fn with_overwrite(mut self, allow_overwrite: bool) -> Self {
        self.allow_overwrite = Some(allow_overwrite);
        self
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
    temp_file: TrackedTempFile,
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
                if !staged.allow_overwrite.unwrap_or(allow_overwrite) {
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
        if let Err(error) = staged.temp_file.persist(&output_path, existed) {
            if let Err(rollback_error) = rollback_committed_files(committed) {
                return Err(AppError::Io(io::Error::new(
                    rollback_error.kind(),
                    format!(
                        "failed to publish {}: {}; rollback also failed: {}",
                        output_path.display(),
                        error,
                        rollback_error
                    ),
                )));
            }
            return Err(map_persist_error(error, output_path));
        }
        committed.push((output_path, backup));
    }
    Ok(())
}

/// Backups are deliberately untracked by the interrupt handler: they may be
/// the only copy of a replaced file and must survive an interrupted rollback.
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
    let mut first_error_kind = None;
    let mut errors = Vec::new();
    while let Some((path, backup)) = committed.pop() {
        let result = match backup {
            Some(backup) => backup.persist(&path).map(|_| ()).map_err(|error| {
                let kind = error.error.kind();
                let reason = error.error;
                let backup_path = error.file.path().to_path_buf();
                // PersistError owns the only remaining copy of the old file.
                // Preserve it even if making the temporary file permanent fails.
                let keep_error = match error.file.keep() {
                    Ok(_) => String::new(),
                    Err(mut error) => {
                        error.file.disable_cleanup(true);
                        format!("; could not finalize recovery file: {}", error.error)
                    }
                };
                io::Error::new(
                    kind,
                    format!(
                        "failed to restore {}: {}; recovery backup retained at {}{}",
                        path.display(),
                        reason,
                        backup_path.display(),
                        keep_error
                    ),
                )
            }),
            None => fs::remove_file(&path),
        };
        if let Err(error) = result {
            first_error_kind.get_or_insert(error.kind());
            errors.push(error.to_string());
        }
    }
    match first_error_kind {
        Some(kind) => Err(io::Error::new(kind, errors.join("; "))),
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn failed_rollback_retains_all_backups_and_restores_other_files() {
        let dir = tempdir().expect("temporary directory must be created");
        let restored = dir.path().join("restored.sec");
        fs::write(&restored, b"old key").expect("old key must be written");
        let restored_backup = stage_backup(&restored).expect("backup must be staged");
        let restored_backup_path = restored_backup.path().to_path_buf();
        fs::write(&restored, b"new key").expect("key must be replaced");
        let new_file = dir.path().join("new.pub");
        fs::write(&new_file, b"new public key").expect("new file must be written");
        let mut committed = vec![
            (restored.clone(), Some(restored_backup)),
            (new_file.clone(), None),
        ];
        let mut recovery_paths = Vec::new();
        for name in ["first.sec", "second.sec"] {
            let path = dir.path().join(name);
            fs::write(&path, b"original secret").expect("original must be written");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("secret permissions must be set");
            }
            let backup = stage_backup(&path).expect("backup must be staged");
            recovery_paths.push(backup.path().to_path_buf());
            fs::remove_file(&path).expect("original must be removed");
            fs::create_dir(&path).expect("directory must block restoration");
            committed.push((path, Some(backup)));
        }

        let error = rollback_committed_files(committed).expect_err("restoration must fail");
        for path in recovery_paths {
            assert_eq!(
                fs::read(&path).expect("backup must survive"),
                b"original secret"
            );
            assert!(error.to_string().contains(&path.display().to_string()));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert_eq!(
            fs::read(restored).expect("old key must be restored"),
            b"old key"
        );
        assert!(!restored_backup_path.exists());
        assert!(!new_file.exists());
    }

    #[test]
    fn per_file_overwrite_denial_survives_transaction_force() {
        let dir = tempdir().expect("temporary directory must be created");
        let key_path = dir.path().join("identity.sec");
        fs::write(&key_path, b"existing key").expect("key must be written");
        let staged = StagedFile::new(TrackedTempFile::new_in(dir.path()).unwrap(), &key_path)
            .with_overwrite(false);
        assert!(matches!(
            persist_staged_files(vec![staged], true),
            Err(AppError::OutputExists(_))
        ));
        assert_eq!(fs::read(key_path).unwrap(), b"existing key");
    }
}
