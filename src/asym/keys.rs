use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

use crate::asym::{envelope, pqc};
use crate::error::{AppError, Result};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const RECIPIENT_MODE: &str = "default";
pub const MAX_AUTO_DISCOVERED_RECIPIENT_IDENTITIES: usize = 32;
pub const MAX_ASYMMETRIC_KEY_FILE_BYTES: u64 = 64 * 1024;

pub struct RecipientSecretKeyLoad {
    pub identities: Vec<RecipientSecretKeyBundle>,
    pub skipped_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientAlgorithms {
    pub kem_1: String,
    pub kem_2: String,
    pub kdf: String,
    pub aead: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientPublicKeyBundle {
    pub version: u16,
    #[serde(rename = "type")]
    pub kind: String,
    pub mode: String,
    pub algorithms: RecipientAlgorithms,
    pub label8: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    pub mlkem1024_public: String,
    pub hqc256_public: String,
}

#[derive(Serialize, Deserialize)]
pub struct RecipientSecretKeyBundle {
    pub version: u16,
    #[serde(rename = "type")]
    pub kind: String,
    pub mode: String,
    pub algorithms: RecipientAlgorithms,
    pub label8: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    pub mlkem1024_secret: SecretString,
    pub hqc256_secret: SecretString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningPublicKeyBundle {
    pub version: u16,
    #[serde(rename = "type")]
    pub kind: String,
    pub algorithm: String,
    pub hash: String,
    pub label8: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    pub mldsa87_public: String,
}

#[derive(Serialize, Deserialize)]
pub struct SigningSecretKeyBundle {
    pub version: u16,
    #[serde(rename = "type")]
    pub kind: String,
    pub algorithm: String,
    pub hash: String,
    pub label8: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    pub mldsa87_secret: SecretString,
}

/// A serialized secret that is wiped when its owning key bundle is dropped.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl fmt::Debug for RecipientSecretKeyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecipientSecretKeyBundle")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("mode", &self.mode)
            .field("algorithms", &self.algorithms)
            .field("label8", &self.label8)
            .field("key_id", &self.key_id)
            .field("created_at_unix", &self.created_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("mlkem1024_secret", &self.mlkem1024_secret)
            .field("hqc256_secret", &self.hqc256_secret)
            .finish()
    }
}

impl fmt::Debug for SigningSecretKeyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningSecretKeyBundle")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("algorithm", &self.algorithm)
            .field("hash", &self.hash)
            .field("label8", &self.label8)
            .field("key_id", &self.key_id)
            .field("created_at_unix", &self.created_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("mldsa87_secret", &self.mldsa87_secret)
            .finish()
    }
}

pub struct GeneratedRecipientKeys {
    pub public: RecipientPublicKeyBundle,
    pub secret: RecipientSecretKeyBundle,
    pub public_path: PathBuf,
    pub secret_path: PathBuf,
}

pub struct GeneratedSigningKeys {
    pub public: SigningPublicKeyBundle,
    pub secret: SigningSecretKeyBundle,
    pub public_path: PathBuf,
    pub secret_path: PathBuf,
}

pub struct GeneratedKeyPair {
    pub recipient_public_path: PathBuf,
    pub recipient_secret_path: PathBuf,
    pub signing_public_path: PathBuf,
    pub signing_secret_path: PathBuf,
}

#[derive(Clone, Copy)]
struct KeyLifetime {
    created_at_unix: Option<u64>,
    expires_at_unix: Option<u64>,
}

#[derive(Serialize)]
struct RecipientPublicMaterial<'a> {
    version: u16,
    #[serde(rename = "type")]
    kind: &'static str,
    mode: &'a str,
    algorithms: RecipientAlgorithms,
    #[serde(with = "serde_bytes")]
    mlkem1024_public: &'a [u8],
    #[serde(with = "serde_bytes")]
    hqc256_public: &'a [u8],
}

#[derive(Serialize)]
struct SigningPublicMaterial<'a> {
    version: u16,
    #[serde(rename = "type")]
    kind: &'static str,
    algorithm: &'static str,
    hash: &'static str,
    #[serde(with = "serde_bytes")]
    mldsa87_public: &'a [u8],
}

impl RecipientPublicKeyBundle {
    pub fn mlkem1024_public_bytes(&self) -> Result<Vec<u8>> {
        decode_base64(&self.mlkem1024_public, "mlkem1024_public")
    }

    pub fn hqc256_public_bytes(&self) -> Result<Vec<u8>> {
        decode_base64(&self.hqc256_public, "hqc256_public")
    }
}

impl RecipientSecretKeyBundle {
    pub fn mlkem1024_secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        decode_base64(self.mlkem1024_secret.as_str(), "mlkem1024_secret").map(Zeroizing::new)
    }

    pub fn hqc256_secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        decode_base64(self.hqc256_secret.as_str(), "hqc256_secret").map(Zeroizing::new)
    }

    pub fn is_expired(&self) -> bool {
        is_expired(self.expires_at_unix)
    }
}

impl SigningPublicKeyBundle {
    pub fn mldsa87_public_bytes(&self) -> Result<Vec<u8>> {
        decode_base64(&self.mldsa87_public, "mldsa87_public")
    }

    pub fn is_expired(&self) -> bool {
        is_expired(self.expires_at_unix)
    }
}

impl SigningSecretKeyBundle {
    pub fn mldsa87_secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        decode_base64(self.mldsa87_secret.as_str(), "mldsa87_secret").map(Zeroizing::new)
    }
}

impl RecipientPublicKeyBundle {
    pub fn is_expired(&self) -> bool {
        is_expired(self.expires_at_unix)
    }
}

pub fn generate_recipient_key_files(
    keys_dir: &Path,
    force: bool,
) -> Result<GeneratedRecipientKeys> {
    pqc::ensure_enabled()?;
    prepare_keys_dir(keys_dir)?;
    let keypair = pqc::generate_recipient_keypair()?;
    let material =
        canonical_recipient_public_material(&keypair.mlkem1024_public, &keypair.hqc256_public)?;
    let key_id = key_id_hex(&material);
    let label8 = generate_label8(&material, keys_dir)?;
    let algorithms = recipient_algorithms();

    let public = RecipientPublicKeyBundle {
        version: 1,
        kind: "recipient-public".to_string(),
        mode: RECIPIENT_MODE.to_string(),
        algorithms: algorithms.clone(),
        label8: label8.clone(),
        key_id: key_id.clone(),
        created_at_unix: None,
        expires_at_unix: None,
        mlkem1024_public: STANDARD.encode(&keypair.mlkem1024_public),
        hqc256_public: STANDARD.encode(&keypair.hqc256_public),
    };
    let secret = RecipientSecretKeyBundle {
        version: 1,
        kind: "recipient-secret".to_string(),
        mode: RECIPIENT_MODE.to_string(),
        algorithms,
        label8: label8.clone(),
        key_id,
        created_at_unix: None,
        expires_at_unix: None,
        mlkem1024_secret: SecretString::new(STANDARD.encode(&keypair.mlkem1024_secret)),
        hqc256_secret: SecretString::new(STANDARD.encode(&keypair.hqc256_secret)),
    };

    let public_path = keys_dir.join(format!("{label8}_recipient_default.pub"));
    let secret_path = keys_dir.join(format!("{label8}_recipient_default.sec"));
    let staged_files = vec![
        stage_json_file(&public_path, &public, false)?,
        stage_json_file(&secret_path, &secret, true)?,
    ];
    envelope::persist_staged_files(staged_files, force)?;

    Ok(GeneratedRecipientKeys {
        public,
        secret,
        public_path,
        secret_path,
    })
}

pub fn generate_signing_key_files(keys_dir: &Path, force: bool) -> Result<GeneratedSigningKeys> {
    pqc::ensure_enabled()?;
    prepare_keys_dir(keys_dir)?;
    let keypair = pqc::generate_signing_keypair()?;
    let material = canonical_signing_public_material(&keypair.mldsa87_public)?;
    let key_id = key_id_hex(&material);
    let label8 = generate_label8(&material, keys_dir)?;

    let public = SigningPublicKeyBundle {
        version: 1,
        kind: "signer-public".to_string(),
        algorithm: "ML-DSA-87".to_string(),
        hash: "SHA3-512".to_string(),
        label8: label8.clone(),
        key_id: key_id.clone(),
        created_at_unix: None,
        expires_at_unix: None,
        mldsa87_public: STANDARD.encode(&keypair.mldsa87_public),
    };
    let secret = SigningSecretKeyBundle {
        version: 1,
        kind: "signer-secret".to_string(),
        algorithm: "ML-DSA-87".to_string(),
        hash: "SHA3-512".to_string(),
        label8: label8.clone(),
        key_id,
        created_at_unix: None,
        expires_at_unix: None,
        mldsa87_secret: SecretString::new(STANDARD.encode(&keypair.mldsa87_secret)),
    };

    let public_path = keys_dir.join(format!("{label8}_signer_mldsa87.pub"));
    let secret_path = keys_dir.join(format!("{label8}_signer_mldsa87.sec"));
    let staged_files = vec![
        stage_json_file(&public_path, &public, false)?,
        stage_json_file(&secret_path, &secret, true)?,
    ];
    envelope::persist_staged_files(staged_files, force)?;

    Ok(GeneratedSigningKeys {
        public,
        secret,
        public_path,
        secret_path,
    })
}

pub fn generate_named_key_pair_files(
    keys_dir: &Path,
    name: &str,
    lifetime_days: Option<u64>,
    force: bool,
) -> Result<GeneratedKeyPair> {
    pqc::ensure_enabled()?;
    validate_key_file_name(name)?;
    prepare_keys_dir(keys_dir)?;
    let recipient_public_path = keys_dir.join(format!("{name}_recipient_default.pub"));
    let recipient_secret_path = keys_dir.join(format!("{name}_recipient_default.sec"));
    let signing_public_path = keys_dir.join(format!("{name}_signer_mldsa87.pub"));
    let signing_secret_path = keys_dir.join(format!("{name}_signer_mldsa87.sec"));
    preflight_output_paths(
        &[
            &recipient_public_path,
            &recipient_secret_path,
            &signing_public_path,
            &signing_secret_path,
        ],
        force,
    )?;
    let lifetime = key_lifetime(lifetime_days)?;

    let recipient_keypair = pqc::generate_recipient_keypair()?;
    let recipient_material = canonical_recipient_public_material(
        &recipient_keypair.mlkem1024_public,
        &recipient_keypair.hqc256_public,
    )?;
    let recipient_key_id = key_id_hex(&recipient_material);
    let recipient_label8 = recipient_key_id[..8].to_string();
    let recipient_algorithms = recipient_algorithms();
    let recipient_public = RecipientPublicKeyBundle {
        version: 1,
        kind: "recipient-public".to_string(),
        mode: RECIPIENT_MODE.to_string(),
        algorithms: recipient_algorithms.clone(),
        label8: recipient_label8.clone(),
        key_id: recipient_key_id.clone(),
        created_at_unix: lifetime.created_at_unix,
        expires_at_unix: lifetime.expires_at_unix,
        mlkem1024_public: STANDARD.encode(&recipient_keypair.mlkem1024_public),
        hqc256_public: STANDARD.encode(&recipient_keypair.hqc256_public),
    };
    let recipient_secret = RecipientSecretKeyBundle {
        version: 1,
        kind: "recipient-secret".to_string(),
        mode: RECIPIENT_MODE.to_string(),
        algorithms: recipient_algorithms,
        label8: recipient_label8,
        key_id: recipient_key_id,
        created_at_unix: lifetime.created_at_unix,
        expires_at_unix: lifetime.expires_at_unix,
        mlkem1024_secret: SecretString::new(STANDARD.encode(&recipient_keypair.mlkem1024_secret)),
        hqc256_secret: SecretString::new(STANDARD.encode(&recipient_keypair.hqc256_secret)),
    };

    let signing_keypair = pqc::generate_signing_keypair()?;
    let signing_material = canonical_signing_public_material(&signing_keypair.mldsa87_public)?;
    let signing_key_id = key_id_hex(&signing_material);
    let signing_label8 = signing_key_id[..8].to_string();
    let signing_public = SigningPublicKeyBundle {
        version: 1,
        kind: "signer-public".to_string(),
        algorithm: "ML-DSA-87".to_string(),
        hash: "SHA3-512".to_string(),
        label8: signing_label8.clone(),
        key_id: signing_key_id.clone(),
        created_at_unix: lifetime.created_at_unix,
        expires_at_unix: lifetime.expires_at_unix,
        mldsa87_public: STANDARD.encode(&signing_keypair.mldsa87_public),
    };
    let signing_secret = SigningSecretKeyBundle {
        version: 1,
        kind: "signer-secret".to_string(),
        algorithm: "ML-DSA-87".to_string(),
        hash: "SHA3-512".to_string(),
        label8: signing_label8,
        key_id: signing_key_id,
        created_at_unix: lifetime.created_at_unix,
        expires_at_unix: lifetime.expires_at_unix,
        mldsa87_secret: SecretString::new(STANDARD.encode(&signing_keypair.mldsa87_secret)),
    };

    let staged_files = vec![
        stage_json_file(&recipient_public_path, &recipient_public, false)?,
        stage_json_file(&recipient_secret_path, &recipient_secret, true)?,
        stage_json_file(&signing_public_path, &signing_public, false)?,
        stage_json_file(&signing_secret_path, &signing_secret, true)?,
    ];
    envelope::persist_staged_files(staged_files, force)?;

    Ok(GeneratedKeyPair {
        recipient_public_path,
        recipient_secret_path,
        signing_public_path,
        signing_secret_path,
    })
}

pub fn read_recipient_public_key(path: &Path) -> Result<RecipientPublicKeyBundle> {
    let bundle: RecipientPublicKeyBundle = read_json(path)?;
    validate_recipient_public_key(&bundle)?;
    Ok(bundle)
}

pub fn read_recipient_secret_key(path: &Path) -> Result<RecipientSecretKeyBundle> {
    let bundle: RecipientSecretKeyBundle = read_json(path)?;
    validate_recipient_secret_key(&bundle)?;
    Ok(bundle)
}

pub fn read_signing_public_key(path: &Path) -> Result<SigningPublicKeyBundle> {
    let bundle: SigningPublicKeyBundle = read_json(path)?;
    validate_signing_public_key(&bundle)?;
    Ok(bundle)
}

pub fn read_signing_secret_key(path: &Path) -> Result<SigningSecretKeyBundle> {
    let bundle: SigningSecretKeyBundle = read_json(path)?;
    validate_signing_secret_key(&bundle)?;
    Ok(bundle)
}

pub fn find_recipient_secret_key(
    keys_dir: &Path,
    recipient_key_id: &str,
) -> Result<RecipientSecretKeyBundle> {
    if !keys_dir.exists() {
        return Err(AppError::NoMatchingIdentity);
    }

    let mut matches = Vec::new();
    for entry in fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_recipient_secret_key_file_name)
        {
            continue;
        }
        let bundle = match read_recipient_secret_key(&path) {
            Ok(bundle) => bundle,
            Err(AppError::InvalidAsymmetricKeyFile(_)) => continue,
            Err(error) => return Err(error),
        };
        if bundle.key_id == recipient_key_id {
            matches.push(bundle);
        }
    }

    match matches.len() {
        0 => Err(AppError::NoMatchingIdentity),
        1 => Ok(matches.remove(0)),
        _ => Err(AppError::MultipleMatchingIdentities),
    }
}

pub fn read_recipient_secret_keys(keys_dir: &Path) -> Result<Vec<RecipientSecretKeyBundle>> {
    Ok(read_recipient_secret_keys_with_diagnostics(keys_dir)?.identities)
}

pub fn read_recipient_secret_keys_with_diagnostics(
    keys_dir: &Path,
) -> Result<RecipientSecretKeyLoad> {
    if !keys_dir.exists() {
        return Err(AppError::NoMatchingIdentity);
    }

    let mut identity_paths = Vec::new();
    for entry in fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_recipient_secret_key_file_name)
        {
            continue;
        }
        identity_paths.push(path);
    }

    if identity_paths.is_empty() {
        return Err(AppError::NoMatchingIdentity);
    }
    if identity_paths.len() > MAX_AUTO_DISCOVERED_RECIPIENT_IDENTITIES {
        return Err(AppError::TooManyRecipientIdentities {
            found: identity_paths.len(),
            limit: MAX_AUTO_DISCOVERED_RECIPIENT_IDENTITIES,
        });
    }

    identity_paths.sort();
    let mut identities = Vec::new();
    let mut skipped_paths = Vec::new();
    for path in identity_paths {
        match read_recipient_secret_key(&path) {
            Ok(bundle) => identities.push(bundle),
            Err(AppError::InvalidAsymmetricKeyFile(_)) => skipped_paths.push(path),
            Err(error) => return Err(error),
        }
    }
    if identities.is_empty() {
        return Err(AppError::NoMatchingIdentity);
    }
    Ok(RecipientSecretKeyLoad {
        identities,
        skipped_paths,
    })
}

pub fn write_json_atomic<T: Serialize>(
    path: &Path,
    value: &T,
    secret: bool,
    force: bool,
) -> Result<()> {
    preflight_output_paths(&[path], force)?;
    let staged = stage_json_file(path, value, secret)?;
    envelope::persist_staged_files(vec![staged], force)
}

pub(crate) fn stage_json_file<T: Serialize>(
    path: &Path,
    value: &T,
    secret: bool,
) -> Result<envelope::StagedFile> {
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&dir)?;
    let mut temp = NamedTempFile::new_in(&dir)?;
    {
        let mut writer = BufWriter::new(temp.as_file_mut());
        serde_json::to_writer_pretty(&mut writer, value)
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }

    #[cfg(unix)]
    {
        let mode = if secret { 0o600 } else { 0o644 };
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(mode))?;
    }

    temp.as_file_mut().sync_all()?;
    Ok(envelope::StagedFile::new(temp, path))
}

fn preflight_output_paths(paths: &[&Path], force: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    if let Some(path) = paths.iter().find(|path| path.exists()) {
        return Err(AppError::OutputExists((*path).to_path_buf()));
    }
    Ok(())
}

fn prepare_keys_dir(keys_dir: &Path) -> Result<()> {
    if keys_dir.exists() {
        return Ok(());
    }

    if let Some(parent) = keys_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    match fs::create_dir(keys_dir) {
        Ok(()) => {
            #[cfg(unix)]
            fs::set_permissions(keys_dir, fs::Permissions::from_mode(0o700))?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(AppError::Io(error)),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let file = fs::File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len > MAX_ASYMMETRIC_KEY_FILE_BYTES {
        return Err(key_file_too_large(path));
    }
    let capacity = usize::try_from(file_len).unwrap_or(MAX_ASYMMETRIC_KEY_FILE_BYTES as usize);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(MAX_ASYMMETRIC_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ASYMMETRIC_KEY_FILE_BYTES {
        return Err(key_file_too_large(path));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::InvalidAsymmetricKeyFile(format!("{}: {e}", path.display())))
}

fn key_file_too_large(path: &Path) -> AppError {
    AppError::InvalidAsymmetricKeyFile(format!(
        "{} exceeds the {} byte limit",
        path.display(),
        MAX_ASYMMETRIC_KEY_FILE_BYTES
    ))
}

fn validate_recipient_public_key(bundle: &RecipientPublicKeyBundle) -> Result<()> {
    validate_key_lifetime_metadata(bundle.created_at_unix, bundle.expires_at_unix)?;
    validate_key_not_expired(bundle.expires_at_unix)?;
    if bundle.version != 1
        || bundle.kind != "recipient-public"
        || !is_recipient_mode(&bundle.mode)
        || !is_recipient_algorithms(&bundle.algorithms)
    {
        return Err(AppError::InvalidAsymmetricKeyFile(
            "not a default recipient public key bundle".to_string(),
        ));
    }
    let mlkem = bundle.mlkem1024_public_bytes()?;
    let hqc = bundle.hqc256_public_bytes()?;
    let material = canonical_recipient_public_material_with_mode(&bundle.mode, &mlkem, &hqc)?;
    let expected_key_id = key_id_hex(&material);
    if bundle.key_id != expected_key_id {
        return Err(AppError::InvalidAsymmetricKeyFile(
            "recipient public key_id mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_recipient_secret_key(bundle: &RecipientSecretKeyBundle) -> Result<()> {
    validate_key_lifetime_metadata(bundle.created_at_unix, bundle.expires_at_unix)?;
    if bundle.version != 1
        || bundle.kind != "recipient-secret"
        || !is_recipient_mode(&bundle.mode)
        || !is_recipient_algorithms(&bundle.algorithms)
        || bundle.label8.len() != 8
        || !bundle.label8.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(AppError::InvalidAsymmetricKeyFile(
            "not a default recipient secret key bundle".to_string(),
        ));
    }
    let _ = bundle.mlkem1024_secret_bytes()?;
    let _ = bundle.hqc256_secret_bytes()?;
    Ok(())
}

fn validate_signing_public_key(bundle: &SigningPublicKeyBundle) -> Result<()> {
    validate_key_lifetime_metadata(bundle.created_at_unix, bundle.expires_at_unix)?;
    if bundle.version != 1
        || bundle.kind != "signer-public"
        || bundle.algorithm != "ML-DSA-87"
        || bundle.hash != "SHA3-512"
    {
        return Err(AppError::InvalidAsymmetricKeyFile(
            "not an ML-DSA-87 signing public key bundle".to_string(),
        ));
    }
    let public_key = bundle.mldsa87_public_bytes()?;
    let material = canonical_signing_public_material(&public_key)?;
    let expected_key_id = key_id_hex(&material);
    if bundle.key_id != expected_key_id {
        return Err(AppError::InvalidAsymmetricKeyFile(
            "signing public key_id mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_signing_secret_key(bundle: &SigningSecretKeyBundle) -> Result<()> {
    validate_key_lifetime_metadata(bundle.created_at_unix, bundle.expires_at_unix)?;
    validate_key_not_expired(bundle.expires_at_unix)?;
    if bundle.version != 1
        || bundle.kind != "signer-secret"
        || bundle.algorithm != "ML-DSA-87"
        || bundle.hash != "SHA3-512"
        || bundle.label8.len() != 8
        || !bundle.label8.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(AppError::InvalidAsymmetricKeyFile(
            "not an ML-DSA-87 signing secret key bundle".to_string(),
        ));
    }
    let _ = bundle.mldsa87_secret_bytes()?;
    Ok(())
}

fn validate_key_lifetime_metadata(
    created_at_unix: Option<u64>,
    expires_at_unix: Option<u64>,
) -> Result<()> {
    if let (Some(created_at_unix), Some(expires_at_unix)) = (created_at_unix, expires_at_unix) {
        if expires_at_unix <= created_at_unix {
            return Err(AppError::InvalidAsymmetricKeyFile(
                "key expiration must be after creation time".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_key_not_expired(expires_at_unix: Option<u64>) -> Result<()> {
    if let Some(expires_at_unix) = expires_at_unix {
        if unix_now()? >= expires_at_unix {
            return Err(AppError::InvalidAsymmetricKeyFile(
                "asymmetric key has expired".to_string(),
            ));
        }
    }
    Ok(())
}

fn is_expired(expires_at_unix: Option<u64>) -> bool {
    expires_at_unix.is_some_and(|expires_at_unix| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() >= expires_at_unix)
            .unwrap_or(false)
    })
}

fn canonical_recipient_public_material(mlkem_public: &[u8], hqc_public: &[u8]) -> Result<Vec<u8>> {
    canonical_recipient_public_material_with_mode(RECIPIENT_MODE, mlkem_public, hqc_public)
}

fn canonical_recipient_public_material_with_mode(
    mode: &str,
    mlkem_public: &[u8],
    hqc_public: &[u8],
) -> Result<Vec<u8>> {
    let material = RecipientPublicMaterial {
        version: 1,
        kind: "recipient-public",
        mode,
        algorithms: recipient_algorithms(),
        mlkem1024_public: mlkem_public,
        hqc256_public: hqc_public,
    };
    envelope::encode_cbor(&material)
}

fn canonical_signing_public_material(public_key: &[u8]) -> Result<Vec<u8>> {
    let material = SigningPublicMaterial {
        version: 1,
        kind: "signer-public",
        algorithm: "ML-DSA-87",
        hash: "SHA3-512",
        mldsa87_public: public_key,
    };
    envelope::encode_cbor(&material)
}

fn key_id_hex(canonical_public_bundle: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"fcrypt-key-id-v1");
    hasher.update(canonical_public_bundle);
    hex::encode(hasher.finalize())
}

fn generate_label8(canonical_public_bundle: &[u8], keys_dir: &Path) -> Result<String> {
    for _ in 0..128 {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut hasher = Sha3_256::new();
        hasher.update(b"fcrypt-key-label-v1");
        hasher.update(seed);
        hasher.update(canonical_public_bundle);
        let label = hex::encode(hasher.finalize());
        let label8 = label[..8].to_string();
        if !label_exists(keys_dir, &label8)? {
            return Ok(label8);
        }
    }
    Err(AppError::InvalidAsymmetricKeyFile(
        "could not allocate a unique key label".to_string(),
    ))
}

fn label_exists(keys_dir: &Path, label8: &str) -> Result<bool> {
    if !keys_dir.exists() {
        return Ok(false);
    }
    for entry in fs::read_dir(keys_dir)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(label8))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn key_lifetime(lifetime_days: Option<u64>) -> Result<KeyLifetime> {
    let created_at_unix = unix_now()?;
    let expires_at_unix =
        if let Some(days) = lifetime_days {
            if days == 0 {
                return Err(AppError::InvalidArgument(
                    "key lifetime must be at least 1 day".to_string(),
                ));
            }
            let seconds = days.checked_mul(86_400).ok_or_else(|| {
                AppError::InvalidArgument("key lifetime is too large".to_string())
            })?;
            Some(created_at_unix.checked_add(seconds).ok_or_else(|| {
                AppError::InvalidArgument("key lifetime is too large".to_string())
            })?)
        } else {
            None
        };
    Ok(KeyLifetime {
        created_at_unix: Some(created_at_unix),
        expires_at_unix,
    })
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            AppError::InvalidAsymmetricKeyFile("system clock is before UNIX epoch".to_string())
        })
}

fn validate_key_file_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(AppError::InvalidArgument(
            "key name must contain only ASCII letters, digits, '.', '_' or '-' and must not start with '.'"
                .to_string(),
        ));
    }
    Ok(())
}

fn recipient_algorithms() -> RecipientAlgorithms {
    RecipientAlgorithms {
        kem_1: "ML-KEM-1024".to_string(),
        kem_2: "HQC-256".to_string(),
        kdf: "HKDF-SHA3-512".to_string(),
        aead: "AES-256-GCM".to_string(),
    }
}

fn is_recipient_algorithms(algorithms: &RecipientAlgorithms) -> bool {
    algorithms.kem_1 == "ML-KEM-1024"
        && algorithms.kem_2 == "HQC-256"
        && algorithms.kdf == "HKDF-SHA3-512"
        && algorithms.aead == "AES-256-GCM"
}

fn is_recipient_mode(mode: &str) -> bool {
    mode == RECIPIENT_MODE
}

fn is_recipient_secret_key_file_name(name: &str) -> bool {
    name.ends_with("_recipient_default.sec")
}

fn decode_base64(input: &str, field: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(input.as_bytes())
        .map_err(|_| AppError::InvalidAsymmetricKeyFile(format!("invalid base64 field: {field}")))
}
