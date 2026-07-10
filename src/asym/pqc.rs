use crate::error::{AppError, Result};
use zeroize::Zeroize;

pub struct RecipientKeypair {
    pub mlkem1024_public: Vec<u8>,
    pub mlkem1024_secret: Vec<u8>,
    pub hqc256_public: Vec<u8>,
    pub hqc256_secret: Vec<u8>,
}

pub struct EncapsulatedSecrets {
    pub mlkem1024_ciphertext: Vec<u8>,
    pub mlkem1024_shared_secret: Vec<u8>,
    pub hqc256_ciphertext: Vec<u8>,
    pub hqc256_shared_secret: Vec<u8>,
}

pub struct SigningKeypair {
    pub mldsa87_public: Vec<u8>,
    pub mldsa87_secret: Vec<u8>,
}

impl Drop for RecipientKeypair {
    fn drop(&mut self) {
        self.mlkem1024_secret.zeroize();
        self.hqc256_secret.zeroize();
    }
}

impl Drop for EncapsulatedSecrets {
    fn drop(&mut self) {
        self.mlkem1024_shared_secret.zeroize();
        self.hqc256_shared_secret.zeroize();
    }
}

impl Drop for SigningKeypair {
    fn drop(&mut self) {
        self.mldsa87_secret.zeroize();
    }
}

#[cfg(feature = "pqc")]
pub fn ensure_enabled() -> Result<()> {
    oqs::init();
    let required_kems = [oqs::kem::Algorithm::MlKem1024, oqs::kem::Algorithm::Hqc256];
    for alg in required_kems {
        if !alg.is_enabled() {
            return Err(AppError::Pqc(format!("required KEM is disabled: {alg}")));
        }
    }
    let sig = oqs::sig::Algorithm::MlDsa87;
    if !sig.is_enabled() {
        return Err(AppError::Pqc(format!(
            "required signature is disabled: {sig}"
        )));
    }
    Ok(())
}

#[cfg(not(feature = "pqc"))]
pub fn ensure_enabled() -> Result<()> {
    Err(AppError::AsymmetricUnavailable)
}

#[cfg(feature = "pqc")]
pub fn generate_recipient_keypair() -> Result<RecipientKeypair> {
    ensure_enabled()?;
    let mlkem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).map_err(oqs_error)?;
    let hqc = oqs::kem::Kem::new(oqs::kem::Algorithm::Hqc256).map_err(oqs_error)?;
    let (mlkem_pk, mlkem_sk) = mlkem.keypair().map_err(oqs_error)?;
    let (hqc_pk, hqc_sk) = hqc.keypair().map_err(oqs_error)?;
    Ok(RecipientKeypair {
        mlkem1024_public: mlkem_pk.into_vec(),
        mlkem1024_secret: mlkem_sk.into_vec(),
        hqc256_public: hqc_pk.into_vec(),
        hqc256_secret: hqc_sk.into_vec(),
    })
}

#[cfg(not(feature = "pqc"))]
pub fn generate_recipient_keypair() -> Result<RecipientKeypair> {
    Err(AppError::AsymmetricUnavailable)
}

#[cfg(feature = "pqc")]
pub fn encapsulate_recipient(
    mlkem1024_public: &[u8],
    hqc256_public: &[u8],
) -> Result<EncapsulatedSecrets> {
    ensure_enabled()?;
    let mlkem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).map_err(oqs_error)?;
    let hqc = oqs::kem::Kem::new(oqs::kem::Algorithm::Hqc256).map_err(oqs_error)?;
    let mlkem_pk = mlkem
        .public_key_from_bytes(mlkem1024_public)
        .ok_or_else(|| {
            AppError::InvalidAsymmetricKeyFile("invalid ML-KEM-1024 public key length".to_string())
        })?;
    let hqc_pk = hqc.public_key_from_bytes(hqc256_public).ok_or_else(|| {
        AppError::InvalidAsymmetricKeyFile("invalid HQC-256 public key length".to_string())
    })?;

    let (mlkem_ct, mlkem_ss) = mlkem.encapsulate(mlkem_pk).map_err(oqs_error)?;
    let (hqc_ct, hqc_ss) = hqc.encapsulate(hqc_pk).map_err(oqs_error)?;
    Ok(EncapsulatedSecrets {
        mlkem1024_ciphertext: mlkem_ct.into_vec(),
        mlkem1024_shared_secret: mlkem_ss.into_vec(),
        hqc256_ciphertext: hqc_ct.into_vec(),
        hqc256_shared_secret: hqc_ss.into_vec(),
    })
}

#[cfg(not(feature = "pqc"))]
pub fn encapsulate_recipient(
    _mlkem1024_public: &[u8],
    _hqc256_public: &[u8],
) -> Result<EncapsulatedSecrets> {
    Err(AppError::AsymmetricUnavailable)
}

#[cfg(feature = "pqc")]
pub fn decapsulate_recipient(
    mlkem1024_secret: &[u8],
    hqc256_secret: &[u8],
    mlkem1024_ciphertext: &[u8],
    hqc256_ciphertext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure_enabled()?;
    let mlkem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).map_err(oqs_error)?;
    let hqc = oqs::kem::Kem::new(oqs::kem::Algorithm::Hqc256).map_err(oqs_error)?;
    let mlkem_sk = mlkem
        .secret_key_from_bytes(mlkem1024_secret)
        .ok_or_else(|| {
            AppError::InvalidAsymmetricKeyFile("invalid ML-KEM-1024 secret key length".to_string())
        })?;
    let hqc_sk = hqc.secret_key_from_bytes(hqc256_secret).ok_or_else(|| {
        AppError::InvalidAsymmetricKeyFile("invalid HQC-256 secret key length".to_string())
    })?;
    let mlkem_ct = mlkem
        .ciphertext_from_bytes(mlkem1024_ciphertext)
        .ok_or(AppError::AsymmetricAuthenticationFailed)?;
    let hqc_ct = hqc
        .ciphertext_from_bytes(hqc256_ciphertext)
        .ok_or(AppError::AsymmetricAuthenticationFailed)?;
    let mlkem_ss = mlkem
        .decapsulate(mlkem_sk, mlkem_ct)
        .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
    let hqc_ss = hqc
        .decapsulate(hqc_sk, hqc_ct)
        .map_err(|_| AppError::AsymmetricAuthenticationFailed)?;
    Ok((mlkem_ss.into_vec(), hqc_ss.into_vec()))
}

#[cfg(not(feature = "pqc"))]
pub fn decapsulate_recipient(
    _mlkem1024_secret: &[u8],
    _hqc256_secret: &[u8],
    _mlkem1024_ciphertext: &[u8],
    _hqc256_ciphertext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(AppError::AsymmetricUnavailable)
}

#[cfg(feature = "pqc")]
pub fn generate_signing_keypair() -> Result<SigningKeypair> {
    ensure_enabled()?;
    let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa87).map_err(oqs_error)?;
    let (pk, sk) = sig.keypair().map_err(oqs_error)?;
    Ok(SigningKeypair {
        mldsa87_public: pk.into_vec(),
        mldsa87_secret: sk.into_vec(),
    })
}

#[cfg(not(feature = "pqc"))]
pub fn generate_signing_keypair() -> Result<SigningKeypair> {
    Err(AppError::AsymmetricUnavailable)
}

#[cfg(feature = "pqc")]
pub fn sign_mldsa87(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    ensure_enabled()?;
    let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa87).map_err(oqs_error)?;
    let sk = sig.secret_key_from_bytes(secret_key).ok_or_else(|| {
        AppError::InvalidAsymmetricKeyFile("invalid ML-DSA-87 secret key length".to_string())
    })?;
    let signature = sig.sign(message, sk).map_err(oqs_error)?;
    Ok(signature.into_vec())
}

#[cfg(not(feature = "pqc"))]
pub fn sign_mldsa87(_secret_key: &[u8], _message: &[u8]) -> Result<Vec<u8>> {
    Err(AppError::AsymmetricUnavailable)
}

#[cfg(feature = "pqc")]
pub fn verify_mldsa87(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    ensure_enabled()?;
    let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa87).map_err(oqs_error)?;
    let pk = sig.public_key_from_bytes(public_key).ok_or_else(|| {
        AppError::InvalidAsymmetricKeyFile("invalid ML-DSA-87 public key length".to_string())
    })?;
    let signature_ref = sig
        .signature_from_bytes(signature)
        .ok_or(AppError::SignatureVerificationFailed)?;
    sig.verify(message, signature_ref, pk)
        .map_err(|_| AppError::SignatureVerificationFailed)
}

#[cfg(not(feature = "pqc"))]
pub fn verify_mldsa87(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> Result<()> {
    Err(AppError::AsymmetricUnavailable)
}

#[cfg(feature = "pqc")]
fn oqs_error(error: oqs::Error) -> AppError {
    AppError::Pqc(error.to_string())
}
