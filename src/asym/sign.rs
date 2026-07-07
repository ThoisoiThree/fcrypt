use serde::Serialize;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use crate::asym::cli::AssymSignArgs;
use crate::asym::{envelope, keys, pqc};
use crate::error::{AppError, Result};
use crate::sym::pathing;

const OPAQUE_SIGNATURE_DOMAIN: &str = "fcrypt opaque detached signature v1";

pub struct SignOutcome {
    pub output: PathBuf,
    pub embedded: bool,
    pub keys_dir: PathBuf,
    pub generated_signer_public: Option<PathBuf>,
    pub generated_signer_secret: Option<PathBuf>,
}

#[derive(Serialize)]
struct OpaqueSignatureTranscript<'a> {
    version: u16,
    domain: &'static str,
    file_len: u64,
    #[serde(with = "serde_bytes")]
    ciphertext_hash: &'a [u8],
}

pub fn sign_file(args: &AssymSignArgs) -> Result<SignOutcome> {
    pqc::ensure_enabled()?;
    if args.embed {
        return Err(AppError::InvalidArgument(
            "embedded signatures are not available for opaque files; use detached signatures"
                .to_string(),
        ));
    }

    let keys_dir = args
        .keys_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_default_keys_dir_for_encrypted_input(&args.input))?;
    let mut generated_signer_public = None;
    let mut generated_signer_secret = None;
    let signer = if let Some(sign_key) = &args.sign_key {
        keys::read_signing_secret_key(sign_key)?
    } else {
        let generated = keys::generate_signing_key_files(&keys_dir, args.force)?;
        generated_signer_public = Some(generated.public_path);
        generated_signer_secret = Some(generated.secret_path);
        generated.secret
    };

    let transcript = opaque_signature_transcript(&args.input)?;
    let output = args
        .output
        .clone()
        .map(Ok)
        .unwrap_or_else(|| envelope::detached_signature_path(&args.input))?;
    write_detached_signature(&signer, &transcript, &output, args.force)?;
    Ok(SignOutcome {
        output,
        embedded: false,
        keys_dir,
        generated_signer_public,
        generated_signer_secret,
    })
}

pub(crate) fn sign_detached_with_secret(
    input: &Path,
    signer: &keys::SigningSecretKeyBundle,
    output: &Path,
    force: bool,
) -> Result<()> {
    let transcript = opaque_signature_transcript(input)?;
    write_detached_signature(signer, &transcript, output, force)
}

pub(crate) fn verify_detached_signature(input: &Path, verify_key: &Path) -> Result<()> {
    pqc::ensure_enabled()?;
    let public_key = keys::read_signing_public_key(verify_key)?;
    let detached_path = envelope::detached_signature_path(input)?;
    if !detached_path.exists() {
        return Err(AppError::SignatureRequired);
    }
    let file = File::open(&detached_path)?;
    let detached: envelope::DetachedSignature = serde_json::from_reader(BufReader::new(file))
        .map_err(|e| {
            AppError::InvalidAsymmetricFile(format!(
                "invalid detached signature {}: {e}",
                detached_path.display()
            ))
        })?;
    let signature = envelope::detached_signature_to_section(detached)?;
    if signature.signer_key_id != public_key.key_id {
        return Err(AppError::SignatureVerificationFailed);
    }
    if signature.alg != "ML-DSA-87" || signature.transcript_hash_alg != "SHA3-512" {
        return Err(AppError::SignatureVerificationFailed);
    }

    let public_key_bytes = public_key.mldsa87_public_bytes()?;
    let transcript = opaque_signature_transcript(input)?;
    pqc::verify_mldsa87(&public_key_bytes, &transcript, &signature.signature)
}

fn write_detached_signature(
    signer: &keys::SigningSecretKeyBundle,
    transcript: &[u8],
    output: &Path,
    force: bool,
) -> Result<()> {
    let signing_secret = signer.mldsa87_secret_bytes()?;
    let signature = pqc::sign_mldsa87(&signing_secret, transcript)?;
    let signature_section = envelope::SignatureSection {
        alg: "ML-DSA-87".to_string(),
        signer_key_id: signer.key_id.clone(),
        transcript_hash_alg: "SHA3-512".to_string(),
        signature,
    };
    let detached = envelope::signature_section_to_detached(&signature_section);
    keys::write_json_atomic(output, &detached, false, force)
}

fn opaque_signature_transcript(input: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(input)?;
    let file_len = file.metadata()?.len();
    let ciphertext_hash = envelope::ciphertext_hash_from_reader(&mut file)?;
    let transcript = OpaqueSignatureTranscript {
        version: 1,
        domain: OPAQUE_SIGNATURE_DOMAIN,
        file_len,
        ciphertext_hash: &ciphertext_hash,
    };
    envelope::encode_cbor(&transcript)
}
