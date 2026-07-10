use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
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

pub struct VerifyOutcome {
    pub signer_key_id: String,
    pub signer_key_expired: bool,
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

    let mut input = File::open(&args.input)?;
    let input_len = input.metadata()?.len();
    let detached = create_detached_signature_from_reader(&mut input, input_len, &signer)?;
    let output = args
        .output
        .clone()
        .map(Ok)
        .unwrap_or_else(|| envelope::detached_signature_path(&args.input))?;
    write_detached_signature(&detached, &output, args.force)?;
    Ok(SignOutcome {
        output,
        embedded: false,
        keys_dir,
        generated_signer_public,
        generated_signer_secret,
    })
}

pub(crate) fn create_detached_signature_from_reader<R>(
    reader: &mut R,
    input_len: u64,
    signer: &keys::SigningSecretKeyBundle,
) -> Result<envelope::DetachedSignature>
where
    R: Read + Seek,
{
    let transcript = opaque_signature_transcript_from_reader(reader, input_len)?;
    detached_signature_from_transcript(signer, &transcript)
}

pub(crate) fn verify_detached_signature<R>(
    input_path: &Path,
    verify_key: &Path,
    reader: &mut R,
    input_len: u64,
) -> Result<()>
where
    R: Read + Seek,
{
    pqc::ensure_enabled()?;
    let public_key = keys::read_signing_public_key(verify_key)?;
    let detached_path = envelope::detached_signature_path(input_path)?;
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
    let transcript = opaque_signature_transcript_from_reader(reader, input_len)?;
    pqc::verify_mldsa87(&public_key_bytes, &transcript, &signature.signature)
}

pub fn verify_file(input: &Path, verify_key: &Path) -> Result<VerifyOutcome> {
    let public_key = keys::read_signing_public_key(verify_key)?;
    let signer_key_id = public_key.key_id.clone();
    let signer_key_expired = public_key.is_expired();
    let mut file = File::open(input)?;
    let input_len = file.metadata()?.len();
    verify_detached_signature(input, verify_key, &mut file, input_len)?;
    Ok(VerifyOutcome {
        signer_key_id,
        signer_key_expired,
    })
}

pub(crate) fn write_detached_signature(
    detached: &envelope::DetachedSignature,
    output: &Path,
    force: bool,
) -> Result<()> {
    keys::write_json_atomic(output, detached, false, force)
}

fn detached_signature_from_transcript(
    signer: &keys::SigningSecretKeyBundle,
    transcript: &[u8],
) -> Result<envelope::DetachedSignature> {
    let signing_secret = signer.mldsa87_secret_bytes()?;
    let signature = pqc::sign_mldsa87(&signing_secret, transcript)?;
    let signature_section = envelope::SignatureSection {
        alg: "ML-DSA-87".to_string(),
        signer_key_id: signer.key_id.clone(),
        transcript_hash_alg: "SHA3-512".to_string(),
        signature,
    };
    Ok(envelope::signature_section_to_detached(&signature_section))
}

fn opaque_signature_transcript_from_reader<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
) -> Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(0))?;
    let ciphertext_hash = envelope::ciphertext_hash_from_reader(reader)?;
    if reader.stream_position()? != file_len {
        return Err(AppError::InputChangedDuringProcessing);
    }
    reader.seek(SeekFrom::Start(0))?;
    let transcript = OpaqueSignatureTranscript {
        version: 1,
        domain: OPAQUE_SIGNATURE_DOMAIN,
        file_len,
        ciphertext_hash: &ciphertext_hash,
    };
    envelope::encode_cbor(&transcript)
}
