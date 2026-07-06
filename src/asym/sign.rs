use std::fs::{self, File};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::PathBuf;
use tempfile::NamedTempFile;

use crate::asym::cli::AssymSignArgs;
use crate::asym::{envelope, keys, pqc};
use crate::error::{AppError, Result};
use crate::sym::pathing;

pub struct SignOutcome {
    pub output: PathBuf,
    pub embedded: bool,
    pub keys_dir: PathBuf,
    pub generated_signer_public: Option<PathBuf>,
    pub generated_signer_secret: Option<PathBuf>,
}

pub fn sign_file(args: &AssymSignArgs) -> Result<SignOutcome> {
    pqc::ensure_enabled()?;
    if !envelope::is_fe_file(&args.input)? {
        return Err(AppError::NotAsymmetricFile(
            args.input.display().to_string(),
        ));
    }
    let envelope_reader = envelope::read_envelope(&args.input)?;
    envelope::validate_header(&envelope_reader.header)?;

    let keys_dir = args
        .keys_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::asym_default_keys_dir_for_fe_input(&args.input))?;
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

    let mut payload_reader =
        envelope::open_payload_reader(&args.input, envelope_reader.payload_offset)?;
    let ciphertext_hash = envelope::ciphertext_hash_from_reader(&mut payload_reader)?;
    let transcript = envelope::signature_transcript(&envelope_reader.header, &ciphertext_hash)?;
    let signing_secret = signer.mldsa87_secret_bytes()?;
    let signature = pqc::sign_mldsa87(&signing_secret, &transcript)?;
    let signature_section = envelope::SignatureSection {
        alg: "ML-DSA-87".to_string(),
        signer_key_id: signer.key_id,
        transcript_hash_alg: "SHA3-512".to_string(),
        signature,
    };

    if args.embed {
        let output = args.output.clone().unwrap_or_else(|| args.input.clone());
        if output.exists() && output != args.input && !args.force {
            return Err(AppError::OutputExists(output));
        }
        embed_signature(
            &args.input,
            &output,
            &envelope_reader,
            signature_section,
            args.force,
        )?;
        Ok(SignOutcome {
            output,
            embedded: true,
            keys_dir,
            generated_signer_public,
            generated_signer_secret,
        })
    } else {
        let output = args
            .output
            .clone()
            .map(Ok)
            .unwrap_or_else(|| envelope::detached_signature_path(&args.input))?;
        let detached = envelope::signature_section_to_detached(&signature_section);
        keys::write_json_atomic(&output, &detached, false, args.force)?;
        Ok(SignOutcome {
            output,
            embedded: false,
            keys_dir,
            generated_signer_public,
            generated_signer_secret,
        })
    }
}

fn embed_signature(
    input: &PathBuf,
    output: &PathBuf,
    envelope_reader: &envelope::EnvelopeReader,
    signature: envelope::SignatureSection,
    force: bool,
) -> Result<()> {
    let mut header = envelope_reader.header.clone();
    header.signature = Some(signature);
    let output_dir = envelope::output_parent_dir(output);
    fs::create_dir_all(&output_dir)?;
    let mut temp_output = NamedTempFile::new_in(&output_dir)?;
    {
        let mut writer = BufWriter::new(temp_output.as_file_mut());
        envelope::write_envelope(&mut writer, &header)?;
        let mut payload_reader = File::open(input)?;
        payload_reader.seek(SeekFrom::Start(envelope_reader.payload_offset))?;
        std::io::copy(&mut payload_reader, &mut writer)?;
        writer.flush()?;
    }
    temp_output.as_file_mut().sync_all()?;
    let allow_overwrite = force || output == input;
    envelope::persist_temp_file(temp_output, output, allow_overwrite)
}
