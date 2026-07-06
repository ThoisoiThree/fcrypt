use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command as AssertCommand;
use clap::Parser;
#[cfg(feature = "pqc")]
use filecrypt::asym;
use filecrypt::asym::cli::AssymCommand;
#[cfg(feature = "pqc")]
use filecrypt::asym::cli::{AssymDecryptArgs, AssymEncryptArgs, AssymSignArgs};
use filecrypt::cli::{Cli, Command as CliCommand};
use filecrypt::error::AppError;
use filecrypt::keygen::phrase;
use filecrypt::sym::crypto::{
    CryptoConfig, CryptoMode, FILE_PREFIX_LEN, PARANOID_FLAG, TAG_LEN, VERSIONED_HEADER_LEN,
};
use filecrypt::sym::file_ops::{decrypt_file, encrypt_file, encrypt_file_with_mode};
use filecrypt::sym::overwrite::resolve_overwrite;
use filecrypt::sym::pathing::{
    asym_decryption_output_path, asym_default_keys_dir_for_fe_input,
    asym_default_keys_dir_for_plain_input, asym_encryption_output_path, decryption_output_path,
    encryption_output_path,
};
use predicates::str::contains;
use tempfile::tempdir;

fn test_config(chunk_size: usize) -> CryptoConfig {
    CryptoConfig {
        chunk_size,
        argon_memory_kib: 8,
        argon_time_cost: 1,
        argon_parallelism: 1,
        paranoid_argon_memory_kib: 8,
        paranoid_argon_time_cost: 1,
        paranoid_argon_parallelism: 1,
    }
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn encrypt_decrypt_roundtrip_small_file() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("small.bin");
    let encrypted = dir.path().join("small.bin.encdata");
    let decrypted = dir.path().join("small.bin.decoded");
    let original = b"hello from filecrypt".to_vec();
    fs::write(&input, &original).expect("input file must be written");

    let config = test_config(1024);
    encrypt_file(
        &input,
        &encrypted,
        "correct horse battery staple",
        &config,
        false,
        |_| {},
    )
    .expect("encryption must succeed");
    decrypt_file(
        &encrypted,
        &decrypted,
        "correct horse battery staple",
        &config,
        false,
        |_| {},
    )
    .expect("decryption must succeed");

    let decrypted_bytes = fs::read(&decrypted).expect("decrypted file must be readable");
    assert_eq!(decrypted_bytes, original);
}

#[test]
fn roundtrip_across_chunk_boundaries() {
    let config = test_config(64);
    let sizes = [63usize, 64, 65, 127, 128, 129, 192, 193];
    let dir = tempdir().expect("tempdir must be created");

    for size in sizes {
        let input = dir.path().join(format!("input_{size}.bin"));
        let encrypted = dir.path().join(format!("input_{size}.bin.encdata"));
        let decrypted = dir.path().join(format!("input_{size}.bin.decoded"));
        let original = deterministic_bytes(size);
        fs::write(&input, &original).expect("input file must be written");

        encrypt_file(&input, &encrypted, "boundary-pass", &config, false, |_| {})
            .expect("encryption must succeed");
        decrypt_file(
            &encrypted,
            &decrypted,
            "boundary-pass",
            &config,
            false,
            |_| {},
        )
        .expect("decryption must succeed");

        let decrypted_bytes = fs::read(&decrypted).expect("decrypted file must be readable");
        assert_eq!(decrypted_bytes, original, "failed for size={size}");
    }
}

#[test]
fn wrong_password_fails_without_finalized_output() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("input.bin.encdata");
    let decrypted = dir.path().join("output.bin");
    fs::write(&input, deterministic_bytes(2048)).expect("input file must be written");

    let config = test_config(256);
    encrypt_file(&input, &encrypted, "right-password", &config, false, |_| {})
        .expect("encryption must succeed");
    let err = decrypt_file(
        &encrypted,
        &decrypted,
        "wrong-password",
        &config,
        false,
        |_| {},
    )
    .expect_err("decryption must fail");

    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn corrupted_ciphertext_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("input.bin.encdata");
    let decrypted = dir.path().join("output.bin");
    fs::write(&input, deterministic_bytes(1024)).expect("input file must be written");

    let config = test_config(128);
    encrypt_file(&input, &encrypted, "password-1", &config, false, |_| {})
        .expect("encryption must succeed");

    let mut bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    assert!(
        bytes.len() > FILE_PREFIX_LEN,
        "encrypted payload should exist"
    );
    bytes[FILE_PREFIX_LEN] ^= 0x5A;
    fs::write(&encrypted, bytes).expect("corrupted file must be written");

    let err = decrypt_file(&encrypted, &decrypted, "password-1", &config, false, |_| {})
        .expect_err("decryption must fail");
    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn truncated_ciphertext_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("input.bin.encdata");
    let decrypted = dir.path().join("output.bin");
    let config = test_config(128);
    fs::write(&input, deterministic_bytes(128 * 3)).expect("input file must be written");

    encrypt_file(&input, &encrypted, "password-2", &config, false, |_| {})
        .expect("encryption must succeed");

    let mut bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    let drop_len = config.chunk_size + TAG_LEN;
    bytes.truncate(bytes.len() - drop_len);
    fs::write(&encrypted, bytes).expect("truncated file must be written");

    let err = decrypt_file(&encrypted, &decrypted, "password-2", &config, false, |_| {})
        .expect_err("decryption must fail");
    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn filename_mapping_behavior() {
    let p1 = Path::new("report.pdf");
    assert_eq!(
        encryption_output_path(p1).expect("mapping must succeed"),
        PathBuf::from("report.pdf.fe")
    );

    let p2 = Path::new("report.pdf.fe");
    assert_eq!(
        decryption_output_path(p2).expect("mapping must succeed"),
        PathBuf::from("report.pdf")
    );

    let p2_legacy = Path::new("report.pdf.enc");
    assert_eq!(
        decryption_output_path(p2_legacy).expect("legacy mapping must succeed"),
        PathBuf::from("report.pdf")
    );

    let p3 = Path::new("report.pdf.data");
    assert_eq!(
        decryption_output_path(p3).expect("mapping must succeed"),
        PathBuf::from("report.pdf.data.dec")
    );
}

#[test]
fn asymmetric_path_mapping_behavior() {
    let p1 = Path::new("report.pdf");
    assert_eq!(
        asym_encryption_output_path(p1).expect("mapping must succeed"),
        PathBuf::from("report.pdf.fe")
    );
    assert_eq!(
        asym_default_keys_dir_for_plain_input(p1).expect("keys dir must resolve"),
        PathBuf::from("report_keys")
    );

    let p2 = Path::new("docs/report.pdf");
    assert_eq!(
        asym_default_keys_dir_for_plain_input(p2).expect("keys dir must resolve"),
        PathBuf::from("docs/report_keys")
    );

    let p3 = Path::new("report.pdf.fe");
    assert_eq!(
        asym_decryption_output_path(p3).expect("mapping must succeed"),
        PathBuf::from("report.pdf")
    );
    assert_eq!(
        asym_default_keys_dir_for_fe_input(p3).expect("keys dir must resolve"),
        PathBuf::from("report_keys")
    );
}

#[test]
fn cli_aliases_parse_to_same_commands() {
    let encrypt = Cli::parse_from(["fcrypt", "encrypt", "notes.txt"]);
    let encode = Cli::parse_from(["fcrypt", "encode", "notes.txt"]);
    assert!(matches!(encrypt.command, CliCommand::Encrypt(_)));
    assert!(matches!(encode.command, CliCommand::Encrypt(_)));

    let decrypt = Cli::parse_from(["fcrypt", "decrypt", "notes.txt.fe"]);
    let decode = Cli::parse_from(["fcrypt", "decode", "notes.txt.fe"]);
    assert!(matches!(decrypt.command, CliCommand::Decrypt(_)));
    assert!(matches!(decode.command, CliCommand::Decrypt(_)));

    let asym = Cli::parse_from(["fcrypt", "asym", "encrypt", "notes.txt"]);
    let assym = Cli::parse_from(["fcrypt", "assym", "encode", "notes.txt"]);
    assert!(matches!(
        asym.command,
        CliCommand::Assym {
            command: AssymCommand::Encrypt(_)
        }
    ));
    assert!(matches!(
        assym.command,
        CliCommand::Assym {
            command: AssymCommand::Encrypt(_)
        }
    ));
}

#[test]
fn help_all_forms_exit_successfully() {
    for args in [
        vec!["-ha"],
        vec!["--help-all"],
        vec!["asym", "-ha"],
        vec!["asym", "encrypt", "-ha"],
    ] {
        AssertCommand::cargo_bin("fcrypt")
            .expect("binary must build")
            .args(args)
            .assert()
            .success()
            .stdout(contains("Asymmetric PQC .fe Mode"))
            .stdout(contains("encrypt and encode are aliases"))
            .stdout(contains("asym and assym are aliases"));
    }
}

#[test]
fn keygen_phrase_uses_embedded_eff_wordlist() {
    let generated = phrase::generate_phrase(5, ".").expect("phrase must be generated");
    let parts: Vec<_> = generated.split('.').collect();
    assert_eq!(parts.len(), 5);
    assert!(parts.iter().all(|word| phrase::words().contains(word)));
    assert_eq!(phrase::words().len(), 7776);
}

#[test]
fn keygen_phrase_cli_accepts_sep_alias() {
    let output = AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args(["keygen", "phrase", "4", "-sep", "."])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let output = String::from_utf8(output).expect("phrase output must be utf-8");
    let phrase = output.trim_end();
    let parts: Vec<_> = phrase.split('.').collect();
    assert_eq!(parts.len(), 4);
    assert!(parts.iter().all(|word| phrase::words().contains(word)));
}

#[cfg(feature = "pqc")]
#[test]
fn asymmetric_roundtrip_with_generated_identity() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("report.pdf");
    let decrypted = dir.path().join("report.decoded.pdf");
    let original = deterministic_bytes(160);
    fs::write(&input, &original).expect("input file must be written");

    let encrypt_args = AssymEncryptArgs {
        input: input.clone(),
        output: None,
        recipient_public: None,
        keys_dir: None,
        sign: false,
        sign_key: None,
        force: false,
    };
    let outcome = asym::encrypt::encrypt_file(&encrypt_args, &test_config(64), |_| {})
        .expect("asymmetric encryption must succeed");

    assert_eq!(outcome.output, dir.path().join("report.pdf.fe"));
    assert_eq!(outcome.keys_dir, dir.path().join("report_keys"));
    let recipient_secret = outcome
        .generated_recipient_secret
        .expect("recipient secret must be generated");
    let recipient_public = outcome
        .generated_recipient_public
        .expect("recipient public must be generated");
    assert_key_name(&recipient_secret, "_recipient_default.sec");
    assert_key_name(&recipient_public, "_recipient_default.pub");
    assert_eq!(json_field(&recipient_secret, "mode"), "default");
    assert_eq!(json_field(&recipient_public, "mode"), "default");
    assert_eq!(
        &fs::read(&outcome.output).expect("encrypted output must be readable")[..8],
        b"FCRYPTFE"
    );

    let decrypt_args = AssymDecryptArgs {
        input: outcome.output,
        output: Some(decrypted.clone()),
        identity: Some(recipient_secret),
        keys_dir: None,
        verify: None,
        require_signature: false,
        force: false,
    };
    asym::decrypt::decrypt_file(&decrypt_args, |_| {}).expect("decryption must succeed");
    assert_eq!(
        fs::read(decrypted).expect("decrypted output must be readable"),
        original
    );
}

#[cfg(feature = "pqc")]
#[test]
fn asymmetric_roundtrip_with_embedded_signature_verification() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("signed.bin");
    let decrypted = dir.path().join("signed.out");
    let original = deterministic_bytes(96);
    fs::write(&input, &original).expect("input file must be written");

    let encrypt_args = AssymEncryptArgs {
        input,
        output: None,
        recipient_public: None,
        keys_dir: None,
        sign: true,
        sign_key: None,
        force: false,
    };
    let outcome = asym::encrypt::encrypt_file(&encrypt_args, &test_config(48), |_| {})
        .expect("signed asymmetric encryption must succeed");
    let recipient_secret = outcome
        .generated_recipient_secret
        .expect("recipient secret must be generated");
    let signer_public = outcome
        .generated_signer_public
        .expect("signer public must be generated");
    let signer_secret = outcome
        .generated_signer_secret
        .expect("signer secret must be generated");
    assert_key_name(&signer_public, "_signer_mldsa87.pub");
    assert_key_name(&signer_secret, "_signer_mldsa87.sec");

    let decrypt_args = AssymDecryptArgs {
        input: outcome.output,
        output: Some(decrypted.clone()),
        identity: Some(recipient_secret),
        keys_dir: None,
        verify: Some(signer_public),
        require_signature: true,
        force: false,
    };
    asym::decrypt::decrypt_file(&decrypt_args, |_| {})
        .expect("signed decryption with verification must succeed");
    assert_eq!(
        fs::read(decrypted).expect("decrypted output must be readable"),
        original
    );
}

#[cfg(feature = "pqc")]
#[test]
fn asymmetric_sign_creates_detached_signature() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("detached.bin");
    fs::write(&input, deterministic_bytes(80)).expect("input file must be written");

    let encrypt_args = AssymEncryptArgs {
        input,
        output: None,
        recipient_public: None,
        keys_dir: None,
        sign: false,
        sign_key: None,
        force: false,
    };
    let encrypt_outcome = asym::encrypt::encrypt_file(&encrypt_args, &test_config(40), |_| {})
        .expect("asymmetric encryption must succeed");
    let sign_args = AssymSignArgs {
        input: encrypt_outcome.output.clone(),
        output: None,
        sign_key: None,
        keys_dir: None,
        embed: false,
        force: false,
    };
    let sign_outcome = asym::sign::sign_file(&sign_args).expect("detached signing must succeed");
    assert!(!sign_outcome.embedded);
    assert_eq!(sign_outcome.output, dir.path().join("detached.bin.fe.sig"));
    assert!(sign_outcome.output.exists());
}

#[cfg(feature = "pqc")]
#[test]
fn asymmetric_tampered_ciphertext_fails_without_plaintext_output() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("tamper.bin");
    let decrypted = dir.path().join("tamper.out");
    fs::write(&input, deterministic_bytes(128)).expect("input file must be written");

    let encrypt_args = AssymEncryptArgs {
        input,
        output: None,
        recipient_public: None,
        keys_dir: None,
        sign: false,
        sign_key: None,
        force: false,
    };
    let outcome = asym::encrypt::encrypt_file(&encrypt_args, &test_config(64), |_| {})
        .expect("asymmetric encryption must succeed");
    let recipient_secret = outcome
        .generated_recipient_secret
        .expect("recipient secret must be generated");
    let mut bytes = fs::read(&outcome.output).expect("encrypted output must be readable");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x5A;
    fs::write(&outcome.output, bytes).expect("tampered output must be written");

    let decrypt_args = AssymDecryptArgs {
        input: outcome.output,
        output: Some(decrypted.clone()),
        identity: Some(recipient_secret),
        keys_dir: None,
        verify: None,
        require_signature: false,
        force: false,
    };
    let err = asym::decrypt::decrypt_file(&decrypt_args, |_| {})
        .expect_err("tampered ciphertext must fail");
    assert!(matches!(err, AppError::AsymmetricAuthenticationFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[cfg(feature = "pqc")]
fn assert_key_name(path: &Path, suffix: &str) {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("key name must be utf-8");
    assert!(name.ends_with(suffix));
    let label = &name[..8];
    assert!(label
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    assert_eq!(name.as_bytes()[8], b'_');
}

#[cfg(feature = "pqc")]
fn json_field(path: &Path, field: &str) -> String {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("json key file must be readable"))
            .expect("json key file must parse");
    value
        .get(field)
        .and_then(|value| value.as_str())
        .expect("json field must be a string")
        .to_string()
}

#[test]
fn overwrite_resolution_logic() {
    let dir = tempdir().expect("tempdir must be created");
    let existing = dir.path().join("existing.bin");
    fs::write(&existing, b"old").expect("existing file must be written");

    let denied = resolve_overwrite(&existing, false, |_| Ok(false));
    assert!(matches!(denied, Err(AppError::UserAborted)));

    let prompt_called = Cell::new(false);
    let allowed = resolve_overwrite(&existing, false, |_| {
        prompt_called.set(true);
        Ok(true)
    })
    .expect("overwrite should be allowed");
    assert!(allowed);
    assert!(prompt_called.get());

    let force_called = Cell::new(false);
    let forced = resolve_overwrite(&existing, true, |_| {
        force_called.set(true);
        Ok(false)
    })
    .expect("force should allow overwrite");
    assert!(forced);
    assert!(
        !force_called.get(),
        "prompt should not be called when force=true"
    );

    let missing = dir.path().join("missing.bin");
    let missing_called = Cell::new(false);
    let no_overwrite = resolve_overwrite(&missing, false, |_| {
        missing_called.set(true);
        Ok(true)
    })
    .expect("missing output should not require overwrite");
    assert!(!no_overwrite);
    assert!(
        !missing_called.get(),
        "prompt should not be called when file is missing"
    );
}

#[test]
fn empty_file_roundtrip() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("empty.bin");
    let encrypted = dir.path().join("empty.bin.encdata");
    let decrypted = dir.path().join("empty.bin.decoded");
    fs::write(&input, []).expect("empty input file must be written");

    let config = test_config(512);
    encrypt_file(&input, &encrypted, "empty-case", &config, false, |_| {})
        .expect("encryption must succeed");
    decrypt_file(&encrypted, &decrypted, "empty-case", &config, false, |_| {})
        .expect("decryption must succeed");

    let encrypted_len = fs::metadata(&encrypted)
        .expect("metadata must be readable")
        .len();
    assert_eq!(
        encrypted_len,
        (FILE_PREFIX_LEN + TAG_LEN) as u64,
        "empty file should contain binary prefix and authentication tag"
    );

    let decrypted_bytes = fs::read(&decrypted).expect("decrypted file must be readable");
    assert!(decrypted_bytes.is_empty());
}

#[test]
fn standard_encryption_keeps_legacy_prefix_format() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("legacy-format.bin");
    let encrypted = dir.path().join("legacy-format.bin.encdata");
    let original = deterministic_bytes(96);
    fs::write(&input, &original).expect("input file must be written");

    let config = test_config(64);
    encrypt_file(
        &input,
        &encrypted,
        "standard-format",
        &config,
        false,
        |_| {},
    )
    .expect("encryption must succeed");

    let encrypted_len = fs::metadata(&encrypted)
        .expect("metadata must be readable")
        .len();
    assert_eq!(
        encrypted_len,
        FILE_PREFIX_LEN as u64
            + filecrypt::sym::crypto::expected_ciphertext_payload_len(
                original.len() as u64,
                config.chunk_size,
            )
            .expect("expected length must be calculated")
    );
}

#[test]
fn paranoid_roundtrip_small_file() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("paranoid.bin");
    let encrypted = dir.path().join("paranoid.bin.encdata");
    let decrypted = dir.path().join("paranoid.bin.decoded");
    let original = deterministic_bytes(150);
    fs::write(&input, &original).expect("input file must be written");

    let config = test_config(64);
    encrypt_file_with_mode(
        &input,
        &encrypted,
        "paranoid-password",
        &config,
        CryptoMode::Paranoid,
        false,
        |_| {},
    )
    .expect("paranoid encryption must succeed");
    decrypt_file(
        &encrypted,
        &decrypted,
        "paranoid-password",
        &config,
        false,
        |_| {},
    )
    .expect("paranoid decryption must succeed");

    let decrypted_bytes = fs::read(&decrypted).expect("decrypted file must be readable");
    assert_eq!(decrypted_bytes, original);
}

#[test]
fn paranoid_header_records_mode_and_argon_params() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("paranoid-meta.bin");
    let encrypted = dir.path().join("paranoid-meta.bin.encdata");
    fs::write(&input, deterministic_bytes(20)).expect("input file must be written");

    let config = test_config(64);
    encrypt_file_with_mode(
        &input,
        &encrypted,
        "metadata-password",
        &config,
        CryptoMode::Paranoid,
        false,
        |_| {},
    )
    .expect("paranoid encryption must succeed");

    let bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    assert!(bytes.len() >= VERSIONED_HEADER_LEN);
    assert_eq!(&bytes[..8], b"FCRYPTH1");
    assert_eq!(bytes[8], 1);
    assert_eq!(bytes[9] & PARANOID_FLAG, PARANOID_FLAG);
    assert_eq!(u64::from_le_bytes(bytes[12..20].try_into().unwrap()), 64);
    assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 8);
    assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(bytes[28..32].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(bytes[32..40].try_into().unwrap()), 20);
}

#[test]
fn paranoid_wrong_password_fails_without_finalized_output() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("paranoid-wrong.bin");
    let encrypted = dir.path().join("paranoid-wrong.bin.encdata");
    let decrypted = dir.path().join("paranoid-wrong.bin.decoded");
    fs::write(&input, deterministic_bytes(140)).expect("input file must be written");

    let config = test_config(64);
    encrypt_file_with_mode(
        &input,
        &encrypted,
        "right-password",
        &config,
        CryptoMode::Paranoid,
        false,
        |_| {},
    )
    .expect("paranoid encryption must succeed");

    let err = decrypt_file(
        &encrypted,
        &decrypted,
        "wrong-password",
        &config,
        false,
        |_| {},
    )
    .expect_err("paranoid decryption must fail");
    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn corrupted_paranoid_ciphertext_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("paranoid-corrupt.bin");
    let encrypted = dir.path().join("paranoid-corrupt.bin.encdata");
    let decrypted = dir.path().join("paranoid-corrupt.bin.decoded");
    fs::write(&input, deterministic_bytes(140)).expect("input file must be written");

    let config = test_config(64);
    encrypt_file_with_mode(
        &input,
        &encrypted,
        "password",
        &config,
        CryptoMode::Paranoid,
        false,
        |_| {},
    )
    .expect("paranoid encryption must succeed");

    let mut bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    bytes[VERSIONED_HEADER_LEN] ^= 0x5A;
    fs::write(&encrypted, bytes).expect("corrupted file must be written");

    let err = decrypt_file(&encrypted, &decrypted, "password", &config, false, |_| {})
        .expect_err("paranoid decryption must fail");
    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn truncated_paranoid_ciphertext_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("paranoid-truncated.bin");
    let encrypted = dir.path().join("paranoid-truncated.bin.encdata");
    let decrypted = dir.path().join("paranoid-truncated.bin.decoded");
    fs::write(&input, deterministic_bytes(140)).expect("input file must be written");

    let config = test_config(64);
    encrypt_file_with_mode(
        &input,
        &encrypted,
        "password",
        &config,
        CryptoMode::Paranoid,
        false,
        |_| {},
    )
    .expect("paranoid encryption must succeed");

    let mut bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    bytes.truncate(bytes.len() - 1);
    fs::write(&encrypted, bytes).expect("truncated file must be written");

    let err = decrypt_file(&encrypted, &decrypted, "password", &config, false, |_| {})
        .expect_err("paranoid decryption must fail");
    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn tampered_paranoid_metadata_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("paranoid-metadata.bin");
    let encrypted = dir.path().join("paranoid-metadata.bin.encdata");
    let decrypted = dir.path().join("paranoid-metadata.bin.decoded");
    fs::write(&input, deterministic_bytes(140)).expect("input file must be written");

    let config = test_config(64);
    encrypt_file_with_mode(
        &input,
        &encrypted,
        "password",
        &config,
        CryptoMode::Paranoid,
        false,
        |_| {},
    )
    .expect("paranoid encryption must succeed");

    let mut bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    bytes[32] ^= 0x01;
    fs::write(&encrypted, bytes).expect("tampered file must be written");

    let err = decrypt_file(&encrypted, &decrypted, "password", &config, false, |_| {})
        .expect_err("paranoid decryption must fail");
    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn empty_file_wrong_password_fails_without_finalized_output() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("empty.bin");
    let encrypted = dir.path().join("empty.bin.encdata");
    let decrypted = dir.path().join("empty.bin.decoded");
    fs::write(&input, []).expect("empty input file must be written");

    let config = test_config(512);
    encrypt_file(&input, &encrypted, "right-password", &config, false, |_| {})
        .expect("encryption must succeed");

    let err = decrypt_file(
        &encrypted,
        &decrypted,
        "wrong-password",
        &config,
        false,
        |_| {},
    )
    .expect_err("decryption must fail");

    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn corrupted_empty_file_tag_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("empty.bin");
    let encrypted = dir.path().join("empty.bin.encdata");
    let decrypted = dir.path().join("empty.bin.decoded");
    fs::write(&input, []).expect("empty input file must be written");

    let config = test_config(512);
    encrypt_file(&input, &encrypted, "empty-case", &config, false, |_| {})
        .expect("encryption must succeed");

    let mut bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    assert_eq!(bytes.len(), FILE_PREFIX_LEN + TAG_LEN);
    bytes[FILE_PREFIX_LEN] ^= 0x5A;
    fs::write(&encrypted, bytes).expect("corrupted file must be written");

    let err = decrypt_file(&encrypted, &decrypted, "empty-case", &config, false, |_| {})
        .expect_err("decryption must fail");

    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn legacy_empty_file_without_tag_still_decrypts() {
    let dir = tempdir().expect("tempdir must be created");
    let encrypted = dir.path().join("legacy-empty.encdata");
    let decrypted = dir.path().join("legacy-empty.out");

    let mut legacy = Vec::new();
    legacy.extend_from_slice(&[1u8; 16]);
    legacy.extend_from_slice(&[2u8; 8]);
    legacy.extend_from_slice(&0u64.to_le_bytes());
    fs::write(&encrypted, legacy).expect("legacy encrypted file must be written");

    let config = test_config(512);
    decrypt_file(
        &encrypted,
        &decrypted,
        "any-password",
        &config,
        false,
        |_| {},
    )
    .expect("legacy empty file should remain supported");

    let decrypted_bytes = fs::read(&decrypted).expect("decrypted file must be readable");
    assert!(decrypted_bytes.is_empty());
}
