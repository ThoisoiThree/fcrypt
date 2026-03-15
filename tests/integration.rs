use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

use filecrypt::crypto::{CryptoConfig, FILE_PREFIX_LEN, TAG_LEN};
use filecrypt::error::AppError;
use filecrypt::file_ops::{decrypt_file, encrypt_file};
use filecrypt::overwrite::resolve_overwrite;
use filecrypt::pathing::{decryption_output_path, encryption_output_path};
use tempfile::tempdir;

fn test_config(chunk_size: usize) -> CryptoConfig {
    CryptoConfig {
        chunk_size,
        argon_memory_kib: 8,
        argon_time_cost: 1,
        argon_parallelism: 1,
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
        PathBuf::from("report.pdf.enc")
    );

    let p2 = Path::new("report.pdf.enc");
    assert_eq!(
        decryption_output_path(p2).expect("mapping must succeed"),
        PathBuf::from("report.pdf")
    );

    let p3 = Path::new("report.pdf.data");
    assert_eq!(
        decryption_output_path(p3).expect("mapping must succeed"),
        PathBuf::from("report.pdf.data.dec")
    );
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
        encrypted_len, FILE_PREFIX_LEN as u64,
        "empty file should contain only binary prefix"
    );

    let decrypted_bytes = fs::read(&decrypted).expect("decrypted file must be readable");
    assert!(decrypted_bytes.is_empty());
}
