use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
};

use assert_cmd::Command as AssertCommand;
use clap::Parser;
#[cfg(feature = "pqc")]
use fcrypt::asym;
use fcrypt::asym::cli::AssymCommand;
#[cfg(feature = "pqc")]
use fcrypt::asym::cli::{AssymDecryptArgs, AssymEncryptArgs, AssymSignArgs};
use fcrypt::asym::keys;
use fcrypt::cli::{Cli, Command as CliCommand};
use fcrypt::error::AppError;
use fcrypt::format::opaque;
use fcrypt::keygen::phrase;
use fcrypt::sym::crypto::{CryptoConfig, TAG_LEN};
use fcrypt::sym::file_ops::{decrypt_file, encrypt_file};
use fcrypt::sym::overwrite::resolve_overwrite;
use fcrypt::sym::pathing::{
    asym_decryption_output_path, asym_default_keys_dir_for_encrypted_input,
    asym_default_keys_dir_for_plain_input, asym_encryption_output_path, decryption_output_path,
    encryption_output_path,
};
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use tempfile::tempdir;

fn test_config(chunk_size: usize) -> CryptoConfig {
    CryptoConfig { chunk_size }
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn parallel_payload_roundtrips_across_thread_counts_and_rejects_tampering() {
    use fcrypt::sym::parallel::with_threads;
    let dir = tempdir().unwrap();
    let input = dir.path().join("input");
    let encrypted = dir.path().join("encrypted");
    let output = dir.path().join("output");
    let original = deterministic_bytes(1024 * 9 + 37);
    fs::write(&input, &original).unwrap();
    let config = test_config(1024);
    for (encrypt_threads, decrypt_threads) in [(1, 4), (4, 1), (4, 3)] {
        let mut encrypted_progress = 0;
        with_threads(encrypt_threads, || {
            encrypt_file(
                &input,
                &encrypted,
                "test-only-password",
                &config,
                true,
                |n| encrypted_progress += n,
            )
        })
        .unwrap();
        assert_eq!(encrypted_progress, original.len() as u64);
        with_threads(decrypt_threads, || {
            decrypt_file(
                &encrypted,
                &output,
                "test-only-password",
                &config,
                true,
                |_| {},
            )
        })
        .unwrap();
        assert_eq!(fs::read(&output).unwrap(), original);
    }
    let valid = fs::read(&encrypted).unwrap();
    for truncated in [false, true] {
        let mut damaged = valid.clone();
        if truncated {
            damaged.pop();
        } else {
            damaged[opaque::PRELUDE_LEN + 1024 + TAG_LEN + 7] ^= 1;
        }
        fs::write(&encrypted, damaged).unwrap();
        let sentinel = b"previous output must survive";
        fs::write(&output, sentinel).unwrap();
        assert!(with_threads(4, || decrypt_file(
            &encrypted,
            &output,
            "test-only-password",
            &config,
            true,
            |_| {},
        ))
        .is_err());
        assert_eq!(fs::read(&output).unwrap(), sentinel);
        let absent = dir.path().join("absent");
        assert!(with_threads(4, || decrypt_file(
            &encrypted,
            &absent,
            "test-only-password",
            &config,
            false,
            |_| {},
        ))
        .is_err());
        assert!(!absent.exists());
    }
}

#[test]
fn threads_option_parses_and_rejects_invalid_values() {
    for flag in ["--threads", "-t"] {
        for threads in ["0", "1", "4", "32"] {
            let cli = Cli::try_parse_from(["fcrypt", "encrypt", "input", flag, threads]).unwrap();
            assert_eq!(cli.threads.to_string(), threads);
            let cli = Cli::try_parse_from(["fcrypt", flag, threads, "decrypt", "input"]).unwrap();
            assert_eq!(cli.threads.to_string(), threads);
        }
        for threads in ["-1", "33", "abc"] {
            assert!(Cli::try_parse_from(["fcrypt", flag, threads, "encrypt", "input"]).is_err());
        }
    }
}

#[test]
fn encrypt_decrypt_roundtrip_small_file() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("small.bin");
    let encrypted = dir.path().join("small.bin.encdata");
    let decrypted = dir.path().join("small.bin.decoded");
    let original = b"hello from fcrypt".to_vec();
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
    let decrypt_config = CryptoConfig { chunk_size: 0 };
    decrypt_file(
        &encrypted,
        &decrypted,
        "correct horse battery staple",
        &decrypt_config,
        false,
        |_| {},
    )
    .expect("decryption must succeed");

    let decrypted_bytes = fs::read(&decrypted).expect("decrypted file must be readable");
    assert_eq!(decrypted_bytes, original);
}

#[test]
fn encrypt_preflight_rejects_oversized_payload_before_writing() {
    let config = test_config(1);
    let mut reader = std::io::empty();
    let mut writer = Vec::new();

    let err = fcrypt::sym::crypto::encrypt_stream(
        &mut reader,
        &mut writer,
        u64::MAX,
        "oversized",
        &config,
        |_| {},
    )
    .expect_err("oversized encrypted payload must be rejected");

    assert!(matches!(err, AppError::InputTooLarge));
    assert!(
        writer.is_empty(),
        "preflight failure must happen before writing the prelude"
    );
}

#[test]
fn opaque_password_encrypt_uses_fixed_argon_profile_without_decrypt_config() {
    let original = deterministic_bytes(48);
    let config = test_config(17);
    let mut reader = std::io::Cursor::new(original.as_slice());
    let mut encrypted = Vec::new();

    opaque::encrypt_password_stream(
        &mut reader,
        &mut encrypted,
        original.len() as u64,
        "fixed-profile",
        &config,
        |_| {},
    )
    .expect("opaque password encryption must succeed");

    let encrypted_len = encrypted.len() as u64;
    let mut encrypted_reader = std::io::Cursor::new(encrypted);
    let mut decrypted = Vec::new();
    opaque::decrypt_password_stream(
        &mut encrypted_reader,
        &mut decrypted,
        encrypted_len,
        "fixed-profile",
        |_| {},
    )
    .expect("opaque password decryption must use the fixed v1 Argon profile");

    assert_eq!(decrypted, original);
}

#[test]
fn opaque_password_encryption_rejects_empty_password_before_writing() {
    let config = test_config(64);
    let mut reader = std::io::empty();
    let mut encrypted = Vec::new();

    let err = opaque::encrypt_password_stream(&mut reader, &mut encrypted, 0, "", &config, |_| {})
        .expect_err("empty passwords must be rejected by the public API");

    assert!(matches!(err, AppError::EmptyPassword));
    assert!(encrypted.is_empty(), "no prelude may be written");
}

#[test]
fn decrypt_stream_ignores_runtime_config_for_format_params() {
    let original = deterministic_bytes(48);
    let encrypt_config = test_config(19);
    let mut reader = std::io::Cursor::new(original.as_slice());
    let mut encrypted = Vec::new();
    fcrypt::sym::crypto::encrypt_stream(
        &mut reader,
        &mut encrypted,
        original.len() as u64,
        "runtime-config",
        &encrypt_config,
        |_| {},
    )
    .expect("encryption must succeed");

    let encrypted_len = encrypted.len() as u64;
    let decrypt_config = CryptoConfig { chunk_size: 0 };
    let mut encrypted_reader = std::io::Cursor::new(encrypted);
    let mut decrypted = Vec::new();
    fcrypt::sym::crypto::decrypt_stream(
        &mut encrypted_reader,
        &mut decrypted,
        encrypted_len,
        "runtime-config",
        &decrypt_config,
        |_| {},
    )
    .expect("decrypt must ignore runtime config for opaque format parameters");

    assert_eq!(decrypted, original);
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
        bytes.len() > opaque::PRELUDE_LEN,
        "encrypted payload should exist"
    );
    bytes[opaque::PRELUDE_LEN] ^= 0x5A;
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
        PathBuf::from("report.pdf.bin")
    );

    let p2 = Path::new("report.pdf.bin");
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
        PathBuf::from("report.pdf.bin")
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

    let p3 = Path::new("report.pdf.bin");
    assert_eq!(
        asym_decryption_output_path(p3).expect("mapping must succeed"),
        PathBuf::from("report.pdf")
    );
    assert_eq!(
        asym_default_keys_dir_for_encrypted_input(p3).expect("keys dir must resolve"),
        PathBuf::from("report_keys")
    );
}

#[cfg(unix)]
#[test]
fn decryption_output_paths_preserve_non_utf8_file_names() {
    let password_input = PathBuf::from(OsString::from_vec(b"report-\xff.bin".to_vec()));
    let password_output = decryption_output_path(&password_input).expect("path must resolve");
    assert_eq!(
        password_output
            .file_name()
            .expect("output must have a file name")
            .as_bytes(),
        b"report-\xff"
    );

    let asym_input = PathBuf::from(OsString::from_vec(b"archive-\xff.bin".to_vec()));
    let asym_output = asym_decryption_output_path(&asym_input).expect("path must resolve");
    assert_eq!(
        asym_output
            .file_name()
            .expect("output must have a file name")
            .as_bytes(),
        b"archive-\xff"
    );
}

#[test]
fn cli_aliases_parse_to_same_commands() {
    assert!(matches!(
        Cli::parse_from(["fcrypt", "enc", "input"]).command,
        CliCommand::Encrypt(_)
    ));
    let dec = Cli::parse_from(["fcrypt", "dec", "input", "-v", "signer.pub"]);
    assert!(
        matches!(dec.command, CliCommand::Decrypt(args) if args.verify == Some(PathBuf::from("signer.pub")))
    );
    for group in ["asym", "assym"] {
        assert!(matches!(
            Cli::parse_from(["fcrypt", group, "enc", "input"]).command,
            CliCommand::Asym {
                command: AssymCommand::Encrypt(_)
            }
        ));
        assert!(matches!(
            Cli::parse_from(["fcrypt", group, "dec", "input", "-v", "signer.pub"]).command,
            CliCommand::Asym { command: AssymCommand::Decrypt(args) } if args.verify == Some(PathBuf::from("signer.pub"))
        ));
    }
    let encrypt = Cli::parse_from(["fcrypt", "encrypt", "notes.txt"]);
    let encode = Cli::parse_from(["fcrypt", "encode", "notes.txt"]);
    assert!(matches!(encrypt.command, CliCommand::Encrypt(_)));
    assert!(matches!(encode.command, CliCommand::Encrypt(_)));

    let decrypt = Cli::parse_from(["fcrypt", "decrypt", "notes.txt.bin"]);
    let decode = Cli::parse_from(["fcrypt", "decode", "notes.txt.bin"]);
    assert!(matches!(decrypt.command, CliCommand::Decrypt(_)));
    assert!(matches!(decode.command, CliCommand::Decrypt(_)));

    let asym = Cli::parse_from(["fcrypt", "asym", "encrypt", "notes.txt"]);
    let assym = Cli::parse_from(["fcrypt", "assym", "encode", "notes.txt"]);
    assert!(matches!(
        asym.command,
        CliCommand::Asym {
            command: AssymCommand::Encrypt(_)
        }
    ));
    assert!(matches!(
        assym.command,
        CliCommand::Asym {
            command: AssymCommand::Encrypt(_)
        }
    ));
}

#[test]
fn cli_version_aliases_print_the_same_version() {
    for flag in ["-v", "-V", "--version"] {
        AssertCommand::cargo_bin("fcrypt")
            .unwrap()
            .arg(flag)
            .assert()
            .success()
            .stdout(format!("fcrypt {}\n", env!("CARGO_PKG_VERSION")))
            .stderr("");
    }
}

#[test]
fn unified_cli_selects_password_or_pqc_from_credentials() {
    let password = Cli::parse_from(["fcrypt", "encrypt", "notes.txt"]);
    let recipient = Cli::parse_from(["fcrypt", "encrypt", "notes.txt", "--recipient", "alice.pub"]);
    let identity = Cli::parse_from([
        "fcrypt",
        "decrypt",
        "notes.txt.bin",
        "--identity",
        "alice.sec",
    ]);

    assert!(matches!(password.command, CliCommand::Encrypt(ref args) if !args.uses_pqc()));
    assert!(matches!(recipient.command, CliCommand::Encrypt(ref args) if args.uses_pqc()));
    assert!(matches!(identity.command, CliCommand::Decrypt(ref args) if args.uses_pqc()));
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
            .stdout(contains("fcrypt command reference"))
            .stdout(contains("fcrypt identity create alice"))
            .stdout(contains("Compatibility commands remain available"));
    }
}

#[test]
fn short_help_mentions_help_all_alias() {
    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .arg("-h")
        .assert()
        .success()
        .stdout(contains("fcrypt help-all"));
}

#[test]
fn password_file_preserves_spaces_and_removes_one_line_ending() {
    let dir = tempdir().expect("tempdir must be created");
    let unix = dir.path().join("unix-password");
    let windows = dir.path().join("windows-password");
    fs::write(&unix, b"  spaced password  \n").expect("password file must be written");
    fs::write(&windows, b"  spaced password  \r\n").expect("password file must be written");

    let unix_password =
        fcrypt::sym::password_file::read_password_file(&unix).expect("password file must read");
    let windows_password =
        fcrypt::sym::password_file::read_password_file(&windows).expect("password file must read");
    assert_eq!(unix_password.password.as_str(), "  spaced password  ");
    assert_eq!(windows_password.password.as_str(), "  spaced password  ");
}

#[test]
fn empty_password_file_is_rejected() {
    let dir = tempdir().expect("tempdir must be created");
    let password = dir.path().join("password");
    fs::write(&password, b"\n").expect("password file must be written");

    let err = match fcrypt::sym::password_file::read_password_file(&password) {
        Ok(_) => panic!("empty password file must fail"),
        Err(err) => err,
    };
    assert!(matches!(err, AppError::EmptyPassword));
}

fn fcrypt_cmd() -> AssertCommand {
    AssertCommand::cargo_bin("fcrypt").expect("binary must build")
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("test path must be utf-8")
}

#[test]
fn binary_key_file_roundtrips_with_long_and_short_options_without_password() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("cipher.bin");
    let decrypted = dir.path().join("plain.txt");
    let key = dir.path().join("photo.jpg");
    let original = deterministic_bytes(fcrypt::sym::crypto::DEFAULT_CHUNK_SIZE + 11);
    fs::write(&input, &original).expect("input must be written");
    let key_bytes: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
    fs::write(&key, &key_bytes).expect("key must be written");

    let output = fcrypt_cmd()
        .args([
            "--json",
            "encrypt",
            path_str(&input),
            "-o",
            path_str(&encrypted),
            "--key-file",
            path_str(&key),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value =
        serde_json::from_slice(&output).expect("JSON output must parse");
    assert_eq!(report["operation"], "encrypt");
    assert_eq!(report["mode"], "key_file");

    fcrypt_cmd()
        .args([
            "decrypt",
            path_str(&encrypted),
            "-o",
            path_str(&decrypted),
            "-K",
            path_str(&key),
            "--quiet",
        ])
        .assert()
        .success()
        .stdout("");
    assert_eq!(fs::read(&decrypted).expect("plaintext must read"), original);
}

#[test]
fn key_file_ciphertext_uses_the_unchanged_password_format() {
    use sha3::{Digest, Sha3_256};

    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.txt.bin");
    let decrypted = dir.path().join("plain.txt");
    let key = dir.path().join("key.bin");
    let password = dir.path().join("password.txt");
    fs::write(&input, b"same format").expect("input must be written");
    fs::write(&key, b"\x00\x01binary key\r\n").expect("key must be written");
    let mut hasher = Sha3_256::new();
    hasher.update(b"fcrypt key-file v1\0");
    hasher.update(b"\x00\x01binary key\r\n");
    fs::write(&password, hex::encode(hasher.finalize())).expect("password must be written");

    fcrypt_cmd()
        .args(["-q", "enc", path_str(&input), "-K", path_str(&key)])
        .assert()
        .success();
    fcrypt_cmd()
        .args([
            "-q",
            "decrypt",
            path_str(&encrypted),
            "-o",
            path_str(&decrypted),
            "--password-file",
            path_str(&password),
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&decrypted).expect("plaintext must read"),
        b"same format"
    );
}

#[test]
fn wrong_key_file_fails_without_plaintext_output() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("cipher.bin");
    let decrypted = dir.path().join("plain.txt");
    let key = dir.path().join("key");
    let other = dir.path().join("other");
    fs::write(&input, b"secret").expect("input must be written");
    fs::write(&key, b"key contents").expect("key must be written");
    fs::write(&other, b"key contents\n").expect("key must be written");

    fcrypt_cmd()
        .args([
            "-q",
            "encrypt",
            path_str(&input),
            "-o",
            path_str(&encrypted),
        ])
        .args(["-K", path_str(&key)])
        .assert()
        .success();
    fcrypt_cmd()
        .args(["decrypt", path_str(&encrypted), "-o", path_str(&decrypted)])
        .args(["--key-file", path_str(&other)])
        .assert()
        .failure()
        .stderr(contains("Decryption failed"));
    assert!(!decrypted.exists());
}

#[test]
fn empty_missing_or_reused_key_file_is_rejected_before_writing() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("cipher.bin");
    let empty = dir.path().join("empty");
    fs::write(&input, b"secret").expect("input must be written");
    fs::write(&empty, b"").expect("key must be written");
    fs::write(&encrypted, b"existing").expect("output must be written");

    fcrypt_cmd()
        .args([
            "encrypt",
            path_str(&input),
            "-o",
            path_str(&encrypted),
            "-f",
        ])
        .args(["-K", path_str(&empty)])
        .assert()
        .failure()
        .stderr(contains("key file is empty"));
    fcrypt_cmd()
        .args([
            "encrypt",
            path_str(&input),
            "-o",
            path_str(&encrypted),
            "-f",
        ])
        .args(["-K", path_str(&dir.path().join("missing"))])
        .assert()
        .failure();
    fcrypt_cmd()
        .args([
            "encrypt",
            path_str(&input),
            "-o",
            path_str(&encrypted),
            "-f",
        ])
        .args(["-K", path_str(&encrypted)])
        .assert()
        .failure()
        .stderr(contains("key file must not be the output file"));
    fcrypt_cmd()
        .args([
            "encrypt",
            path_str(&input),
            "-o",
            path_str(&encrypted),
            "-f",
        ])
        .args(["-K", path_str(&input)])
        .assert()
        .failure()
        .stderr(contains("key file must not be the input file"));
    fcrypt_cmd()
        .args([
            "encrypt",
            path_str(&input),
            "-o",
            path_str(&encrypted),
            "-f",
        ])
        .args(["-K", path_str(dir.path())])
        .assert()
        .failure();
    assert_eq!(fs::read(&encrypted).expect("output must read"), b"existing");
}

#[test]
fn key_file_mixed_with_password_requires_both_to_decrypt() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("cipher.bin");
    let decrypted = dir.path().join("plain.txt");
    let key = dir.path().join("key.bin");
    let password = dir.path().join("password.txt");
    let wrong_password = dir.path().join("wrong.txt");
    fs::write(&input, b"mixed secret").expect("input must be written");
    fs::write(&key, b"\x10\x20 key material").expect("key must be written");
    fs::write(&password, b"correct horse\n").expect("password must be written");
    fs::write(&wrong_password, b"correct horse!\n").expect("password must be written");

    let output = fcrypt_cmd()
        .args([
            "--json",
            "encrypt",
            path_str(&input),
            "-o",
            path_str(&encrypted),
        ])
        .args(["-K", path_str(&key), "--password-file", path_str(&password)])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value =
        serde_json::from_slice(&output).expect("JSON output must parse");
    assert_eq!(report["mode"], "key_file");
    assert!(!String::from_utf8_lossy(&output).contains("correct horse"));

    // Non-interactive stdin: the optional password is skipped (empty).
    fcrypt_cmd()
        .args(["decrypt", path_str(&encrypted), "-o", path_str(&decrypted)])
        .args(["-K", path_str(&key)])
        .assert()
        .failure()
        .stderr(contains("Decryption failed"));
    assert!(!decrypted.exists());
    fcrypt_cmd()
        .args(["decrypt", path_str(&encrypted), "-o", path_str(&decrypted)])
        .args(["-K", path_str(&key), "--password-file"])
        .arg(path_str(&wrong_password))
        .assert()
        .failure()
        .stderr(contains("Decryption failed"));
    assert!(!decrypted.exists());
    fcrypt_cmd()
        .args(["decrypt", path_str(&encrypted), "-o", path_str(&decrypted)])
        .args(["--password-file", path_str(&password)])
        .assert()
        .failure()
        .stderr(contains("Decryption failed"));
    assert!(!decrypted.exists());

    fcrypt_cmd()
        .args([
            "-q",
            "decrypt",
            path_str(&encrypted),
            "-o",
            path_str(&decrypted),
        ])
        .args([
            "--key-file",
            path_str(&key),
            "--password-file",
            path_str(&password),
        ])
        .assert()
        .success()
        .stdout("");
    assert_eq!(
        fs::read(&decrypted).expect("plaintext must read"),
        b"mixed secret"
    );
}

#[test]
fn key_file_without_terminal_skips_the_optional_password() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("cipher.bin");
    let decrypted = dir.path().join("plain.txt");
    let key = dir.path().join("key");
    fs::write(&input, b"key only").expect("input must be written");
    fs::write(&key, b"key only material").expect("key must be written");

    fcrypt_cmd()
        .args(["encrypt", path_str(&input), "-o", path_str(&encrypted)])
        .args(["-K", path_str(&key)])
        .write_stdin("typed password\n")
        .assert()
        .success()
        .stderr(contains("Enter password").not());
    fcrypt_cmd()
        .args([
            "-q",
            "decrypt",
            path_str(&encrypted),
            "-o",
            path_str(&decrypted),
        ])
        .args(["-K", path_str(&key)])
        .assert()
        .success();
    assert_eq!(
        fs::read(&decrypted).expect("plaintext must read"),
        b"key only"
    );
}

#[test]
fn key_file_conflicts_with_other_credentials() {
    for args in [
        vec![
            "fcrypt",
            "encrypt",
            "in",
            "--key-file",
            "k",
            "--recipient",
            "r.pub",
        ],
        vec![
            "fcrypt",
            "encrypt",
            "in",
            "--key-file",
            "k",
            "--sign-key",
            "s.sec",
        ],
        vec![
            "fcrypt",
            "decrypt",
            "in.bin",
            "--key-file",
            "k",
            "--identity",
            "i.sec",
        ],
        vec![
            "fcrypt",
            "decrypt",
            "in.bin",
            "--key-file",
            "k",
            "--verify",
            "v.pub",
        ],
    ] {
        assert!(
            Cli::try_parse_from(&args).is_err(),
            "{args:?} must conflict"
        );
    }
    let parsed = Cli::parse_from([
        "fcrypt",
        "decrypt",
        "in.bin",
        "-K",
        "k",
        "--password-file",
        "p",
    ]);
    assert!(matches!(
        parsed.command,
        CliCommand::Decrypt(ref args)
            if !args.uses_pqc() && args.key_file.is_some() && args.password_file.is_some()
    ));
}

#[test]
fn unified_password_cli_supports_output_and_json() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("cipher.bin");
    let decrypted = dir.path().join("plain.txt");
    let password = dir.path().join("password.txt");
    let original = deterministic_bytes(2 * fcrypt::sym::crypto::DEFAULT_CHUNK_SIZE + 37);
    fs::write(&input, &original).expect("input must be written");
    fs::write(&password, b"test password\n").expect("password must be written");

    let output = AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args([
            "--json",
            "--threads",
            "4",
            "encrypt",
            input.to_str().expect("input path must be utf-8"),
            "--output",
            encrypted.to_str().expect("output path must be utf-8"),
            "--password-file",
            password.to_str().expect("password path must be utf-8"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value =
        serde_json::from_slice(&output).expect("JSON output must parse");
    assert_eq!(report["operation"], "encrypt");
    assert_eq!(report["mode"], "password");
    assert!(!String::from_utf8_lossy(&output).contains("test password"));

    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args([
            "decrypt",
            encrypted.to_str().expect("input path must be utf-8"),
            "--output",
            decrypted.to_str().expect("output path must be utf-8"),
            "--password-file",
            password.to_str().expect("password path must be utf-8"),
            "--quiet",
            "--threads",
            "2",
        ])
        .assert()
        .success()
        .stdout("");
    assert_eq!(
        fs::read(&decrypted).expect("decrypted file must read"),
        original
    );
}

#[test]
fn new_password_and_phrase_commands_generate_output() {
    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args(["password", "generate", "--length", "24"])
        .assert()
        .success();
    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args(["phrase", "generate", "--words", "4"])
        .assert()
        .success();
}

#[test]
fn password_generate_supports_base64_and_compatible_output() {
    let base64_output = AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args(["password", "generate", "--length", "24", "-b"])
        .output()
        .expect("password generation must run");
    assert!(base64_output.status.success());
    let encoded = String::from_utf8(base64_output.stdout).expect("output must be UTF-8");
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded.trim_end(),
    )
    .expect("output must be valid Base64");
    assert_eq!(decoded.len(), 24);

    let compatible_output = AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args(["password", "generate", "--length", "256", "-c"])
        .output()
        .expect("password generation must run");
    assert!(compatible_output.status.success());
    let password = compatible_output.stdout.strip_suffix(b"\n").unwrap();
    assert_eq!(password.len(), 256);
    assert!(password
        .iter()
        .all(|byte| fcrypt::keygen::password::COMPATIBLE_PASSWORD_ALPHABET.contains(byte)));

    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args(["password", "generate", "--length", "24", "-b64"])
        .assert()
        .success();
}

#[test]
fn password_generate_help_lists_short_options() {
    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args(["password", "generate", "--help"])
        .assert()
        .success()
        .stdout(contains("-b, --base64"))
        .stdout(contains("-c, --compatible"));
}

#[cfg(feature = "pqc")]
#[test]
fn unified_pqc_cli_identity_sign_verify_and_decrypt_roundtrip() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("report.txt");
    let encrypted = dir.path().join("report.bin");
    let decrypted = dir.path().join("report.out");
    fs::write(&input, b"unified pqc workflow").expect("input must be written");

    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .current_dir(dir.path())
        .args(["identity", "create", "alice", "--quiet"])
        .assert()
        .success();

    let recipient_public = dir.path().join("alice_recipient_default.pub");
    let recipient_secret = dir.path().join("alice_recipient_default.sec");
    let signing_public = dir.path().join("alice_signer_mldsa87.pub");
    let signing_secret = dir.path().join("alice_signer_mldsa87.sec");
    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args([
            "encrypt",
            input.to_str().expect("input path must be utf-8"),
            "--output",
            encrypted.to_str().expect("output path must be utf-8"),
            "--recipient",
            recipient_public.to_str().expect("key path must be utf-8"),
            "--sign",
            "--sign-key",
            signing_secret.to_str().expect("key path must be utf-8"),
            "--quiet",
        ])
        .assert()
        .success();

    let verification = AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args([
            "--json",
            "verify",
            encrypted.to_str().expect("ciphertext path must be utf-8"),
            "--key",
            signing_public.to_str().expect("key path must be utf-8"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let verification: serde_json::Value =
        serde_json::from_slice(&verification).expect("verification JSON must parse");
    assert_eq!(verification["verified"], true);

    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args([
            "decrypt",
            encrypted.to_str().expect("ciphertext path must be utf-8"),
            "--output",
            decrypted.to_str().expect("output path must be utf-8"),
            "--identity",
            recipient_secret.to_str().expect("key path must be utf-8"),
            "--verify",
            signing_public.to_str().expect("key path must be utf-8"),
            "--quiet",
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&decrypted).expect("decrypted file must read"),
        b"unified pqc workflow"
    );
}

#[cfg(feature = "pqc")]
#[test]
fn identity_list_and_inspect_json_never_expose_secret_material() {
    let dir = tempdir().expect("tempdir must be created");
    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .current_dir(dir.path())
        .args(["identity", "create", "alice", "--quiet"])
        .assert()
        .success();
    let secret_path = dir.path().join("alice_recipient_default.sec");
    let secret = json_field(&secret_path, "mlkem1024_secret");

    let list = AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args([
            "--json",
            "identity",
            "list",
            "--keys-dir",
            dir.path().to_str().expect("directory path must be utf-8"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let list: serde_json::Value = serde_json::from_slice(&list).expect("list JSON must parse");
    assert_eq!(list["operation"], "identity_list");
    assert_eq!(
        list["data"]
            .as_array()
            .expect("data must be an array")
            .len(),
        4
    );
    assert!(!list.to_string().contains(&secret));

    let inspect = AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .args([
            "--json",
            "identity",
            "inspect",
            secret_path.to_str().expect("key path must be utf-8"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(!String::from_utf8_lossy(&inspect).contains(&secret));
}

#[cfg(feature = "pqc")]
#[test]
fn new_identity_encryption_failure_preserves_existing_keys_and_ciphertext() {
    let dir = tempdir().expect("tempdir must be created");
    let keys_dir = dir.path().join("keys");
    let generated = keys::generate_named_key_pair_files(&keys_dir, "alice", None, false)
        .expect("original identity must be generated");
    let paths = [
        generated.recipient_public_path,
        generated.recipient_secret_path,
        generated.signing_public_path,
        generated.signing_secret_path,
    ];
    let originals = paths
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect::<Vec<_>>();
    let input = dir.path().join("input.txt");
    let output = dir.path().join("output.bin");
    let signature = dir.path().join("output.bin.sig");
    fs::write(&output, b"previous ciphertext").unwrap();

    let refused = AssertCommand::cargo_bin("fcrypt")
        .unwrap()
        .arg("encrypt")
        .arg(&input)
        .arg("--output")
        .arg(dir.path().join("unpublished.bin"))
        .args(["--new-identity", "alice", "--keys-dir"])
        .arg(&keys_dir)
        .arg("--json")
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&refused).unwrap();
    assert_eq!(report["error"]["kind"], "output_exists");
    assert!(!dir.path().join("unpublished.bin").exists());

    for missing_input in [true, false] {
        if !missing_input {
            fs::write(&input, b"new plaintext").unwrap();
            fs::create_dir(&signature).unwrap();
        }
        let result = AssertCommand::cargo_bin("fcrypt")
            .unwrap()
            .arg("encrypt")
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .args(["--new-identity", "alice", "--keys-dir"])
            .arg(&keys_dir)
            .args(["--sign", "--force", "--json"])
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();
        let report: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(report["status"], "error");
        for (path, original) in paths.iter().zip(&originals) {
            assert_eq!(&fs::read(path).unwrap(), original);
        }
        assert_eq!(fs::read(&output).unwrap(), b"previous ciphertext");
        assert_eq!(fs::read_dir(&keys_dir).unwrap().count(), 4);
    }
}

#[cfg(feature = "pqc")]
#[test]
fn new_identity_encryption_publishes_usable_keys_and_signature() {
    let dir = tempdir().expect("tempdir must be created");
    for mode in ["--json", "--quiet", "--no-progress"] {
        let work = dir.path().join(mode.trim_start_matches('-'));
        fs::create_dir(&work).unwrap();
        fs::write(work.join("input.txt"), b"transactional encryption").unwrap();
        let result = AssertCommand::cargo_bin("fcrypt")
            .unwrap()
            .current_dir(&work)
            .args([
                "encrypt",
                "input.txt",
                "--new-identity",
                "alice",
                "--keys-dir",
                "keys",
                "--sign",
                mode,
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        match mode {
            "--json" => {
                let report: serde_json::Value = serde_json::from_slice(&result).unwrap();
                assert_eq!(report["status"], "ok");
                assert_eq!(report["generated_keys"].as_array().unwrap().len(), 4);
                assert!(report["signature"].is_string());
            }
            "--quiet" => assert!(result.is_empty()),
            _ => assert!(String::from_utf8(result)
                .unwrap()
                .contains("Encryption complete")),
        }
        asym::decrypt::decrypt_file(
            &AssymDecryptArgs {
                input: work.join("input.txt.bin"),
                output: Some(work.join("recovered.txt")),
                identity: Some(work.join("keys/alice_recipient_default.sec")),
                keys_dir: None,
                verify: Some(work.join("keys/alice_signer_mldsa87.pub")),
                require_signature: true,
                force: false,
            },
            |_| {},
        )
        .expect("published keys and signature must decrypt the ciphertext");
        assert_eq!(
            fs::read(work.join("recovered.txt")).unwrap(),
            b"transactional encryption"
        );
        assert_eq!(fs::read_dir(work.join("keys")).unwrap().count(), 4);
    }
}

#[cfg(feature = "pqc")]
#[test]
fn late_key_collision_is_not_overwritten_by_ciphertext_force() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.txt");
    let output = dir.path().join("output.bin");
    let keys_dir = dir.path().join("keys");
    let collision = keys_dir.join("alice_recipient_default.sec");
    fs::write(&input, b"new plaintext").unwrap();
    fs::write(&output, b"old ciphertext").unwrap();
    let result = asym::encrypt::encrypt_file_with_new_identity(
        &AssymEncryptArgs {
            input,
            output: Some(output.clone()),
            recipient_public: None,
            keys_dir: Some(keys_dir.clone()),
            sign: true,
            sign_key: None,
            force: true,
        },
        "alice",
        false,
        &test_config(64),
        |_| fs::write(&collision, b"concurrent key").unwrap(),
    );
    assert!(matches!(result, Err(AppError::OutputExists(_))));
    assert_eq!(fs::read(&collision).unwrap(), b"concurrent key");
    assert_eq!(fs::read(&output).unwrap(), b"old ciphertext");
    assert_eq!(fs::read_dir(keys_dir).unwrap().count(), 1);
    assert!(!dir.path().join("output.bin.sig").exists());
}

#[cfg(feature = "pqc")]
#[test]
fn failed_automatic_encryption_and_signing_leave_no_generated_keys() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.txt");
    let output = dir.path().join("output.bin");
    let signature = dir.path().join("output.bin.sig");
    let keys_dir = dir.path().join("keys");
    fs::write(&input, b"plaintext").unwrap();
    fs::create_dir(&signature).unwrap();
    let result = asym::encrypt::encrypt_file(
        &AssymEncryptArgs {
            input: input.clone(),
            output: Some(output.clone()),
            recipient_public: None,
            keys_dir: Some(keys_dir.clone()),
            sign: true,
            sign_key: None,
            force: true,
        },
        &test_config(64),
        |_| {},
    );
    assert!(result.is_err());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(&keys_dir).unwrap().count(), 0);

    let result = asym::sign::sign_file(&AssymSignArgs {
        input,
        output: Some(signature),
        sign_key: None,
        keys_dir: Some(keys_dir.clone()),
        embed: false,
        force: true,
    });
    assert!(result.is_err());
    assert_eq!(fs::read_dir(keys_dir).unwrap().count(), 0);
}

#[cfg(feature = "pqc")]
#[test]
fn forced_keyset_failure_restores_previously_published_files() {
    let dir = tempdir().expect("tempdir must be created");
    let generated = keys::generate_named_key_pair_files(dir.path(), "alice", None, false)
        .expect("initial key pair must be generated");
    let original_public = fs::read(&generated.recipient_public_path).expect("public key must read");
    let original_secret = fs::read(&generated.recipient_secret_path).expect("secret key must read");
    fs::remove_file(&generated.signing_public_path).expect("signing public key must be removed");
    fs::create_dir(&generated.signing_public_path).expect("blocking directory must be created");

    let err = match keys::generate_named_key_pair_files(dir.path(), "alice", None, true) {
        Ok(_) => panic!("publication must fail when one destination is a directory"),
        Err(err) => err,
    };
    assert!(matches!(err, AppError::Io(_)));
    assert_eq!(
        fs::read(&generated.recipient_public_path).expect("public key must read"),
        original_public
    );
    assert_eq!(
        fs::read(&generated.recipient_secret_path).expect("secret key must read"),
        original_secret
    );
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
fn keygen_pair_cli_generates_named_non_expiring_keys() {
    let dir = tempdir().expect("tempdir must be created");

    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .current_dir(dir.path())
        .args(["keygen", "pair", "alice"])
        .assert()
        .success()
        .stdout(contains("alice_recipient_default.pub"))
        .stdout(contains("alice_recipient_default.sec"))
        .stdout(contains("alice_signer_mldsa87.pub"))
        .stdout(contains("alice_signer_mldsa87.sec"));

    let recipient_public = dir.path().join("alice_recipient_default.pub");
    let recipient_secret = dir.path().join("alice_recipient_default.sec");
    let signing_public = dir.path().join("alice_signer_mldsa87.pub");
    let signing_secret = dir.path().join("alice_signer_mldsa87.sec");
    assert!(recipient_public.exists());
    assert!(recipient_secret.exists());
    assert!(signing_public.exists());
    assert!(signing_secret.exists());
    keys::read_recipient_public_key(&recipient_public).expect("recipient public key must read");
    keys::read_recipient_secret_key(&recipient_secret).expect("recipient secret key must read");
    keys::read_signing_public_key(&signing_public).expect("signing public key must read");
    keys::read_signing_secret_key(&signing_secret).expect("signing secret key must read");

    let recipient_secret_json = json_value(&recipient_secret);
    assert!(recipient_secret_json.get("created_at_unix").is_some());
    assert!(recipient_secret_json.get("expires_at_unix").is_none());
}

#[cfg(feature = "pqc")]
#[test]
fn keygen_pair_cli_accepts_lifetime_days() {
    let dir = tempdir().expect("tempdir must be created");

    AssertCommand::cargo_bin("fcrypt")
        .expect("binary must build")
        .current_dir(dir.path())
        .args(["keygen", "pair", "bob", "30"])
        .assert()
        .success();

    let recipient_secret = dir.path().join("bob_recipient_default.sec");
    let signing_secret = dir.path().join("bob_signer_mldsa87.sec");
    keys::read_recipient_secret_key(&recipient_secret).expect("recipient secret key must read");
    keys::read_signing_secret_key(&signing_secret).expect("signing secret key must read");

    let recipient_secret_json = json_value(&recipient_secret);
    let created_at = recipient_secret_json
        .get("created_at_unix")
        .and_then(|value| value.as_u64())
        .expect("created_at_unix must be present");
    let expires_at = recipient_secret_json
        .get("expires_at_unix")
        .and_then(|value| value.as_u64())
        .expect("expires_at_unix must be present");
    assert_eq!(expires_at - created_at, 30 * 86_400);
}

#[cfg(all(feature = "pqc", unix))]
#[test]
fn named_key_generation_preserves_existing_directory_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("tempdir must be created");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))
        .expect("directory permissions must be set");

    keys::generate_named_key_pair_files(dir.path(), "permissions", None, false)
        .expect("key pair must be generated");

    assert_eq!(
        fs::metadata(dir.path())
            .expect("directory metadata must read")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[cfg(feature = "pqc")]
#[test]
fn named_key_generation_preflights_all_paths_before_writing() {
    let dir = tempdir().expect("tempdir must be created");
    let conflict = dir.path().join("broken_signer_mldsa87.pub");
    fs::write(&conflict, b"existing key").expect("conflict file must be written");

    let err = match keys::generate_named_key_pair_files(dir.path(), "broken", None, false) {
        Ok(_) => panic!("an existing destination must fail before any key is published"),
        Err(err) => err,
    };

    assert!(matches!(err, AppError::OutputExists(path) if path == conflict));
    assert!(!dir.path().join("broken_recipient_default.pub").exists());
    assert!(!dir.path().join("broken_recipient_default.sec").exists());
    assert!(!dir.path().join("broken_signer_mldsa87.sec").exists());
    assert_eq!(
        fs::read(conflict).expect("conflict must remain readable"),
        b"existing key"
    );
}

#[cfg(feature = "pqc")]
#[test]
fn recipient_auto_discovery_skips_malformed_key_files() {
    let dir = tempdir().expect("tempdir must be created");
    keys::generate_named_key_pair_files(dir.path(), "valid", None, false)
        .expect("valid key pair must be generated");
    fs::write(
        dir.path().join("00000000_recipient_default.sec"),
        b"not json",
    )
    .expect("malformed key must be written");

    let identities = keys::read_recipient_secret_keys(dir.path())
        .expect("valid identities must still be discovered");

    assert_eq!(identities.len(), 1);
}

#[cfg(feature = "pqc")]
#[test]
fn expired_recipient_secrets_decrypt_and_expired_signing_public_keys_verify() {
    let dir = tempdir().expect("tempdir must be created");
    let generated = keys::generate_named_key_pair_files(dir.path(), "expired", None, false)
        .expect("key pair must be generated");
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.bin");
    let output = dir.path().join("output.txt");
    let original = b"archived data";
    fs::write(&input, original).expect("input must be written");

    asym::encrypt::encrypt_file(
        &AssymEncryptArgs {
            input,
            output: Some(encrypted.clone()),
            recipient_public: Some(generated.recipient_public_path.clone()),
            keys_dir: None,
            sign: false,
            sign_key: Some(generated.signing_secret_path.clone()),
            force: false,
        },
        &test_config(64),
        |_| {},
    )
    .expect("signed ciphertext must be created before expiration");

    set_key_lifetime(&generated.recipient_public_path, 0, 1);
    set_key_lifetime(&generated.recipient_secret_path, 0, 1);
    set_key_lifetime(&generated.signing_public_path, 0, 1);
    set_key_lifetime(&generated.signing_secret_path, 0, 1);

    assert!(keys::read_recipient_public_key(&generated.recipient_public_path).is_err());
    assert!(keys::read_signing_secret_key(&generated.signing_secret_path).is_err());
    assert!(keys::read_recipient_secret_key(&generated.recipient_secret_path).is_ok());
    assert!(keys::read_signing_public_key(&generated.signing_public_path).is_ok());

    asym::decrypt::decrypt_file(
        &AssymDecryptArgs {
            input: encrypted,
            output: Some(output.clone()),
            identity: Some(generated.recipient_secret_path),
            keys_dir: None,
            verify: Some(generated.signing_public_path),
            require_signature: true,
            force: false,
        },
        |_| {},
    )
    .expect("expired decryption and verification keys must remain usable for archives");

    assert_eq!(fs::read(output).expect("output must read"), original);
}

#[cfg(feature = "pqc")]
#[test]
fn secret_key_debug_output_is_redacted() {
    let dir = tempdir().expect("tempdir must be created");
    let generated = keys::generate_named_key_pair_files(dir.path(), "redacted", None, false)
        .expect("key pair must be generated");
    let serialized_secret = json_field(&generated.recipient_secret_path, "mlkem1024_secret");
    let secret = keys::read_recipient_secret_key(&generated.recipient_secret_path)
        .expect("secret key must be readable");

    let debug = format!("{secret:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&serialized_secret));
}

#[test]
fn recipient_key_auto_discovery_is_bounded_before_parsing_keys() {
    let dir = tempdir().expect("tempdir must be created");
    for index in 0..=keys::MAX_AUTO_DISCOVERED_RECIPIENT_IDENTITIES {
        let path = dir
            .path()
            .join(format!("{index:08x}_recipient_default.sec"));
        fs::write(path, b"not json").expect("dummy key file must be written");
    }

    let err = keys::read_recipient_secret_keys(dir.path())
        .expect_err("too many identities must be rejected before key parsing");

    assert!(matches!(
        err,
        AppError::TooManyRecipientIdentities {
            found,
            limit
        } if found == keys::MAX_AUTO_DISCOVERED_RECIPIENT_IDENTITIES + 1
            && limit == keys::MAX_AUTO_DISCOVERED_RECIPIENT_IDENTITIES
    ));
}

#[test]
fn oversized_asymmetric_key_file_is_rejected_before_json_parsing() {
    let dir = tempdir().expect("tempdir must be created");
    let key = dir.path().join("oversized_recipient_default.pub");
    fs::write(
        &key,
        vec![b' '; keys::MAX_ASYMMETRIC_KEY_FILE_BYTES as usize + 1],
    )
    .expect("oversized key fixture must be written");

    let err = keys::read_recipient_public_key(&key)
        .expect_err("oversized key files must be rejected before parsing");
    assert!(matches!(
        err,
        AppError::InvalidAsymmetricKeyFile(message) if message.contains("exceeds")
    ));
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

    assert_eq!(outcome.output, dir.path().join("report.pdf.bin"));
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
    let encrypted_bytes = fs::read(&outcome.output).expect("encrypted output must be readable");
    assert!(encrypted_bytes.len() > opaque::PRELUDE_LEN);
    assert_ne!(&encrypted_bytes[..8], b"FCRYPTFE");
    assert_ne!(&encrypted_bytes[..8], b"FCRYPTH1");

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
fn asymmetric_roundtrip_with_detached_signature_verification() {
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
    let detached_signature = outcome
        .detached_signature
        .expect("detached signature path must be returned");
    assert_key_name(&signer_public, "_signer_mldsa87.pub");
    assert_key_name(&signer_secret, "_signer_mldsa87.sec");
    assert!(detached_signature.exists());

    let unverified_output = dir.path().join("signed.unverified.out");
    let unverified_err = asym::decrypt::decrypt_file(
        &AssymDecryptArgs {
            input: outcome.output.clone(),
            output: Some(unverified_output.clone()),
            identity: Some(recipient_secret.clone()),
            keys_dir: None,
            verify: None,
            require_signature: false,
            force: false,
        },
        |_| {},
    )
    .expect_err("an existing detached signature must not be silently ignored");
    assert!(matches!(
        unverified_err,
        AppError::SignatureVerificationKeyRequired
    ));
    assert!(!unverified_output.exists());

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

    fs::remove_file(detached_signature).expect("detached signature must be removable");
    let stripped_output = dir.path().join("signed.stripped.out");
    let stripped_err = asym::decrypt::decrypt_file(
        &AssymDecryptArgs {
            input: decrypt_args.input,
            output: Some(stripped_output.clone()),
            identity: decrypt_args.identity,
            keys_dir: None,
            verify: None,
            require_signature: false,
            force: false,
        },
        |_| {},
    )
    .expect_err("authenticated signing intent must detect a removed detached signature");
    assert!(matches!(
        stripped_err,
        AppError::SignatureVerificationKeyRequired
    ));
    assert!(!stripped_output.exists());
}

#[cfg(feature = "pqc")]
#[test]
fn oversized_detached_signature_is_rejected_before_json_parsing() {
    let dir = tempdir().expect("tempdir must be created");
    let generated = keys::generate_named_key_pair_files(dir.path(), "signature-limit", None, false)
        .expect("key pair must be generated");
    let input = dir.path().join("ciphertext.bin");
    let signature = dir.path().join("ciphertext.bin.sig");
    fs::write(&input, b"ciphertext").expect("input must be written");
    fs::write(
        &signature,
        vec![b' '; asym::sign::MAX_DETACHED_SIGNATURE_FILE_BYTES as usize + 1],
    )
    .expect("oversized signature fixture must be written");

    let err = match asym::sign::verify_file(&input, &generated.signing_public_path) {
        Ok(_) => panic!("oversized detached signatures must be rejected before parsing"),
        Err(error) => error,
    };
    assert!(matches!(
        err,
        AppError::InvalidAsymmetricFile(message) if message.contains("exceeds")
    ));
}

#[cfg(feature = "pqc")]
#[test]
fn signed_asymmetric_encryption_keeps_existing_ciphertext_when_signature_publish_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let generated = keys::generate_named_key_pair_files(dir.path(), "transaction", None, false)
        .expect("key pair must be generated");
    let input = dir.path().join("input.txt");
    let output = dir.path().join("output.bin");
    let signature = dir.path().join("output.bin.sig");
    let previous_ciphertext = b"previous ciphertext";
    fs::write(&input, deterministic_bytes(96)).expect("input must be written");
    fs::write(&output, previous_ciphertext).expect("existing ciphertext must be written");
    fs::create_dir(&signature).expect("blocking signature directory must be created");

    let err = match asym::encrypt::encrypt_file(
        &AssymEncryptArgs {
            input,
            output: Some(output.clone()),
            recipient_public: Some(generated.recipient_public_path),
            keys_dir: None,
            sign: false,
            sign_key: Some(generated.signing_secret_path),
            force: true,
        },
        &test_config(48),
        |_| {},
    ) {
        Ok(_) => panic!("ciphertext and signature must be published as one transaction"),
        Err(error) => error,
    };

    assert!(matches!(err, AppError::Io(_)));
    assert_eq!(
        fs::read(&output).expect("existing ciphertext must remain readable"),
        previous_ciphertext
    );
    assert!(signature.is_dir());
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
    assert_eq!(sign_outcome.output, dir.path().join("detached.bin.bin.sig"));
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
    json_value(path)
        .get(field)
        .and_then(|value| value.as_str())
        .expect("json field must be a string")
        .to_string()
}

#[cfg(feature = "pqc")]
fn json_value(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).expect("json key file must be readable"))
        .expect("json key file must parse")
}

#[cfg(feature = "pqc")]
fn set_key_lifetime(path: &Path, created_at_unix: u64, expires_at_unix: u64) {
    let mut value = json_value(path);
    value["created_at_unix"] = serde_json::Value::from(created_at_unix);
    value["expires_at_unix"] = serde_json::Value::from(expires_at_unix);
    fs::write(
        path,
        serde_json::to_vec(&value).expect("key JSON must serialize"),
    )
    .expect("key JSON must be updated");
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
        (opaque::PRELUDE_LEN + TAG_LEN) as u64,
        "empty file should contain opaque prelude and authentication tag"
    );

    let decrypted_bytes = fs::read(&decrypted).expect("decrypted file must be readable");
    assert!(decrypted_bytes.is_empty());
}

#[test]
fn opaque_encryption_uses_fixed_prelude_without_legacy_magic() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("opaque-format.bin");
    let encrypted = dir.path().join("opaque-format.bin.encdata");
    let original = deterministic_bytes(96);
    fs::write(&input, &original).expect("input file must be written");

    let config = test_config(64);
    encrypt_file(&input, &encrypted, "opaque-format", &config, false, |_| {})
        .expect("encryption must succeed");

    let bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    assert_eq!(
        bytes.len() as u64,
        opaque::PRELUDE_LEN as u64
            + fcrypt::sym::crypto::expected_ciphertext_payload_len(
                original.len() as u64,
                config.chunk_size,
            )
            .expect("expected length must be calculated")
    );
    assert_ne!(&bytes[..8], b"FCRYPTH1");
    assert_ne!(&bytes[..8], b"FCRYPTFE");
}

#[test]
fn opaque_roundtrip_small_file() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("opaque.bin");
    let encrypted = dir.path().join("opaque.bin.encdata");
    let decrypted = dir.path().join("opaque.bin.decoded");
    let original = deterministic_bytes(150);
    fs::write(&input, &original).expect("input file must be written");

    let config = test_config(64);
    encrypt_file(
        &input,
        &encrypted,
        "opaque-password",
        &config,
        false,
        |_| {},
    )
    .expect("encryption must succeed");
    decrypt_file(
        &encrypted,
        &decrypted,
        "opaque-password",
        &config,
        false,
        |_| {},
    )
    .expect("decryption must succeed");

    let decrypted_bytes = fs::read(&decrypted).expect("decrypted file must be readable");
    assert_eq!(decrypted_bytes, original);
}

#[test]
fn opaque_wrong_password_fails_without_finalized_output() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("opaque-wrong.bin");
    let encrypted = dir.path().join("opaque-wrong.bin.encdata");
    let decrypted = dir.path().join("opaque-wrong.bin.decoded");
    fs::write(&input, deterministic_bytes(140)).expect("input file must be written");

    let config = test_config(64);
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
fn corrupted_opaque_payload_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("opaque-corrupt.bin");
    let encrypted = dir.path().join("opaque-corrupt.bin.encdata");
    let decrypted = dir.path().join("opaque-corrupt.bin.decoded");
    fs::write(&input, deterministic_bytes(140)).expect("input file must be written");

    let config = test_config(64);
    encrypt_file(&input, &encrypted, "password", &config, false, |_| {})
        .expect("encryption must succeed");

    let mut bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    bytes[opaque::PRELUDE_LEN] ^= 0x5A;
    fs::write(&encrypted, bytes).expect("corrupted file must be written");

    let err = decrypt_file(&encrypted, &decrypted, "password", &config, false, |_| {})
        .expect_err("decryption must fail");
    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn truncated_opaque_ciphertext_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("opaque-truncated.bin");
    let encrypted = dir.path().join("opaque-truncated.bin.encdata");
    let decrypted = dir.path().join("opaque-truncated.bin.decoded");
    fs::write(&input, deterministic_bytes(140)).expect("input file must be written");

    let config = test_config(64);
    encrypt_file(&input, &encrypted, "password", &config, false, |_| {})
        .expect("encryption must succeed");

    let mut bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    bytes.truncate(bytes.len() - 1);
    fs::write(&encrypted, bytes).expect("truncated file must be written");

    let err = decrypt_file(&encrypted, &decrypted, "password", &config, false, |_| {})
        .expect_err("decryption must fail");
    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[test]
fn tampered_opaque_prelude_fails() {
    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("opaque-metadata.bin");
    let encrypted = dir.path().join("opaque-metadata.bin.encdata");
    let decrypted = dir.path().join("opaque-metadata.bin.decoded");
    fs::write(&input, deterministic_bytes(140)).expect("input file must be written");

    let config = test_config(64);
    encrypt_file(&input, &encrypted, "password", &config, false, |_| {})
        .expect("encryption must succeed");

    let mut bytes = fs::read(&encrypted).expect("encrypted file must be readable");
    bytes[0] ^= 0x01;
    fs::write(&encrypted, bytes).expect("tampered file must be written");

    let err = decrypt_file(&encrypted, &decrypted, "password", &config, false, |_| {})
        .expect_err("decryption must fail");
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
    assert_eq!(bytes.len(), opaque::PRELUDE_LEN + TAG_LEN);
    bytes[opaque::PRELUDE_LEN] ^= 0x5A;
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
fn legacy_empty_file_without_tag_is_rejected() {
    let dir = tempdir().expect("tempdir must be created");
    let encrypted = dir.path().join("legacy-empty.encdata");
    let decrypted = dir.path().join("legacy-empty.out");

    let mut legacy = Vec::new();
    legacy.extend_from_slice(&[1u8; 16]);
    legacy.extend_from_slice(&[2u8; 8]);
    legacy.extend_from_slice(&0u64.to_le_bytes());
    fs::write(&encrypted, legacy).expect("legacy encrypted file must be written");

    let config = test_config(512);
    let err = decrypt_file(
        &encrypted,
        &decrypted,
        "any-password",
        &config,
        false,
        |_| {},
    )
    .expect_err("legacy empty file should be rejected");

    assert!(matches!(err, AppError::DecryptionFailed));
    assert!(
        !decrypted.exists(),
        "decrypted output must not be finalized"
    );
}

#[cfg(unix)]
fn staged_temp_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .expect("directory must be readable")
        .map(|entry| entry.expect("entry must be readable").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".tmp"))
        })
        .collect()
}

#[cfg(unix)]
#[test]
fn non_regular_input_is_rejected_before_password_prompt() {
    let dir = tempdir().expect("tempdir must be created");
    let fifo = dir.path().join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must run");
    assert!(status.success());

    for command in ["encrypt", "decrypt"] {
        AssertCommand::cargo_bin("fcrypt")
            .expect("binary must build")
            .arg(command)
            .arg(&fifo)
            .write_stdin("never read password\n")
            .timeout(std::time::Duration::from_secs(60))
            .assert()
            .failure()
            .stderr(contains("not a regular file"))
            .stderr(contains("assword").not());
    }
}

#[cfg(unix)]
#[test]
fn non_regular_inputs_are_rejected_without_output() {
    let dir = tempdir().expect("tempdir must be created");
    let fifo = dir.path().join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must run");
    assert!(status.success());
    let directory = dir.path().join("folder");
    fs::create_dir(&directory).expect("directory must be created");
    let password = dir.path().join("password.txt");
    fs::write(&password, b"test password\n").expect("password must be written");

    for input in [&fifo, &directory] {
        let output = dir.path().join("out.bin");
        let stdout = AssertCommand::cargo_bin("fcrypt")
            .expect("binary must build")
            .args(["--json", "encrypt"])
            .arg(input)
            .arg("--output")
            .arg(&output)
            .arg("--password-file")
            .arg(&password)
            .timeout(std::time::Duration::from_secs(60))
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();
        let report: serde_json::Value =
            serde_json::from_slice(&stdout).expect("JSON error must parse");
        assert_eq!(report["error"]["kind"], "invalid_argument");
        assert!(report["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("not a regular file")));
        assert!(!output.exists());

        let error = encrypt_file(
            input,
            &output,
            "test password",
            &test_config(64),
            false,
            |_| {},
        )
        .expect_err("library encryption must reject non-regular input");
        assert!(matches!(error, AppError::InputNotRegularFile(_)));
        let error = decrypt_file(
            input,
            &output,
            "test password",
            &test_config(64),
            false,
            |_| {},
        )
        .expect_err("library decryption must reject non-regular input");
        assert!(matches!(error, AppError::InputNotRegularFile(_)));
        assert!(!output.exists());
        assert!(staged_temp_files(dir.path()).is_empty());
    }
}

#[cfg(all(unix, feature = "pqc"))]
#[test]
fn asymmetric_commands_reject_non_regular_inputs() {
    let dir = tempdir().expect("tempdir must be created");
    let fifo = dir.path().join("pipe.bin");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must run");
    assert!(status.success());
    let keys_dir = dir.path().join("keys");
    let generated = keys::generate_named_key_pair_files(&keys_dir, "alice", None, false)
        .expect("keys must be generated");
    let output = dir.path().join("out");

    let Err(error) = asym::encrypt::encrypt_file(
        &AssymEncryptArgs {
            input: fifo.clone(),
            output: Some(output.clone()),
            recipient_public: Some(generated.recipient_public_path),
            keys_dir: None,
            sign: false,
            sign_key: None,
            force: false,
        },
        &test_config(64),
        |_| {},
    ) else {
        panic!("PQC encryption must reject non-regular input");
    };
    assert!(matches!(error, AppError::InputNotRegularFile(_)));

    let error = asym::decrypt::decrypt_file(
        &AssymDecryptArgs {
            input: fifo.clone(),
            output: Some(output.clone()),
            identity: Some(generated.recipient_secret_path),
            keys_dir: None,
            verify: None,
            require_signature: false,
            force: false,
        },
        |_| {},
    )
    .expect_err("PQC decryption must reject non-regular input");
    assert!(matches!(error, AppError::InputNotRegularFile(_)));

    let Err(error) = asym::sign::verify_file(&fifo, &generated.signing_public_path) else {
        panic!("verification must reject non-regular input");
    };
    assert!(matches!(error, AppError::InputNotRegularFile(_)));
    assert!(!output.exists());
    assert!(staged_temp_files(dir.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn interrupted_decryption_removes_staged_plaintext() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let dir = tempdir().expect("tempdir must be created");
    let input = dir.path().join("input.dat");
    let encrypted = dir.path().join("input.dat.bin");
    let decrypted = dir.path().join("decrypted.dat");
    let password = dir.path().join("password.txt");
    fs::write(&input, deterministic_bytes(64 * 1024 * 1024)).expect("input must be written");
    fs::write(&password, b"test password\n").expect("password must be written");
    encrypt_file(
        &input,
        &encrypted,
        "test password",
        &CryptoConfig::default(),
        false,
        |_| {},
    )
    .expect("fixture must encrypt");

    let mut child = Command::new(assert_cmd::cargo::cargo_bin("fcrypt"))
        .args(["--quiet", "--threads", "1", "decrypt"])
        .arg(&encrypted)
        .arg("--output")
        .arg(&decrypted)
        .arg("--password-file")
        .arg(&password)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("decryption must start");

    // The staged output exists from before key derivation until publication.
    let deadline = Instant::now() + Duration::from_secs(60);
    while staged_temp_files(dir.path()).is_empty() {
        assert!(
            child.try_wait().expect("child status must read").is_none(),
            "decryption finished before it could be interrupted"
        );
        assert!(Instant::now() < deadline, "staged output never appeared");
        std::thread::sleep(Duration::from_millis(5));
    }
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill must run");
    assert!(status.success());
    let output = child.wait_with_output().expect("child must exit");

    assert_eq!(output.status.code(), Some(130));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Interrupted"));
    assert!(staged_temp_files(dir.path()).is_empty());
    assert!(!decrypted.exists());
}
