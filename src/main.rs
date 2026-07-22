use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use serde::Serialize;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fcrypt::asym;
use fcrypt::asym::cli::{AssymCommand, AssymDecryptArgs, AssymEncryptArgs, AssymSignArgs};
use fcrypt::cli::{
    Cli, Command, DecryptArgs, EncryptArgs, IdentityCommand, KeygenCommand, PasswordCommand,
    PhraseCommand, SignArgs,
};
use fcrypt::error::{AppError, Result};
use fcrypt::keygen;
use fcrypt::output::{self, OperationReport, OutputOptions};
use fcrypt::sym::crypto::CryptoConfig;
use fcrypt::sym::{file_ops, overwrite, password_file, pathing, progress, prompt};

fn main() {
    let args = normalized_args();
    let wants_json = args.iter().any(|arg| arg == "--json");
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            if wants_json {
                println!(
                    "{{\"status\":\"error\",\"error\":{{\"kind\":\"argument\",\"message\":{}}}}}",
                    serde_json::to_string(&error.to_string())
                        .unwrap_or_else(|_| "\"invalid arguments\"".to_string())
                );
            } else {
                let _ = error.print();
            }
            std::process::exit(error.exit_code());
        }
    };
    let options = OutputOptions {
        quiet: cli.quiet,
        json: cli.json,
        no_progress: cli.no_progress,
    };
    if let Err(error) = run(cli, options) {
        output::emit_error(options, &error);
        std::process::exit(1);
    }
}

fn run(cli: Cli, options: OutputOptions) -> Result<()> {
    let config = CryptoConfig::default();
    match cli.command {
        Command::Encrypt(args) => run_encrypt(args, &config, options),
        Command::Decrypt(args) => run_decrypt(args, &config, options),
        Command::Sign(args) => run_sign(args, options),
        Command::Verify(args) => run_verify(&args.input, &args.key, options),
        Command::Identity(args) => run_identity(args.command, options),
        Command::Password(args) => match args.command {
            PasswordCommand::Generate {
                length,
                base64,
                compatible,
            } => run_password_generate(length, base64, compatible, options),
        },
        Command::Phrase(args) => match args.command {
            PhraseCommand::Generate { words, separator } => {
                run_phrase_generate(words, &separator, options)
            }
        },
        Command::Asym { command } => run_legacy_asym(command, &config, options),
        Command::Keygen(args) => run_legacy_keygen(args, options),
        Command::HelpAll => {
            print_help_all();
            Ok(())
        }
    }
}

fn print_help_all() {
    println!(
        "fcrypt command reference

Password encryption:
  fcrypt encrypt <INPUT> [-o <OUTPUT>]
  fcrypt decrypt <INPUT.bin> [-o <OUTPUT>]
  fcrypt encrypt <INPUT> --password-file <FILE>

Recipient-key encryption:
  fcrypt identity create alice
  fcrypt encrypt <INPUT> --recipient ./alice_recipient_default.pub
  fcrypt decrypt <INPUT.bin> --identity ./alice_recipient_default.sec

Signatures:
  fcrypt sign <INPUT.bin> --key ./alice_signer_mldsa87.sec
  fcrypt verify <INPUT.bin> --key ./alice_signer_mldsa87.pub
  fcrypt decrypt <INPUT.bin> --identity <KEY> --verify <SIGNER_PUB>

Identity management:
  fcrypt identity create <NAME> [--keys-dir <DIR>] [--lifetime-days <DAYS>]
  fcrypt identity list [--keys-dir <DIR>]
  fcrypt identity inspect <KEY>

Secret generation:
  fcrypt password generate --length 32
  fcrypt phrase generate --words 7 --separator -

Automation:
  --json          emit one JSON result to stdout
  --quiet         suppress success output and progress
  --no-progress   suppress progress indicators

Compatibility commands remain available:
  fcrypt asym ...     legacy asymmetric command group
  fcrypt assym ...    compatibility alias
  fcrypt keygen ...   legacy generation commands"
    );
}

fn run_encrypt(args: EncryptArgs, config: &CryptoConfig, options: OutputOptions) -> Result<()> {
    let input = args.input_path()?;
    let output = args
        .output
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::encryption_output_path(&input))?;
    let allow_overwrite = resolve_overwrite(&output, args.force, options)?;

    if !args.uses_pqc() {
        let (password, warnings) = encryption_password(args.password_file.as_deref())?;
        let total = fs::metadata(&input)?.len();
        let pb = progress::create_progress(total, "Encrypting", progress_enabled(options));
        let result = file_ops::encrypt_file(
            &input,
            &output,
            password.as_str(),
            config,
            allow_overwrite,
            |n| pb.inc(n),
        );
        pb.finish();
        result?;
        let mut report = OperationReport::new("encrypt");
        report.mode = Some("password");
        report.input = Some(input.display().to_string());
        report.output = Some(output.display().to_string());
        report.warnings = warnings;
        output::emit_success(
            options,
            &report,
            &[format!("Encryption complete: {}", output.display())],
        )
    } else {
        run_pqc_encrypt(args, input, output, allow_overwrite, config, options)
    }
}

fn run_pqc_encrypt(
    args: EncryptArgs,
    input: PathBuf,
    output: PathBuf,
    allow_overwrite: bool,
    config: &CryptoConfig,
    options: OutputOptions,
) -> Result<()> {
    if args.sign && args.sign_key.is_none() && args.new_identity.is_none() {
        return Err(AppError::InvalidArgument(
            "--sign requires --sign-key or --new-identity in the unified command".to_string(),
        ));
    }

    let mut generated_keys = Vec::new();
    let mut recipient = args.recipient.clone();
    let mut sign_key = args.sign_key.clone();
    let keys_dir = args
        .keys_dir
        .clone()
        .unwrap_or(pathing::asym_default_keys_dir_for_plain_input(&input)?);
    if let Some(name) = &args.new_identity {
        let key_force = resolve_named_key_overwrite(&keys_dir, name, args.force, options)?;
        let generated =
            asym::keys::generate_named_key_pair_files(&keys_dir, name, None, key_force)?;
        recipient = Some(generated.recipient_public_path.clone());
        if args.sign {
            sign_key = Some(generated.signing_secret_path.clone());
        }
        generated_keys = vec![
            generated.recipient_public_path,
            generated.recipient_secret_path,
            generated.signing_public_path,
            generated.signing_secret_path,
        ];
    }
    let recipient = recipient.ok_or_else(|| {
        AppError::InvalidArgument(
            "asymmetric encryption requires --recipient or --new-identity".to_string(),
        )
    })?;
    let signing = args.sign || sign_key.is_some();
    let detached_signature = signing
        .then(|| asym::envelope::detached_signature_path(&output))
        .transpose()?;
    let signature_overwrite = if let Some(signature) = &detached_signature {
        resolve_overwrite(signature, args.force, options)?
    } else {
        false
    };

    let asym_args = AssymEncryptArgs {
        input: input.clone(),
        output: Some(output.clone()),
        recipient_public: Some(recipient),
        keys_dir: Some(keys_dir.clone()),
        sign: signing,
        sign_key,
        force: args.force || allow_overwrite || signature_overwrite,
    };
    let total = fs::metadata(&input)?.len();
    let pb = progress::create_progress(total, "Encrypting", progress_enabled(options));
    let result = asym::encrypt::encrypt_file(&asym_args, config, |n| pb.inc(n));
    pb.finish();
    let outcome = result?;
    let mut report = OperationReport::new("encrypt");
    report.mode = Some("pqc");
    report.input = Some(input.display().to_string());
    report.output = Some(outcome.output.display().to_string());
    report.signature = outcome
        .detached_signature
        .as_ref()
        .map(|path| path.display().to_string());
    report.keys_dir = Some(outcome.keys_dir.display().to_string());
    report.generated_keys = generated_keys
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let mut lines = vec![format!("Encryption complete: {}", outcome.output.display())];
    if !generated_keys.is_empty() {
        lines.push(format!("Keys directory: {}", keys_dir.display()));
        if let Some(secret) = generated_keys.iter().find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with("_recipient_default.sec"))
        }) {
            lines.push(format!("IMPORTANT: Back up {}.", secret.display()));
            lines.push(
                "Without the recipient secret key, encrypted data cannot be recovered.".to_string(),
            );
        }
    }
    if let Some(signature) = &outcome.detached_signature {
        lines.push(format!("Detached signature: {}", signature.display()));
    }
    output::emit_success(options, &report, &lines)
}

fn run_decrypt(args: DecryptArgs, config: &CryptoConfig, options: OutputOptions) -> Result<()> {
    let input = args.input_path()?;
    let output = args
        .output
        .clone()
        .map(Ok)
        .unwrap_or_else(|| pathing::decryption_output_path(&input))?;
    let allow_overwrite = resolve_overwrite(&output, args.force, options)?;
    if !args.uses_pqc() {
        let (password, warnings) = decryption_password(args.password_file.as_deref())?;
        let total = fs::metadata(&input)?.len();
        let pb = progress::create_progress(total, "Decrypting", progress_enabled(options));
        let result = file_ops::decrypt_file(
            &input,
            &output,
            password.as_str(),
            config,
            allow_overwrite,
            |n| pb.inc(n),
        );
        pb.finish();
        result?;
        let mut report = OperationReport::new("decrypt");
        report.mode = Some("password");
        report.input = Some(input.display().to_string());
        report.output = Some(output.display().to_string());
        report.warnings = warnings;
        output::emit_success(
            options,
            &report,
            &[format!("Decryption complete: {}", output.display())],
        )
    } else {
        let mut warnings = Vec::new();
        let asym_args = AssymDecryptArgs {
            input: input.clone(),
            output: Some(output.clone()),
            identity: args.identity,
            keys_dir: args.keys_dir,
            verify: args.verify,
            require_signature: args.require_signature,
            force: args.force || allow_overwrite,
        };
        let total = fs::metadata(&input)?.len();
        let pb = progress::create_progress(total, "Decrypting", progress_enabled(options));
        let result = asym::decrypt::decrypt_file_with_diagnostics(&asym_args, |n| pb.inc(n));
        pb.finish();
        let outcome = result?;
        if outcome.recipient_key_expired {
            warnings.push("recipient key is expired; using it for archival decryption".to_string());
        }
        if outcome.signer_key_expired {
            warnings.push(
                "signing key is expired; historical signature verification is allowed".to_string(),
            );
        }
        warnings.extend(
            outcome
                .skipped_identity_files
                .iter()
                .map(|path| format!("skipped invalid key file {}", path.display())),
        );
        let output = outcome.output;
        let mut report = OperationReport::new("decrypt");
        report.mode = Some("pqc");
        report.input = Some(input.display().to_string());
        report.output = Some(output.display().to_string());
        report.warnings = warnings;
        output::emit_success(
            options,
            &report,
            &[format!("Decryption complete: {}", output.display())],
        )
    }
}

fn run_sign(args: SignArgs, options: OutputOptions) -> Result<()> {
    let output = args
        .output
        .clone()
        .map(Ok)
        .unwrap_or_else(|| asym::envelope::detached_signature_path(&args.input))?;
    let allow_overwrite = resolve_overwrite(&output, args.force, options)?;
    let outcome = asym::sign::sign_file(&AssymSignArgs {
        input: args.input.clone(),
        output: Some(output.clone()),
        sign_key: Some(args.key),
        keys_dir: None,
        embed: false,
        force: args.force || allow_overwrite,
    })?;
    let mut report = OperationReport::new("sign");
    report.input = Some(args.input.display().to_string());
    report.output = Some(outcome.output.display().to_string());
    output::emit_success(
        options,
        &report,
        &[format!(
            "Detached signature complete: {}",
            outcome.output.display()
        )],
    )
}

fn run_verify(input: &Path, key: &Path, options: OutputOptions) -> Result<()> {
    let verified = asym::sign::verify_file(input, key)?;
    let mut report = OperationReport::new("verify");
    report.input = Some(input.display().to_string());
    report.verified = Some(true);
    report.signer_key_id = Some(verified.signer_key_id);
    if verified.signer_key_expired {
        report.warnings.push(
            "signing key is expired; historical signature verification is allowed".to_string(),
        );
    }
    output::emit_success(
        options,
        &report,
        &["Signature verification succeeded.".to_string()],
    )
}

fn run_identity(command: IdentityCommand, options: OutputOptions) -> Result<()> {
    match command {
        IdentityCommand::Create {
            name,
            keys_dir,
            lifetime_days,
            force,
        } => {
            let key_force = resolve_named_key_overwrite(&keys_dir, &name, force, options)?;
            let generated = asym::keys::generate_named_key_pair_files(
                &keys_dir,
                &name,
                lifetime_days,
                key_force,
            )?;
            let mut report = OperationReport::new("identity_create");
            report.keys_dir = Some(keys_dir.display().to_string());
            report.generated_keys = vec![
                generated.recipient_public_path.display().to_string(),
                generated.recipient_secret_path.display().to_string(),
                generated.signing_public_path.display().to_string(),
                generated.signing_secret_path.display().to_string(),
            ];
            let lines = vec![
                format!("Identity created in {}", keys_dir.display()),
                format!(
                    "Recipient public key: {}",
                    generated.recipient_public_path.display()
                ),
                format!(
                    "Recipient secret key: {}",
                    generated.recipient_secret_path.display()
                ),
                format!(
                    "Signing public key: {}",
                    generated.signing_public_path.display()
                ),
                format!(
                    "Signing secret key: {}",
                    generated.signing_secret_path.display()
                ),
                format!(
                    "IMPORTANT: Back up {}.",
                    generated.recipient_secret_path.display()
                ),
                "Without the recipient secret key, encrypted data cannot be recovered.".to_string(),
            ];
            output::emit_success(options, &report, &lines)
        }
        IdentityCommand::List { keys_dir } => {
            let (infos, warnings) = list_identities(&keys_dir)?;
            let mut report = OperationReport::new("identity_list");
            report.keys_dir = Some(keys_dir.display().to_string());
            report.warnings = warnings;
            report.data = Some(
                serde_json::to_value(&infos)
                    .map_err(|error| AppError::Serialization(error.to_string()))?,
            );
            let lines = infos.iter().map(KeyInfo::human_line).collect::<Vec<_>>();
            output::emit_success(options, &report, &lines)
        }
        IdentityCommand::Inspect { key } => {
            let info = inspect_key(&key)?;
            let mut report = OperationReport::new("identity_inspect");
            report.input = Some(key.display().to_string());
            report.data = Some(
                serde_json::to_value(&info)
                    .map_err(|error| AppError::Serialization(error.to_string()))?,
            );
            output::emit_success(options, &report, &[info.human_line()])
        }
    }
}

fn run_password_generate(
    length: usize,
    base64: bool,
    compatible: bool,
    options: OutputOptions,
) -> Result<()> {
    reject_machine_secret_output(options)?;
    let password = if compatible {
        keygen::generate_compatible_password(length)?
    } else {
        keygen::generate_password(length)?
    };
    let mut stdout = io::stdout().lock();
    if base64 {
        let encoded = zeroize::Zeroizing::new(STANDARD.encode(password.as_slice()));
        stdout.write_all(encoded.as_bytes())?;
    } else {
        stdout.write_all(password.as_slice())?;
    }
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn run_phrase_generate(words: usize, separator: &str, options: OutputOptions) -> Result<()> {
    reject_machine_secret_output(options)?;
    let phrase = keygen::generate_phrase(words, separator)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(phrase.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn reject_machine_secret_output(options: OutputOptions) -> Result<()> {
    if options.json || options.quiet {
        return Err(AppError::InvalidArgument(
            "--json and --quiet cannot be used when generating a secret".to_string(),
        ));
    }
    Ok(())
}

fn run_legacy_asym(
    command: AssymCommand,
    config: &CryptoConfig,
    options: OutputOptions,
) -> Result<()> {
    match command {
        AssymCommand::Encrypt(mut args) => {
            let output = args
                .output
                .clone()
                .map(Ok)
                .unwrap_or_else(|| pathing::asym_encryption_output_path(&args.input))?;
            let output_overwrite = resolve_overwrite(&output, args.force, options)?;
            let signature_overwrite = if args.sign || args.sign_key.is_some() {
                let signature = asym::envelope::detached_signature_path(&output)?;
                resolve_overwrite(&signature, args.force, options)?
            } else {
                false
            };
            args.output = Some(output);
            args.force |= output_overwrite || signature_overwrite;
            let total = fs::metadata(&args.input)?.len();
            let pb = progress::create_progress(total, "Encrypting", progress_enabled(options));
            let result = asym::encrypt::encrypt_file(&args, config, |n| pb.inc(n));
            pb.finish();
            let outcome = result?;
            let mut report = OperationReport::new("encrypt");
            report.mode = Some("pqc");
            report.input = Some(args.input.display().to_string());
            report.output = Some(outcome.output.display().to_string());
            report.signature = outcome
                .detached_signature
                .as_ref()
                .map(|path| path.display().to_string());
            report.keys_dir = Some(outcome.keys_dir.display().to_string());
            report.generated_keys = [
                outcome.generated_recipient_public,
                outcome.generated_recipient_secret,
                outcome.generated_signer_public,
                outcome.generated_signer_secret,
            ]
            .into_iter()
            .flatten()
            .map(|path| path.display().to_string())
            .collect();
            output::emit_success(
                options,
                &report,
                &[format!("Encryption complete: {}", outcome.output.display())],
            )
        }
        AssymCommand::Decrypt(mut args) => {
            let output = args
                .output
                .clone()
                .map(Ok)
                .unwrap_or_else(|| pathing::asym_decryption_output_path(&args.input))?;
            let output_overwrite = resolve_overwrite(&output, args.force, options)?;
            args.output = Some(output);
            args.force |= output_overwrite;
            let total = fs::metadata(&args.input)?.len();
            let pb = progress::create_progress(total, "Decrypting", progress_enabled(options));
            let result = asym::decrypt::decrypt_file(&args, |n| pb.inc(n));
            pb.finish();
            let output_path = result?;
            let mut report = OperationReport::new("decrypt");
            report.mode = Some("pqc");
            report.input = Some(args.input.display().to_string());
            report.output = Some(output_path.display().to_string());
            output::emit_success(
                options,
                &report,
                &[format!("Decryption complete: {}", output_path.display())],
            )
        }
        AssymCommand::Sign(mut args) => {
            let output = args
                .output
                .clone()
                .map(Ok)
                .unwrap_or_else(|| asym::envelope::detached_signature_path(&args.input))?;
            let output_overwrite = resolve_overwrite(&output, args.force, options)?;
            args.output = Some(output);
            args.force |= output_overwrite;
            let outcome = asym::sign::sign_file(&args)?;
            let mut report = OperationReport::new("sign");
            report.input = Some(args.input.display().to_string());
            report.output = Some(outcome.output.display().to_string());
            output::emit_success(
                options,
                &report,
                &[format!(
                    "Detached signature complete: {}",
                    outcome.output.display()
                )],
            )
        }
    }
}

fn run_legacy_keygen(args: fcrypt::cli::KeygenArgs, options: OutputOptions) -> Result<()> {
    match args.command {
        Some(KeygenCommand::Phrase {
            word_count,
            separator,
        }) => run_phrase_generate(word_count, &separator, options),
        Some(KeygenCommand::Pair {
            name,
            lifetime_days,
        }) => run_identity(
            IdentityCommand::Create {
                name,
                keys_dir: PathBuf::from("."),
                lifetime_days,
                force: false,
            },
            options,
        ),
        None => {
            let length = args.length.ok_or_else(|| {
                AppError::InvalidArgument("password length is required".to_string())
            })?;
            run_password_generate(length, false, false, options)
        }
    }
}

fn encryption_password(path: Option<&Path>) -> Result<(zeroize::Zeroizing<String>, Vec<String>)> {
    match path {
        Some(path) => {
            let password = password_file::read_password_file(path)?;
            Ok((password.password, password.warning.into_iter().collect()))
        }
        None => Ok((prompt::prompt_password_for_encryption()?, Vec::new())),
    }
}

fn decryption_password(path: Option<&Path>) -> Result<(zeroize::Zeroizing<String>, Vec<String>)> {
    match path {
        Some(path) => {
            let password = password_file::read_password_file(path)?;
            Ok((password.password, password.warning.into_iter().collect()))
        }
        None => Ok((prompt::prompt_password_for_decryption()?, Vec::new())),
    }
}

fn progress_enabled(options: OutputOptions) -> bool {
    !options.quiet && !options.json && !options.no_progress
}

fn resolve_named_key_overwrite(
    keys_dir: &Path,
    name: &str,
    force: bool,
    options: OutputOptions,
) -> Result<bool> {
    let key_paths = [
        keys_dir.join(format!("{name}_recipient_default.pub")),
        keys_dir.join(format!("{name}_recipient_default.sec")),
        keys_dir.join(format!("{name}_signer_mldsa87.pub")),
        keys_dir.join(format!("{name}_signer_mldsa87.sec")),
    ];
    let mut allow_overwrite = false;
    for path in &key_paths {
        allow_overwrite |= resolve_overwrite(path, force, options)?;
    }
    Ok(force || allow_overwrite)
}

fn resolve_overwrite(path: &Path, force: bool, options: OutputOptions) -> Result<bool> {
    if options.json && path.exists() && !force {
        return Err(AppError::OutputExistsNonInteractive(path.to_path_buf()));
    }
    overwrite::resolve_overwrite(path, force, prompt::confirm_overwrite)
}

#[derive(Serialize)]
struct KeyInfo {
    path: String,
    kind: String,
    label8: Option<String>,
    key_id: Option<String>,
    created_at_unix: Option<u64>,
    expires_at_unix: Option<u64>,
    expired: bool,
}

impl KeyInfo {
    fn human_line(&self) -> String {
        let expiration = self
            .expires_at_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "never".to_string());
        format!(
            "{}  type={}  label={}  key_id={}  expires={}{}",
            self.path,
            self.kind,
            self.label8.as_deref().unwrap_or("-"),
            self.key_id.as_deref().unwrap_or("-"),
            expiration,
            if self.expired { " (expired)" } else { "" }
        )
    }
}

fn list_identities(keys_dir: &Path) -> Result<(Vec<KeyInfo>, Vec<String>)> {
    let mut infos = Vec::new();
    let mut warnings = Vec::new();
    if !keys_dir.exists() {
        return Ok((infos, warnings));
    }
    let mut paths = fs::read_dir(keys_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("pub") | Some("sec")
            )
        })
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        match inspect_key(&path) {
            Ok(info) => infos.push(info),
            Err(_) => warnings.push(format!("skipped invalid key file {}", path.display())),
        }
    }
    Ok((infos, warnings))
}

fn inspect_key(path: &Path) -> Result<KeyInfo> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?).map_err(|error| {
        AppError::InvalidAsymmetricKeyFile(format!("{}: {error}", path.display()))
    })?;
    let kind = value
        .get("type")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            AppError::InvalidAsymmetricKeyFile(format!("{}: missing key type", path.display()))
        })?;
    if !matches!(
        kind,
        "recipient-public" | "recipient-secret" | "signer-public" | "signer-secret"
    ) {
        return Err(AppError::InvalidAsymmetricKeyFile(format!(
            "{}: unknown key type",
            path.display()
        )));
    }
    let expires_at_unix = value
        .get("expires_at_unix")
        .and_then(|value| value.as_u64());
    let expired = expires_at_unix.is_some_and(|expires| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|now| now.as_secs() >= expires)
            .unwrap_or(false)
    });
    Ok(KeyInfo {
        path: path.display().to_string(),
        kind: kind.to_string(),
        label8: value
            .get("label8")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        key_id: value
            .get("key_id")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        created_at_unix: value
            .get("created_at_unix")
            .and_then(|value| value.as_u64()),
        expires_at_unix,
        expired,
    })
}

fn normalized_args() -> Vec<OsString> {
    normalize_args(env::args_os().collect())
}

fn normalize_args(args: Vec<OsString>) -> Vec<OsString> {
    let mut before_separator = true;
    for arg in args.iter().skip(1) {
        if arg == "--" {
            before_separator = false;
        } else if before_separator && (arg == "-ha" || arg == "--help-all") {
            return vec![args[0].clone(), OsString::from("help-all")];
        }
    }
    args.into_iter()
        .map(|arg| {
            if arg == "-b64" {
                OsString::from("--base64")
            } else if arg == "-sep" {
                OsString::from("--sep")
            } else if let Some(value) = arg.to_str().and_then(|arg| arg.strip_prefix("-sep=")) {
                OsString::from(format!("--sep={value}"))
            } else {
                arg
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_all_alias_does_not_consume_a_path_after_double_dash() {
        let args = normalize_args(vec![
            OsString::from("fcrypt"),
            OsString::from("encrypt"),
            OsString::from("--"),
            OsString::from("-ha"),
        ]);
        assert_eq!(args[3], OsString::from("-ha"));
    }

    #[test]
    fn help_all_alias_maps_to_the_explicit_command() {
        let args = normalize_args(vec![
            OsString::from("fcrypt"),
            OsString::from("asym"),
            OsString::from("-ha"),
        ]);
        assert_eq!(
            args,
            vec![OsString::from("fcrypt"), OsString::from("help-all")]
        );
    }

    #[test]
    fn base64_legacy_option_is_normalized() {
        let args = normalize_args(vec![
            OsString::from("fcrypt"),
            OsString::from("password"),
            OsString::from("generate"),
            OsString::from("-b64"),
        ]);
        assert_eq!(args[3], OsString::from("--base64"));
    }
}
