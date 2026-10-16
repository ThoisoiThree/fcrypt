use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use serde::Serialize;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fcrypt::asym;
use fcrypt::asym::cli::{AssymCommand, AssymDecryptArgs, AssymEncryptArgs, AssymSignArgs};
use fcrypt::cli::{
    Cli, Command, DecryptArgs, EncryptArgs, IdentityCommand, KeygenCommand, PasswordCommand,
    PhraseCommand, SignArgs,
};
use fcrypt::error::{AppError, Result};
use fcrypt::keygen;
use fcrypt::output::{self, FileReport, OperationReport, OutputOptions};
use fcrypt::sym::crypto::CryptoConfig;
use fcrypt::sym::{file_ops, input, key_file, overwrite, password_file, pathing, progress, prompt};

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
    if let Err(error) = fcrypt::sym::cleanup::install_interrupt_handler() {
        output::emit_error(options, &AppError::Io(error));
        std::process::exit(1);
    }
    if let Err(error) =
        fcrypt::sym::parallel::with_threads(usize::from(cli.threads), || run(cli, options))
    {
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
  fcrypt encrypt <INPUT>... [-o <OUTPUT>]          (-o only with one input)
  fcrypt decrypt <INPUT.bin>... [-o <OUTPUT>]
  fcrypt encrypt <INPUT> --password-file <FILE>
  fcrypt encrypt <INPUT> --key-file <ANY_FILE>      (short: -K; optional password, Enter skips)
  fcrypt decrypt <INPUT.bin> --key-file <ANY_FILE>
  fcrypt encrypt <INPUT> -K <ANY_FILE> --password-file <FILE>

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
  fcrypt password generate [--length 32]
  fcrypt phrase generate [--words 7] [--separator -]

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

/// One input/output pair of an encrypt or decrypt invocation.
struct FileJob {
    input: PathBuf,
    output: PathBuf,
    allow_overwrite: bool,
}

/// A finished file, used for the human summary line and the report.
struct Completed {
    input: PathBuf,
    output: PathBuf,
    signature: Option<PathBuf>,
    bytes: u64,
    elapsed: Duration,
}

/// Resolve outputs and overwrite decisions for every input before any
/// credential is requested, so a batch never stops halfway for a prompt.
fn plan_jobs(
    inputs: Vec<PathBuf>,
    output: Option<PathBuf>,
    default_output: fn(&Path) -> Result<PathBuf>,
    force: bool,
    options: OutputOptions,
) -> Result<Vec<FileJob>> {
    if output.is_some() && inputs.len() > 1 {
        return Err(AppError::InvalidArgument(
            "--output can only be used with a single input file".to_string(),
        ));
    }
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in &inputs {
        input::reject_non_regular_file(input)?;
        outputs.push(match &output {
            Some(output) => output.clone(),
            None => default_output(input)?,
        });
    }
    if inputs.len() > 1 {
        reject_batch_collisions(&inputs, &outputs)?;
    }
    let mut jobs = Vec::with_capacity(inputs.len());
    for (input, output) in inputs.into_iter().zip(outputs) {
        let allow_overwrite = resolve_overwrite(&output, force, options)?;
        jobs.push(FileJob {
            input,
            output,
            allow_overwrite,
        });
    }
    Ok(jobs)
}

fn reject_batch_collisions(inputs: &[PathBuf], outputs: &[PathBuf]) -> Result<()> {
    for (index, input) in inputs.iter().enumerate() {
        if inputs[..index].contains(input) {
            return Err(AppError::InvalidArgument(format!(
                "input file listed more than once: {}",
                input.display()
            )));
        }
    }
    for (index, output) in outputs.iter().enumerate() {
        if outputs[..index].contains(output) {
            return Err(AppError::InvalidArgument(format!(
                "more than one input would be written to {}",
                output.display()
            )));
        }
        if inputs.contains(output) {
            return Err(AppError::InvalidArgument(format!(
                "output {} is also an input file",
                output.display()
            )));
        }
    }
    Ok(())
}

/// Run `operation` for each job, printing a summary line after every file.
/// Stops at the first failure; files completed before it are kept.
fn run_jobs<F>(
    jobs: &[FileJob],
    verb: &str,
    progress_label: &str,
    options: OutputOptions,
    mut operation: F,
) -> Result<Vec<Completed>>
where
    F: FnMut(&FileJob, &progress::OperationProgress) -> Result<Completed>,
{
    let batch = jobs.len() > 1;
    let mut completed = Vec::with_capacity(jobs.len());
    for (index, job) in jobs.iter().enumerate() {
        let total =
            fs::metadata(&job.input).map_err(|error| batch_error(batch, job, error.into()))?;
        let label = if batch {
            format!("{progress_label} {}/{}", index + 1, jobs.len())
        } else {
            progress_label.to_string()
        };
        let pb = progress::create_progress(total.len(), &label, progress_enabled(options));
        let result = operation(job, &pb);
        pb.finish();
        let done = result.map_err(|error| batch_error(batch, job, error))?;
        output::emit_line(options, &completion_line(verb, &done));
        if let Some(signature) = &done.signature {
            output::emit_line(
                options,
                &format!("Detached signature: {}", signature.display()),
            );
        }
        completed.push(done);
    }
    Ok(completed)
}

fn batch_error(batch: bool, job: &FileJob, error: AppError) -> AppError {
    if batch {
        AppError::BatchFile {
            input: job.input.clone(),
            source: Box::new(error),
        }
    } else {
        error
    }
}

fn completion_line(verb: &str, done: &Completed) -> String {
    format!(
        "{verb} {} → {} ({}, {})",
        done.input.display(),
        done.output.display(),
        output::format_size(done.bytes),
        output::format_duration(done.elapsed)
    )
}

/// Fill the input/output fields for one file, or `files` for a batch, so
/// single-file JSON reports keep their established shape.
fn report_files(report: &mut OperationReport, completed: &[Completed]) {
    match completed {
        [done] => {
            report.input = Some(done.input.display().to_string());
            report.output = Some(done.output.display().to_string());
            report.signature = done
                .signature
                .as_ref()
                .map(|path| path.display().to_string());
        }
        _ => {
            report.files = completed
                .iter()
                .map(|done| FileReport {
                    input: done.input.display().to_string(),
                    output: done.output.display().to_string(),
                    signature: done
                        .signature
                        .as_ref()
                        .map(|path| path.display().to_string()),
                })
                .collect();
        }
    }
}

fn push_unique(warnings: &mut Vec<String>, warning: String) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

fn run_encrypt(args: EncryptArgs, config: &CryptoConfig, options: OutputOptions) -> Result<()> {
    let inputs = args.input_paths()?;
    if args.new_identity.is_some() && inputs.len() > 1 {
        return Err(AppError::InvalidArgument(
            "--new-identity supports a single input file; create the identity with `fcrypt identity create` and use --recipient for several files".to_string(),
        ));
    }
    let jobs = plan_jobs(
        inputs,
        args.output.clone(),
        pathing::encryption_output_path,
        args.force,
        options,
    )?;

    if args.uses_pqc() {
        return run_pqc_encrypt(args, jobs, config, options);
    }
    let (password, mode, warnings) = encryption_secret(
        args.password_file.as_deref(),
        args.key_file.as_deref(),
        &jobs,
    )?;
    let completed = run_jobs(&jobs, "Encrypted", "Encrypting", options, |job, pb| {
        let bytes = fs::metadata(&job.input)?.len();
        let started = Instant::now();
        file_ops::encrypt_file(
            &job.input,
            &job.output,
            password.as_str(),
            config,
            job.allow_overwrite,
            |n| pb.inc(n),
        )?;
        Ok(Completed {
            input: job.input.clone(),
            output: job.output.clone(),
            signature: None,
            bytes,
            elapsed: started.elapsed(),
        })
    })?;
    let mut report = OperationReport::new("encrypt");
    report.mode = Some(mode);
    report_files(&mut report, &completed);
    report.warnings = warnings;
    output::emit_success(options, &report, &[])
}

fn run_pqc_encrypt(
    args: EncryptArgs,
    jobs: Vec<FileJob>,
    config: &CryptoConfig,
    options: OutputOptions,
) -> Result<()> {
    if args.sign && args.sign_key.is_none() && args.new_identity.is_none() {
        return Err(AppError::InvalidArgument(
            "--sign requires --sign-key or --new-identity in the unified command".to_string(),
        ));
    }
    if args.recipient.is_none() && args.new_identity.is_none() {
        return Err(AppError::InvalidArgument(
            "asymmetric encryption requires --recipient or --new-identity".to_string(),
        ));
    }

    // Resolve every overwrite question before generating keys or writing.
    let signing = args.sign || args.sign_key.is_some();
    let mut prepared = Vec::with_capacity(jobs.len());
    for job in &jobs {
        let keys_dir = match &args.keys_dir {
            Some(dir) => dir.clone(),
            None => pathing::asym_default_keys_dir_for_plain_input(&job.input)?,
        };
        let signature_overwrite = if signing {
            let signature = asym::envelope::detached_signature_path(&job.output)?;
            resolve_overwrite(&signature, args.force, options)?
        } else {
            false
        };
        prepared.push((keys_dir, signature_overwrite));
    }
    let key_force = match &args.new_identity {
        Some(name) => resolve_named_key_overwrite(&prepared[0].0, name, args.force, options)?,
        None => false,
    };

    let mut generated_keys = Vec::new();
    let mut keys_dir_used = None;
    let mut next = prepared.into_iter();
    let completed = run_jobs(&jobs, "Encrypted", "Encrypting", options, |job, pb| {
        let (keys_dir, signature_overwrite) = next.next().expect("one entry per job");
        let asym_args = AssymEncryptArgs {
            input: job.input.clone(),
            output: Some(job.output.clone()),
            recipient_public: args.recipient.clone(),
            keys_dir: Some(keys_dir),
            sign: args.sign,
            sign_key: args.sign_key.clone(),
            force: args.force || job.allow_overwrite || signature_overwrite,
        };
        let bytes = fs::metadata(&job.input)?.len();
        let started = Instant::now();
        let outcome = match &args.new_identity {
            Some(name) => asym::encrypt::encrypt_file_with_new_identity(
                &asym_args,
                name,
                key_force,
                config,
                |n| pb.inc(n),
            )?,
            None => asym::encrypt::encrypt_file(&asym_args, config, |n| pb.inc(n))?,
        };
        let elapsed = started.elapsed();
        generated_keys.extend(
            [
                outcome.generated_recipient_public,
                outcome.generated_recipient_secret,
                outcome.generated_signer_public,
                outcome.generated_signer_secret,
            ]
            .into_iter()
            .flatten(),
        );
        keys_dir_used = Some(outcome.keys_dir);
        Ok(Completed {
            input: job.input.clone(),
            output: outcome.output,
            signature: outcome.detached_signature,
            bytes,
            elapsed,
        })
    })?;

    let mut report = OperationReport::new("encrypt");
    report.mode = Some("pqc");
    report_files(&mut report, &completed);
    report.keys_dir = keys_dir_used.map(|dir| dir.display().to_string());
    report.generated_keys = generated_keys
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let mut lines = Vec::new();
    if !generated_keys.is_empty() {
        if let Some(keys_dir) = &report.keys_dir {
            lines.push(format!("Keys directory: {keys_dir}"));
        }
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
    output::emit_success(options, &report, &lines)
}

fn run_decrypt(args: DecryptArgs, config: &CryptoConfig, options: OutputOptions) -> Result<()> {
    let jobs = plan_jobs(
        args.input_paths()?,
        args.output.clone(),
        pathing::decryption_output_path,
        args.force,
        options,
    )?;
    if !args.uses_pqc() {
        let (password, mode, warnings) = decryption_secret(
            args.password_file.as_deref(),
            args.key_file.as_deref(),
            &jobs,
        )?;
        let completed = run_jobs(&jobs, "Decrypted", "Decrypting", options, |job, pb| {
            let started = Instant::now();
            file_ops::decrypt_file(
                &job.input,
                &job.output,
                password.as_str(),
                config,
                job.allow_overwrite,
                |n| pb.inc(n),
            )
            .map_err(|error| match (error, mode) {
                (AppError::DecryptionFailed, "key_file") => AppError::KeyFileDecryptionFailed,
                (AppError::DecryptionFailed, _) => AppError::PasswordDecryptionFailed,
                (error, _) => error,
            })?;
            Ok(Completed {
                input: job.input.clone(),
                output: job.output.clone(),
                signature: None,
                bytes: fs::metadata(&job.output)?.len(),
                elapsed: started.elapsed(),
            })
        })?;
        let mut report = OperationReport::new("decrypt");
        report.mode = Some(mode);
        report_files(&mut report, &completed);
        report.warnings = warnings;
        return output::emit_success(options, &report, &[]);
    }

    let mut warnings = Vec::new();
    let completed = run_jobs(&jobs, "Decrypted", "Decrypting", options, |job, pb| {
        let asym_args = AssymDecryptArgs {
            input: job.input.clone(),
            output: Some(job.output.clone()),
            identity: args.identity.clone(),
            keys_dir: args.keys_dir.clone(),
            verify: args.verify.clone(),
            require_signature: args.require_signature,
            force: args.force || job.allow_overwrite,
        };
        let started = Instant::now();
        let outcome = asym::decrypt::decrypt_file_with_diagnostics(&asym_args, |n| pb.inc(n))?;
        let elapsed = started.elapsed();
        if outcome.recipient_key_expired {
            push_unique(
                &mut warnings,
                "recipient key is expired; using it for archival decryption".to_string(),
            );
        }
        if outcome.signer_key_expired {
            push_unique(
                &mut warnings,
                "signing key is expired; historical signature verification is allowed".to_string(),
            );
        }
        for path in &outcome.skipped_identity_files {
            push_unique(
                &mut warnings,
                format!("skipped invalid key file {}", path.display()),
            );
        }
        Ok(Completed {
            input: job.input.clone(),
            bytes: fs::metadata(&outcome.output)?.len(),
            output: outcome.output,
            signature: None,
            elapsed,
        })
    })?;
    let mut report = OperationReport::new("decrypt");
    report.mode = Some("pqc");
    report_files(&mut report, &completed);
    report.warnings = warnings;
    output::emit_success(options, &report, &[])
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

type SymmetricSecret = (zeroize::Zeroizing<String>, &'static str, Vec<String>);

#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// Shorter passwords trigger a warning when encrypting with a password only.
const RECOMMENDED_MIN_PASSWORD_CHARS: usize = 12;

fn encryption_secret(
    password_path: Option<&Path>,
    key_path: Option<&Path>,
    jobs: &[FileJob],
) -> Result<SymmetricSecret> {
    symmetric_secret(password_path, key_path, jobs, Direction::Encrypt)
}

fn decryption_secret(
    password_path: Option<&Path>,
    key_path: Option<&Path>,
    jobs: &[FileJob],
) -> Result<SymmetricSecret> {
    symmetric_secret(password_path, key_path, jobs, Direction::Decrypt)
}

fn symmetric_secret(
    password_path: Option<&Path>,
    key_path: Option<&Path>,
    jobs: &[FileJob],
    direction: Direction,
) -> Result<SymmetricSecret> {
    let mut warnings = Vec::new();
    let Some(key_path) = key_path else {
        let password = match password_path {
            Some(path) => {
                let password = password_file::read_password_file(path)?;
                warnings.extend(password.warning);
                password.password
            }
            None => match direction {
                Direction::Encrypt => prompt::prompt_password_for_encryption()?,
                Direction::Decrypt => prompt::prompt_password_for_decryption()?,
            },
        };
        if matches!(direction, Direction::Encrypt)
            && password.chars().count() < RECOMMENDED_MIN_PASSWORD_CHARS
        {
            warnings.push(format!(
                "password is shorter than {RECOMMENDED_MIN_PASSWORD_CHARS} characters; consider a longer one, e.g. from `fcrypt phrase generate`"
            ));
        }
        return Ok((password, "password", warnings));
    };

    // Validate and hash the key file before asking for the optional password.
    for job in jobs {
        key_file::reject_key_file_reuse(key_path, &job.input, &job.output)?;
    }
    let mut key = key_file::read_key_file(key_path)?;
    warnings.extend(key.warning.take());
    let password = match password_path {
        Some(path) => {
            let password = password_file::read_password_file(path)?;
            warnings.extend(password.warning);
            password.password
        }
        None => match direction {
            Direction::Encrypt => prompt::prompt_optional_password_for_encryption()?,
            Direction::Decrypt => prompt::prompt_optional_password_for_decryption()?,
        },
    };
    Ok((key.slot_password(&password), "key_file", warnings))
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
    let metadata = asym::keys::read_key_metadata(path)?;
    let kind = metadata.kind;
    if !matches!(
        kind.as_str(),
        "recipient-public" | "recipient-secret" | "signer-public" | "signer-secret"
    ) {
        return Err(AppError::InvalidAsymmetricKeyFile(format!(
            "{}: unknown key type",
            path.display()
        )));
    }
    let expires_at_unix = metadata.expires_at_unix;
    let expired = expires_at_unix.is_some_and(|expires| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|now| now.as_secs() >= expires)
            .unwrap_or(false)
    });
    Ok(KeyInfo {
        path: path.display().to_string(),
        kind,
        label8: metadata.label8,
        key_id: metadata.key_id,
        created_at_unix: metadata.created_at_unix,
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
