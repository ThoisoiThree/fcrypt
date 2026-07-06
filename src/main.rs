use clap::Parser;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};

use filecrypt::asym;
use filecrypt::asym::cli::AssymCommand;
use filecrypt::cli::{Cli, Command, KeygenCommand};
use filecrypt::error::Result;
use filecrypt::keygen;
use filecrypt::sym::crypto::{CryptoConfig, CryptoMode};
use filecrypt::sym::{file_ops, overwrite, pathing, progress, prompt};

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    if env::args_os().any(|arg| arg == "-ha" || arg == "--help-all") {
        asym::help_all::print_help_all();
        return Ok(());
    }

    let cli = Cli::parse_from(normalized_args());
    let config = CryptoConfig::default();

    match cli.command {
        Command::Encrypt(args) => {
            let input = args.input_path()?;
            let output = pathing::encryption_output_path(&input)?;
            let allow_overwrite =
                overwrite::resolve_overwrite(&output, args.force, prompt::confirm_overwrite)?;
            let password = prompt::prompt_password_for_encryption()?;
            let total = fs::metadata(&input)?.len();
            let pb = progress::create_progress_bar(total, "Encrypting");
            let mode = if args.paranoic {
                CryptoMode::Paranoid
            } else {
                CryptoMode::Standard
            };

            let result = file_ops::encrypt_file_with_mode(
                &input,
                &output,
                password.as_str(),
                &config,
                mode,
                allow_overwrite,
                |n| pb.inc(n),
            );
            pb.finish_and_clear();
            result?;

            println!("Encryption complete: {}", output.display());
            Ok(())
        }
        Command::Decrypt(args) => {
            let input = args.input_path()?;
            if asym::envelope::is_fe_file(&input)? {
                return Err(filecrypt::error::AppError::SymmetricCommandUsedForFe(
                    input.display().to_string(),
                ));
            }
            let output = pathing::decryption_output_path(&input)?;
            let allow_overwrite =
                overwrite::resolve_overwrite(&output, args.force, prompt::confirm_overwrite)?;
            let password = prompt::prompt_password_for_decryption()?;
            let total = fs::metadata(&input)?.len();
            let pb = progress::create_progress_bar(total, "Decrypting");

            let result = file_ops::decrypt_file(
                &input,
                &output,
                password.as_str(),
                &config,
                allow_overwrite,
                |n| pb.inc(n),
            );
            pb.finish_and_clear();
            result?;

            println!("Decryption complete: {}", output.display());
            Ok(())
        }
        Command::Assym { command } => match command {
            AssymCommand::Encrypt(args) => {
                let total = fs::metadata(&args.input)?.len();
                let pb = progress::create_progress_bar(total, "Encrypting");
                let result = asym::encrypt::encrypt_file(&args, &config, |n| pb.inc(n));
                pb.finish_and_clear();
                let outcome = result?;
                println!("Encryption complete: {}", outcome.output.display());
                println!("Keys directory: {}", outcome.keys_dir.display());
                if let Some(path) = outcome.generated_recipient_public {
                    println!("Recipient public key: {}", path.display());
                }
                if let Some(path) = outcome.generated_recipient_secret {
                    println!("Recipient secret key: {}", path.display());
                }
                if let Some(path) = outcome.generated_signer_public {
                    println!("Signing public key: {}", path.display());
                }
                if let Some(path) = outcome.generated_signer_secret {
                    println!("Signing secret key: {}", path.display());
                }
                Ok(())
            }
            AssymCommand::Decrypt(args) => {
                let total = fs::metadata(&args.input)?.len();
                let pb = progress::create_progress_bar(total, "Decrypting");
                let result = asym::decrypt::decrypt_file(&args, |n| pb.inc(n));
                pb.finish_and_clear();
                let output = result?;
                println!("Decryption complete: {}", output.display());
                Ok(())
            }
            AssymCommand::Sign(args) => {
                let outcome = asym::sign::sign_file(&args)?;
                if outcome.embedded {
                    println!("Embedded signature complete: {}", outcome.output.display());
                } else {
                    println!("Detached signature complete: {}", outcome.output.display());
                }
                println!("Keys directory: {}", outcome.keys_dir.display());
                if let Some(path) = outcome.generated_signer_public {
                    println!("Signing public key: {}", path.display());
                }
                if let Some(path) = outcome.generated_signer_secret {
                    println!("Signing secret key: {}", path.display());
                }
                Ok(())
            }
        },
        Command::Keygen(args) => {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();

            match args.command {
                Some(KeygenCommand::Phrase {
                    word_count,
                    separator,
                }) => {
                    let phrase = keygen::generate_phrase(word_count, &separator)?;
                    stdout.write_all(phrase.as_bytes())?;
                    stdout.write_all(b"\n")?;
                    stdout.flush()?;
                    Ok(())
                }
                None => {
                    let length = args.length.ok_or_else(|| {
                        filecrypt::error::AppError::InvalidArgument(
                            "password length is required".to_string(),
                        )
                    })?;
                    let password = keygen::generate_password(length)?;
                    stdout.write_all(password.as_slice())?;
                    stdout.write_all(b"\n")?;
                    stdout.flush()?;
                    Ok(())
                }
            }
        }
    }
}

fn normalized_args() -> Vec<OsString> {
    env::args_os()
        .map(|arg| {
            if arg == "-sep" {
                OsString::from("--sep")
            } else if let Some(value) = arg.to_str().and_then(|arg| arg.strip_prefix("-sep=")) {
                OsString::from(format!("--sep={value}"))
            } else {
                arg
            }
        })
        .collect()
}
