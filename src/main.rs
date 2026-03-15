use clap::Parser;
use std::fs;

use filecrypt::cli::{Cli, Command};
use filecrypt::crypto::{CryptoConfig, FILE_PREFIX_LEN};
use filecrypt::error::Result;
use filecrypt::{file_ops, overwrite, pathing, progress, prompt};

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let config = CryptoConfig::default();

    match cli.command {
        Command::Encrypt { input, force } => {
            let output = pathing::encryption_output_path(&input)?;
            let allow_overwrite =
                overwrite::resolve_overwrite(&output, force, prompt::confirm_overwrite)?;
            let password = prompt::prompt_password_for_encryption()?;
            let total = fs::metadata(&input)?.len();
            let pb = progress::create_progress_bar(total, "Encrypting");

            let result = file_ops::encrypt_file(
                &input,
                &output,
                password.as_str(),
                &config,
                allow_overwrite,
                |n| pb.inc(n),
            );
            pb.finish_and_clear();
            result?;

            println!("Encryption complete: {}", output.display());
            Ok(())
        }
        Command::Decrypt { input, force } => {
            let output = pathing::decryption_output_path(&input)?;
            let allow_overwrite =
                overwrite::resolve_overwrite(&output, force, prompt::confirm_overwrite)?;
            let password = prompt::prompt_password_for_decryption()?;
            let total = fs::metadata(&input)?
                .len()
                .saturating_sub(FILE_PREFIX_LEN as u64);
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
    }
}
