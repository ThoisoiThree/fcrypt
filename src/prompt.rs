use rpassword::prompt_password;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use zeroize::Zeroizing;

use crate::error::{AppError, Result};

pub fn prompt_password_for_encryption() -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(prompt_password("Enter password: ")?);
    if password.is_empty() {
        return Err(AppError::EmptyPassword);
    }

    let confirmation = Zeroizing::new(prompt_password("Confirm password: ")?);
    if password.as_str() != confirmation.as_str() {
        return Err(AppError::PasswordMismatch);
    }

    Ok(password)
}

pub fn prompt_password_for_decryption() -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(prompt_password("Enter password: ")?);
    if password.is_empty() {
        return Err(AppError::EmptyPassword);
    }
    Ok(password)
}

pub fn confirm_overwrite(path: &Path) -> Result<bool> {
    if !io::stdin().is_terminal() {
        return Err(AppError::OutputExistsNonInteractive(path.to_path_buf()));
    }

    let mut stdout = io::stdout();
    write!(
        stdout,
        "Output file '{}' already exists. Overwrite? [y/N]: ",
        path.display()
    )?;
    stdout.flush()?;

    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    let normalized = response.trim().to_ascii_lowercase();
    Ok(matches!(normalized.as_str(), "y" | "yes"))
}
