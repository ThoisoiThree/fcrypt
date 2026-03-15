use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};

pub fn encryption_output_path(input: &Path) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .ok_or_else(|| AppError::MissingFileName(input.to_path_buf()))?;

    let mut encrypted_name: OsString = file_name.to_os_string();
    encrypted_name.push(".enc");
    Ok(input.with_file_name(encrypted_name))
}

pub fn decryption_output_path(input: &Path) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .ok_or_else(|| AppError::MissingFileName(input.to_path_buf()))?;
    let file_name_string = file_name.to_string_lossy();

    if let Some(stripped) = file_name_string.strip_suffix(".enc") {
        if !stripped.is_empty() {
            return Ok(input.with_file_name(stripped));
        }
    }

    let mut decrypted_name: OsString = file_name.to_os_string();
    decrypted_name.push(".dec");
    Ok(input.with_file_name(decrypted_name))
}
