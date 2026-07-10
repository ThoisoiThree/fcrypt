use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};

pub fn encryption_output_path(input: &Path) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .ok_or_else(|| AppError::MissingFileName(input.to_path_buf()))?;

    let mut encrypted_name: OsString = file_name.to_os_string();
    encrypted_name.push(".bin");
    Ok(input.with_file_name(encrypted_name))
}

pub fn decryption_output_path(input: &Path) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .ok_or_else(|| AppError::MissingFileName(input.to_path_buf()))?;

    if has_extension(input, "bin") || has_extension(input, "enc") {
        return Ok(input.with_extension(""));
    }

    let mut decrypted_name: OsString = file_name.to_os_string();
    decrypted_name.push(".dec");
    Ok(input.with_file_name(decrypted_name))
}

pub fn asym_encryption_output_path(input: &Path) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .ok_or_else(|| AppError::MissingFileName(input.to_path_buf()))?;

    let mut encrypted_name: OsString = file_name.to_os_string();
    encrypted_name.push(".bin");
    Ok(input.with_file_name(encrypted_name))
}

pub fn asym_decryption_output_path(input: &Path) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .ok_or_else(|| AppError::MissingFileName(input.to_path_buf()))?;

    if has_extension(input, "bin") {
        return Ok(input.with_extension(""));
    }

    let mut decrypted_name: OsString = file_name.to_os_string();
    decrypted_name.push(".dec");
    Ok(input.with_file_name(decrypted_name))
}

pub fn asym_default_keys_dir_for_plain_input(input: &Path) -> Result<PathBuf> {
    default_keys_dir(input)
}

pub fn asym_default_keys_dir_for_encrypted_input(input: &Path) -> Result<PathBuf> {
    let logical_input = asym_decryption_output_path(input)?;
    default_keys_dir(&logical_input)
}

fn default_keys_dir(input: &Path) -> Result<PathBuf> {
    let file_stem = input
        .file_stem()
        .ok_or_else(|| AppError::MissingFileName(input.to_path_buf()))?;

    let mut dir_name = file_stem.to_os_string();
    dir_name.push("_keys");
    Ok(input.with_file_name(dir_name))
}

fn has_extension(path: &Path, extension: &str) -> bool {
    path.extension()
        .is_some_and(|value| value == OsStr::new(extension))
}
