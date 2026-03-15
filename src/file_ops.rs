use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::crypto::{self, CryptoConfig};
use crate::error::{AppError, Result};

pub fn encrypt_file<F>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    config: &CryptoConfig,
    allow_overwrite: bool,
    mut on_progress: F,
) -> Result<()>
where
    F: FnMut(u64),
{
    if output_path.exists() && !allow_overwrite {
        return Err(AppError::OutputExists(output_path.to_path_buf()));
    }

    let input_file = File::open(input_path)?;
    let input_len = input_file.metadata()?.len();
    let reader_capacity = config.chunk_size.max(64 * 1024);
    let mut reader = BufReader::with_capacity(reader_capacity, input_file);

    let output_dir = output_parent_dir(output_path);
    let mut temp_output = NamedTempFile::new_in(output_dir)?;
    {
        let writer_capacity = config
            .chunk_size
            .checked_add(crypto::TAG_LEN)
            .ok_or(AppError::InputTooLarge)?
            .max(64 * 1024);
        let mut writer = BufWriter::with_capacity(writer_capacity, temp_output.as_file_mut());
        crypto::encrypt_stream(&mut reader, &mut writer, input_len, password, config, |n| {
            on_progress(n)
        })?;
        writer.flush()?;
    }

    temp_output.as_file_mut().sync_all()?;
    persist_temp_file(temp_output, output_path, allow_overwrite)
}

pub fn decrypt_file<F>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    config: &CryptoConfig,
    allow_overwrite: bool,
    mut on_progress: F,
) -> Result<()>
where
    F: FnMut(u64),
{
    if output_path.exists() && !allow_overwrite {
        return Err(AppError::OutputExists(output_path.to_path_buf()));
    }

    let input_file = File::open(input_path)?;
    let input_len = input_file.metadata()?.len();
    let reader_capacity = config.chunk_size.max(64 * 1024);
    let mut reader = BufReader::with_capacity(reader_capacity, input_file);

    let output_dir = output_parent_dir(output_path);
    let mut temp_output = NamedTempFile::new_in(output_dir)?;
    {
        let writer_capacity = config
            .chunk_size
            .checked_add(crypto::TAG_LEN)
            .ok_or(AppError::InputTooLarge)?
            .max(64 * 1024);
        let mut writer = BufWriter::with_capacity(writer_capacity, temp_output.as_file_mut());
        crypto::decrypt_stream(&mut reader, &mut writer, input_len, password, config, |n| {
            on_progress(n)
        })?;
        writer.flush()?;
    }

    temp_output.as_file_mut().sync_all()?;
    persist_temp_file(temp_output, output_path, allow_overwrite)
}

fn persist_temp_file(
    temp_file: NamedTempFile,
    output_path: &Path,
    allow_overwrite: bool,
) -> Result<()> {
    if output_path.exists() {
        if !allow_overwrite {
            return Err(AppError::OutputExists(output_path.to_path_buf()));
        }
        fs::remove_file(output_path)?;
    }

    temp_file
        .persist(output_path)
        .map_err(|e| AppError::Io(e.error))?;
    Ok(())
}

fn output_parent_dir(output_path: &Path) -> PathBuf {
    output_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
