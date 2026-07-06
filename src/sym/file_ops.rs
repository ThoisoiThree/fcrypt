use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::error::{AppError, Result};
use crate::sym::crypto::{self, CryptoConfig, CryptoMode};

pub fn encrypt_file<F>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    config: &CryptoConfig,
    allow_overwrite: bool,
    on_progress: F,
) -> Result<()>
where
    F: FnMut(u64),
{
    encrypt_file_with_mode(
        input_path,
        output_path,
        password,
        config,
        CryptoMode::Standard,
        allow_overwrite,
        on_progress,
    )
}

pub fn encrypt_file_with_mode<F>(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    config: &CryptoConfig,
    mode: CryptoMode,
    allow_overwrite: bool,
    on_progress: F,
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
        crypto::encrypt_stream_with_mode(
            &mut reader,
            &mut writer,
            input_len,
            password,
            config,
            mode,
            on_progress,
        )?;
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
    let result = if allow_overwrite {
        temp_file.persist(output_path)
    } else {
        temp_file.persist_noclobber(output_path)
    };

    result.map(|_| ()).map_err(|e| {
        if e.error.kind() == std::io::ErrorKind::AlreadyExists {
            AppError::OutputExists(output_path.to_path_buf())
        } else {
            AppError::Io(e.error)
        }
    })
}

fn output_parent_dir(output_path: &Path) -> PathBuf {
    output_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn persist_temp_file_does_not_clobber_without_overwrite() {
        let dir = tempdir().expect("tempdir must be created");
        let output = dir.path().join("output.bin");
        std::fs::write(&output, b"old").expect("existing output must be written");

        let mut temp_output =
            NamedTempFile::new_in(dir.path()).expect("temp output must be created");
        temp_output
            .write_all(b"new")
            .expect("temp output must be written");

        let err = persist_temp_file(temp_output, &output, false)
            .expect_err("persist must fail when output exists");

        assert!(matches!(err, AppError::OutputExists(path) if path == output));
        assert_eq!(
            std::fs::read(&output).expect("output must remain readable"),
            b"old"
        );
    }

    #[test]
    fn persist_temp_file_replaces_when_overwrite_allowed() {
        let dir = tempdir().expect("tempdir must be created");
        let output = dir.path().join("output.bin");
        std::fs::write(&output, b"old").expect("existing output must be written");

        let mut temp_output =
            NamedTempFile::new_in(dir.path()).expect("temp output must be created");
        temp_output
            .write_all(b"new")
            .expect("temp output must be written");

        persist_temp_file(temp_output, &output, true).expect("persist must replace output");

        assert_eq!(
            std::fs::read(&output).expect("output must remain readable"),
            b"new"
        );
    }
}
