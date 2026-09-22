use std::fs::{self, File};
use std::io;
use std::path::Path;

use crate::error::{AppError, Result};

/// Open a regular input file and return it with its length.
///
/// Encryption trusts the reported length when sizing the container, so pipes,
/// devices, and directories (which report zero or meaningless lengths) are
/// rejected. The path is checked before opening so a FIFO without a writer
/// cannot block, and the opened handle is checked again in case the path was
/// replaced in between.
pub fn open_regular_file(path: &Path) -> Result<(File, u64)> {
    if !fs::metadata(path)?.is_file() {
        return Err(AppError::InputNotRegularFile(path.to_path_buf()));
    }
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(AppError::InputNotRegularFile(path.to_path_buf()));
    }
    Ok((file, metadata.len()))
}

/// Reject an existing input that is not a regular file, without opening it.
/// The CLI calls this before prompting for credentials. A missing path is
/// left to the operation itself so its usual error ordering is preserved;
/// `open_regular_file` re-checks either way.
pub fn reject_non_regular_file(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            Err(AppError::InputNotRegularFile(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AppError::Io(error)),
    }
}
