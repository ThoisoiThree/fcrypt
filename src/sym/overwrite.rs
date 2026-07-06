use std::path::Path;

use crate::error::{AppError, Result};

pub fn resolve_overwrite<F>(output_path: &Path, force: bool, mut confirm: F) -> Result<bool>
where
    F: FnMut(&Path) -> Result<bool>,
{
    if !output_path.exists() {
        return Ok(false);
    }

    if force {
        return Ok(true);
    }

    if confirm(output_path)? {
        Ok(true)
    } else {
        Err(AppError::UserAborted)
    }
}
