use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

use crate::error::{AppError, Result};

pub struct PasswordFile {
    pub password: Zeroizing<String>,
    pub warning: Option<String>,
}

pub fn read_password_file(path: &Path) -> Result<PasswordFile> {
    let mut bytes = Zeroizing::new(fs::read(path)?);
    if bytes.ends_with(b"\r\n") {
        let new_len = bytes.len() - 2;
        bytes.truncate(new_len);
    } else if bytes.ends_with(b"\n") {
        let new_len = bytes.len() - 1;
        bytes.truncate(new_len);
    }
    let password = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(password) => password,
        Err(error) => {
            let mut invalid_bytes = error.into_bytes();
            use zeroize::Zeroize;
            invalid_bytes.zeroize();
            return Err(AppError::InvalidArgument(format!(
                "password file is not valid UTF-8: {}",
                path.display()
            )));
        }
    };
    let password = Zeroizing::new(password);
    if password.is_empty() {
        return Err(AppError::EmptyPassword);
    }
    Ok(PasswordFile {
        password,
        warning: insecure_permissions_warning(path)?,
    })
}

#[cfg(unix)]
fn insecure_permissions_warning(path: &Path) -> Result<Option<String>> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    Ok((mode & 0o077 != 0).then(|| {
        format!(
            "password file {} is readable by group or other users",
            path.display()
        )
    }))
}

#[cfg(not(unix))]
fn insecure_permissions_warning(_path: &Path) -> Result<Option<String>> {
    Ok(None)
}
