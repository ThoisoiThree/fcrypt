use sha3::{Digest, Sha3_256};
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::Path;
use zeroize::Zeroizing;

use crate::error::{AppError, Result};
use crate::sym::input;

/// Domain-separation prefix hashed before the key file contents.
///
/// Changing either domain (or the digest/encoding below) changes the password
/// derived from every key file and makes existing key-file ciphertexts
/// undecryptable.
const KEY_FILE_DOMAIN: &[u8] = b"fcrypt key-file v1\0";
/// Domain-separation prefix for mixing a non-empty password with the key file.
const KEY_FILE_PASSWORD_DOMAIN: &[u8] = b"fcrypt key-file+password v1\0";
const READ_BUFFER_LEN: usize = 64 * 1024;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

type Digest32 = Zeroizing<[u8; 32]>;

/// Hashed key file contents. Deliberately neither `Debug` nor `Clone`.
pub struct KeyFile {
    /// `SHA3-256("fcrypt key-file v1\0" || contents)`.
    digest: Digest32,
    pub warning: Option<String>,
}

impl KeyFile {
    /// Derive the password for the existing opaque password slot.
    ///
    /// Without a password this is `hex(file_digest)`. With a password it is
    /// `hex(SHA3-256("fcrypt key-file+password v1\0" || u64be(len(password))
    /// || password || file_digest))`; the length prefix keeps the encoding
    /// unambiguous. The result then goes through the unchanged Argon2id
    /// profile, keeping the container format identical.
    pub fn slot_password(&self, password: &str) -> Zeroizing<String> {
        if password.is_empty() {
            return lower_hex(self.digest.as_slice());
        }
        let mut hasher = Sha3_256::new();
        hasher.update(KEY_FILE_PASSWORD_DOMAIN);
        hasher.update((password.len() as u64).to_be_bytes());
        hasher.update(password.as_bytes());
        hasher.update(self.digest.as_slice());
        lower_hex(finalize(hasher).as_slice())
    }
}

/// Hash an arbitrary regular file. Every byte is significant, so binary files
/// work and no line ending is trimmed.
pub fn read_key_file(path: &Path) -> Result<KeyFile> {
    let (mut file, _) = input::open_regular_file(path)?;
    let warning = insecure_permissions_warning(&file, path)?;

    let mut hasher = Sha3_256::new();
    hasher.update(KEY_FILE_DOMAIN);
    let mut buffer = Zeroizing::new(vec![0u8; READ_BUFFER_LEN]);
    let mut total = 0u64;
    loop {
        let read = match file.read(buffer.as_mut_slice()) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(AppError::Io(error)),
        };
        hasher.update(&buffer[..read]);
        total += read as u64;
    }
    if total == 0 {
        return Err(AppError::InvalidArgument(format!(
            "key file is empty: {}",
            path.display()
        )));
    }
    Ok(KeyFile {
        digest: finalize(hasher),
        warning,
    })
}

/// Reject a key file that is also the operation's input or output. Using the
/// output would overwrite the only copy of the key; using the input would make
/// the key and the protected data the same thing.
pub fn reject_key_file_reuse(key_file: &Path, input: &Path, output: &Path) -> Result<()> {
    for (other, role) in [(input, "input"), (output, "output")] {
        if same_existing_file(key_file, other) {
            return Err(AppError::InvalidArgument(format!(
                "key file must not be the {role} file"
            )));
        }
    }
    Ok(())
}

fn finalize(hasher: Sha3_256) -> Digest32 {
    let mut digest = Zeroizing::new([0u8; 32]);
    hasher.finalize_into(digest.as_mut_slice().into());
    digest
}

fn lower_hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut encoded = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn same_existing_file(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(unix)]
fn insecure_permissions_warning(file: &fs::File, path: &Path) -> Result<Option<String>> {
    use std::os::unix::fs::PermissionsExt;

    let mode = file.metadata()?.permissions().mode() & 0o777;
    Ok((mode & 0o077 != 0).then(|| {
        format!(
            "key file {} is readable by group or other users",
            path.display()
        )
    }))
}

#[cfg(not(unix))]
fn insecure_permissions_warning(_file: &fs::File, _path: &Path) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_digest(contents: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(KEY_FILE_DOMAIN);
        hasher.update(contents);
        hasher.finalize().to_vec()
    }

    #[test]
    fn derivation_is_stable_and_uses_every_byte() {
        let dir = tempfile::tempdir().expect("tempdir must be created");
        let key = dir.path().join("key");
        fs::write(&key, b"\x00\xffbinary\n").expect("key must be written");
        let first = read_key_file(&key).expect("key must read");
        assert_eq!(
            first.slot_password("").as_str(),
            hex::encode(file_digest(b"\x00\xffbinary\n"))
        );

        fs::write(&key, b"\x00\xffbinary").expect("key must be written");
        let trimmed = read_key_file(&key).expect("key must read");
        assert_ne!(
            first.slot_password("").as_str(),
            trimmed.slot_password("").as_str()
        );
    }

    #[test]
    fn password_is_mixed_with_a_length_prefix() {
        let dir = tempfile::tempdir().expect("tempdir must be created");
        let key = dir.path().join("key");
        fs::write(&key, b"key bytes").expect("key must be written");
        let key = read_key_file(&key).expect("key must read");

        let mut expected = Sha3_256::new();
        expected.update(KEY_FILE_PASSWORD_DOMAIN);
        expected.update(6u64.to_be_bytes());
        expected.update(b"secret");
        expected.update(file_digest(b"key bytes"));
        let mixed = key.slot_password("secret");
        assert_eq!(mixed.as_str(), hex::encode(expected.finalize()));
        assert_ne!(mixed.as_str(), key.slot_password("").as_str());
        assert_ne!(mixed.as_str(), key.slot_password("secret ").as_str());
    }
}
