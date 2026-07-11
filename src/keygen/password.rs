use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AppError, Result};

pub const MAX_PASSWORD_LEN: usize = 4096;
pub const PASSWORD_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~";
pub const COMPATIBLE_PASSWORD_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_-+=";

pub fn generate_password(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    generate_password_from_alphabet(len, PASSWORD_ALPHABET)
}

pub fn generate_compatible_password(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    generate_password_from_alphabet(len, COMPATIBLE_PASSWORD_ALPHABET)
}

fn generate_password_from_alphabet(len: usize, alphabet: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if len == 0 || len > MAX_PASSWORD_LEN {
        return Err(AppError::InvalidGeneratedPasswordLength(MAX_PASSWORD_LEN));
    }

    let alphabet_len = alphabet.len();
    let limit = 256 - (256 % alphabet_len);
    let mut password = Zeroizing::new(Vec::with_capacity(len));
    let mut random = [0u8; 64];

    while password.len() < len {
        OsRng.fill_bytes(&mut random);
        for byte in random {
            if password.len() == len {
                break;
            }
            let value = usize::from(byte);
            if value < limit {
                password.push(alphabet[value % alphabet_len]);
            }
        }
    }

    random.zeroize();
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_contains_required_character_classes() {
        for byte in b'A'..=b'Z' {
            assert!(PASSWORD_ALPHABET.contains(&byte));
        }
        for byte in b'a'..=b'z' {
            assert!(PASSWORD_ALPHABET.contains(&byte));
        }
        for byte in b'0'..=b'9' {
            assert!(PASSWORD_ALPHABET.contains(&byte));
        }
        for byte in b"!#$%&()*+,-./:;<=>?@[]^_{|}~" {
            assert!(PASSWORD_ALPHABET.contains(byte));
        }
    }

    #[test]
    fn generated_password_has_requested_length_and_allowed_chars() {
        let password = generate_password(128).expect("password must be generated");

        assert_eq!(password.len(), 128);
        assert!(password.iter().all(|byte| PASSWORD_ALPHABET.contains(byte)));
    }

    #[test]
    fn compatible_password_uses_only_the_compatible_alphabet() {
        let password = generate_compatible_password(512).expect("password must be generated");

        assert_eq!(password.len(), 512);
        assert!(password
            .iter()
            .all(|byte| COMPATIBLE_PASSWORD_ALPHABET.contains(byte)));
        assert!(COMPATIBLE_PASSWORD_ALPHABET
            .iter()
            .all(|byte| PASSWORD_ALPHABET.contains(byte)));
    }

    #[test]
    fn invalid_lengths_are_rejected() {
        let zero = generate_password(0).expect_err("zero length must be rejected");
        assert!(matches!(
            zero,
            AppError::InvalidGeneratedPasswordLength(MAX_PASSWORD_LEN)
        ));

        let too_long =
            generate_password(MAX_PASSWORD_LEN + 1).expect_err("too long length must be rejected");
        assert!(matches!(
            too_long,
            AppError::InvalidGeneratedPasswordLength(MAX_PASSWORD_LEN)
        ));
    }
}
