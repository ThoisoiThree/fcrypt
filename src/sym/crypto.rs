use std::io::{Read, Write};

use crate::error::Result;
use crate::format::opaque;

pub const TAG_LEN: usize = opaque::TAG_LEN;
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub chunk_size: usize,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

pub fn expected_ciphertext_payload_len(plaintext_len: u64, chunk_size: usize) -> Result<u64> {
    opaque::expected_payload_len(plaintext_len, chunk_size)
}

pub fn encrypt_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    plaintext_len: u64,
    password: &str,
    config: &CryptoConfig,
    on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    opaque::encrypt_password_stream(reader, writer, plaintext_len, password, config, on_progress)
}

pub fn decrypt_stream<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    encrypted_len: u64,
    password: &str,
    _config: &CryptoConfig,
    on_progress: F,
) -> Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(u64),
{
    opaque::decrypt_password_stream(reader, writer, encrypted_len, password, on_progress)
}
