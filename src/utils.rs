use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use getrandom::fill;
use secrecy::{ExposeSecret, SecretBox};

use crate::{error::DefendorError, error::DefendorResult};

/// 生成安全随机字节
pub fn get_random_bytes(size: usize) -> DefendorResult<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    fill(&mut buffer)?;
    Ok(buffer)
}

pub fn encrypt_data(
    data: &[u8],
    key: &SecretBox<Vec<u8>>,
    nonce: &[u8],
) -> DefendorResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
        .map_err(|_| DefendorError::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(nonce);
    let encrypted = cipher.encrypt(nonce, data)?;

    Ok(encrypted)
}

pub fn decrypt_data(
    data: &[u8],
    key: &SecretBox<Vec<u8>>,
    nonce: &[u8],
) -> DefendorResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
        .map_err(|_| DefendorError::InvalidKeyLength)?;

    let nonce = Nonce::from_slice(nonce);
    let decrypted = cipher.decrypt(nonce, data)?;

    Ok(decrypted)
}
