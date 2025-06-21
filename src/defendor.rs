use std::{fmt::Debug, path::Path};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64, Encoding};
use getrandom::fill;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};
use tokio::fs;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{DefendorError, error::DefendorResult};

// 32 bytes for AES-256
const KEY_LENGTH: usize = 32;
// 32 bytes for salt
const SALT_LENGTH: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Defendor {
    salt: Vec<u8>,
    key: SecretBox<Vec<u8>>,
}

impl Debug for Defendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unlockor")
            .field("salt", &"[REDACTED]")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Defendor {
    pub async fn new<P, Z>(path: P, password: Z) -> DefendorResult<Self>
    where
        P: AsRef<Path>,
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        let is_exists = fs::try_exists(path.as_ref()).await?;
        if is_exists {
            Self::load(path, password).await
        } else {
            Self::init(path, password).await
        }
    }

    pub async fn init<P, Z>(path: P, password: Z) -> DefendorResult<Self>
    where
        P: AsRef<Path>,
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        let salt = Self::random(SALT_LENGTH)?;
        let key = SecretBox::new(Box::new(Self::random(KEY_LENGTH)?));

        let unlock_key = Self::derive_key(&password.into(), &salt)?;

        let mut nonce = Defendor::random(12)?;

        let encrypted_key = Defendor::encrypt_data(key.expose_secret(), &unlock_key, &nonce)?;

        nonce.extend_from_slice(&encrypted_key);

        let salt_b64 = Base64::encode_string(&salt);
        let encrypted_key_b64 = Base64::encode_string(&nonce);

        let vault = Vault::new(salt_b64, encrypted_key_b64);
        let json = to_string(&vault)?;

        fs::write(path, json).await?;

        Ok(Defendor { salt, key })
    }

    pub async fn load<P, Z>(path: P, password: Z) -> DefendorResult<Self>
    where
        P: AsRef<Path>,
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        let json = fs::read_to_string(path).await?;
        let vault: Vault = from_str(&json)?;

        let salt = Base64::decode_vec(&vault.salt)?;
        let encrypted_key = Base64::decode_vec(&vault.encrypted_key)?;
        let unlock_key = Self::derive_key(&password.into(), &salt)?;

        let nonce = &encrypted_key[..12];
        let encrypted_key = &encrypted_key[12..];

        let key = Defendor::decrypt_data(&encrypted_key, &unlock_key, &nonce)?;

        Ok(Defendor {
            salt,
            key: SecretBox::new(Box::new(key)),
        })
    }

    pub fn random(size: usize) -> DefendorResult<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        fill(&mut buffer)?;
        Ok(buffer)
    }

    pub fn derive_key(
        password: &Zeroizing<Vec<u8>>,
        salt: &[u8],
    ) -> DefendorResult<SecretBox<Vec<u8>>> {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(64 * 1024, 4, 2, None)?,
        );
        let mut key = vec![0u8; KEY_LENGTH];

        argon2.hash_password_into(&password, salt, &mut key)?;

        Ok(SecretBox::new(Box::new(key)))
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

    pub fn encrypt(&self, data: &[u8], nonce: &[u8]) -> DefendorResult<Vec<u8>> {
        Self::encrypt_data(data, &self.key, nonce)
    }

    pub fn decrypt(&self, data: &[u8], nonce: &[u8]) -> DefendorResult<Vec<u8>> {
        Self::decrypt_data(data, &self.key, nonce)
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct Vault {
    pub salt: String,
    pub encrypted_key: String,
}

impl Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("salt", &"[REDACTED]")
            .field("encrypted_key", &"[REDACTED]")
            .finish()
    }
}

impl Vault {
    pub fn new(salt: String, encrypted_key: String) -> Self {
        Vault {
            salt,
            encrypted_key,
        }
    }
}
