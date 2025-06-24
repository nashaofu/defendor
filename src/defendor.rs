use std::{fmt::Debug, path::Path};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64, Encoding};
use getrandom::fill;
use secrecy::{ExposeSecret, SecretBox};
use serde_json::{from_str, to_string};
use tokio::fs;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{DefendorError, data::Data, error::DefendorResult, key_store::KeyStore};

// 32 bytes for AES-256
pub const KEY_LENGTH: usize = 32;
// 32 bytes for salt
pub const SALT_LENGTH: usize = 32;
// 12 bytes for nonce
pub const NONCE_LENGTH: usize = 12;
// 2 bytes for VERSION
pub const VERSION_LENGTH: usize = 2;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Defendor {
    path: String,
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
    pub const VERSION: u16 = 1;
    /// 初始化或加载密钥库
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

    /// 初始化密钥库
    pub async fn init<P, Z>(path: P, password: Z) -> DefendorResult<Self>
    where
        P: AsRef<Path>,
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        let salt = Self::random(SALT_LENGTH)?;
        let unlock_key = Self::derive_key(&password.into(), &salt)?;
        let nonce = Defendor::random(12)?;
        let key = SecretBox::new(Box::new(Self::random(KEY_LENGTH)?));
        let encrypted_key = Defendor::encrypt_data(key.expose_secret(), &unlock_key, &nonce)?;

        let salt_b64 = Base64::encode_string(&salt);
        let data = Data::new(Self::VERSION, nonce, encrypted_key);
        let encrypted_key_b64 = Base64::encode_string(&data.to_bytes());

        let key_store = KeyStore::new(salt_b64, encrypted_key_b64);

        let json = to_string(&key_store)?;
        fs::write(&path, json).await?;
        Ok(Defendor {
            path: path.as_ref().to_string_lossy().into(),
            salt,
            key,
        })
    }

    /// 加载密钥库
    pub async fn load<P, Z>(path: P, password: Z) -> DefendorResult<Self>
    where
        P: AsRef<Path>,
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        let json = fs::read_to_string(&path).await?;
        let key_store: KeyStore = from_str(&json)?;

        let salt = Base64::decode_vec(&key_store.salt)?;
        let encrypted_key = Base64::decode_vec(&key_store.encrypted_key)?;
        let data = Data::from_bytes(&encrypted_key)?;

        let unlock_key = Self::derive_key(&password.into(), &salt)?;

        let key = Defendor::decrypt_data(&data.encrypted, &unlock_key, &data.nonce)?;

        Ok(Defendor {
            path: path.as_ref().to_string_lossy().into(),
            salt,
            key: SecretBox::new(Box::new(key)),
        })
    }

    /// 生成安全随机字节
    pub fn random(size: usize) -> DefendorResult<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        fill(&mut buffer)?;
        Ok(buffer)
    }

    /// 密码和盐派生密钥，使用更高安全参数
    pub fn derive_key(
        password: &Zeroizing<Vec<u8>>,
        salt: &[u8],
    ) -> DefendorResult<SecretBox<Vec<u8>>> {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(128 * 1024, 4, 4, None)?, // 128MB, 4线程, 4次迭代
        );
        let mut key = vec![0u8; KEY_LENGTH];

        argon2.hash_password_into(password, salt, &mut key)?;

        Ok(SecretBox::new(Box::new(key)))
    }

    pub async fn change_password<Z>(&mut self, password: Z) -> DefendorResult<()>
    where
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        self.salt = Self::random(SALT_LENGTH)?;
        let unlock_key = Self::derive_key(&password.into(), &self.salt)?;

        let nonce = Defendor::random(12)?;
        let encrypted_key = Defendor::encrypt_data(self.key.expose_secret(), &unlock_key, &nonce)?;

        let salt_b64 = Base64::encode_string(&self.salt);
        let data = Data::new(Self::VERSION, nonce, encrypted_key);
        let encrypted_key_b64 = Base64::encode_string(&data.to_bytes());

        let key_store = KeyStore::new(salt_b64, encrypted_key_b64);
        let json = to_string(&key_store)?;

        fs::write(&self.path, json).await?;

        Ok(())
    }

    pub async fn rotate_key<Z>(&mut self, password: Z) -> DefendorResult<()>
    where
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        self.salt = Self::random(SALT_LENGTH)?;
        let unlock_key = Self::derive_key(&password.into(), &self.salt)?;

        let nonce = Defendor::random(12)?;
        let key = SecretBox::new(Box::new(Self::random(KEY_LENGTH)?));
        let encrypted_key = Defendor::encrypt_data(key.expose_secret(), &unlock_key, &nonce)?;

        self.key = key;

        let salt_b64 = Base64::encode_string(&self.salt);
        let data = Data::new(Self::VERSION, nonce, encrypted_key);
        let encrypted_key_b64 = Base64::encode_string(&data.to_bytes());

        let key_store = KeyStore::new(salt_b64, encrypted_key_b64);
        let json = to_string(&key_store)?;

        fs::write(&self.path, json).await?;

        Ok(())
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

    /// 加密数据，仅返回加密后的数据
    pub fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> DefendorResult<Vec<u8>> {
        Self::encrypt_data(data, &self.key, nonce)
    }
    /// 解密数据，仅返回解密后的数据
    pub fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> DefendorResult<Vec<u8>> {
        Self::decrypt_data(data, &self.key, nonce)
    }

    /// 加密数据，并自动生成随机 nonce
    /// 返回包含版本、nonce 和加密数据的原始字节
    pub fn encrypt(&self, data: &[u8]) -> DefendorResult<Vec<u8>> {
        let nonce = Self::random(NONCE_LENGTH)?;
        let encrypted = self.encrypt_with_nonce(data, &nonce)?;
        let data = Data::new(Self::VERSION, nonce, encrypted);

        Ok(data.to_bytes())
    }

    /// 解密包含版本、nonce 和加密数据的原始字节
    /// 返回解密后的数据
    pub fn decrypt(&self, data: &[u8]) -> DefendorResult<Vec<u8>> {
        let data = Data::from_bytes(data)?;

        self.decrypt_with_nonce(&data.encrypted, &data.nonce)
    }
}
