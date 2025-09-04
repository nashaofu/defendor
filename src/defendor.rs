use base64ct::{Base64, Encoding};
use secrecy::{ExposeSecret, SecretBox};

#[cfg(feature = "biometric")]
use crate::biometric::{Biometric, BiometricConfig};
use crate::{
    KEY_LENGTH, NONCE_LENGTH,
    data::Data,
    error::{DefendorError, DefendorResult},
    key_manager::KeyManager,
    password::{Password, PasswordConfig},
    store::Store,
    utils::{decrypt_data, encrypt_data, get_random_bytes},
};

pub struct Defendor<S>
where
    S: Store,
{
    key: Option<secrecy::SecretBox<Vec<u8>>>,
    store: S,
}

impl<S: Store> KeyManager for Defendor<S> {
    type KeyManagerError = DefendorError;
    async fn get_key(&self) -> DefendorResult<SecretBox<Vec<u8>>> {
        let key = self
            .key
            .as_ref()
            .ok_or(DefendorError::CryptoNotInit)?
            .expose_secret();

        Ok(SecretBox::new(Box::new(key.clone())))
    }

    async fn set_key(&mut self, val: secrecy::SecretBox<Vec<u8>>) -> DefendorResult<()> {
        self.key = Some(val);
        Ok(())
    }
}

impl<S: Store> Password for Defendor<S> {
    type PasswordError = DefendorError;
    async fn get_password_config(&self) -> DefendorResult<PasswordConfig> {
        let password_salt = self
            .store
            .get("password_salt")
            .await
            .ok_or(DefendorError::CryptoNotInit)?;

        let password_nonce = self
            .store
            .get("password_nonce")
            .await
            .ok_or(DefendorError::CryptoNotInit)?;

        let password_encrypted_key = self
            .store
            .get("password_encrypted_key")
            .await
            .ok_or(DefendorError::CryptoNotInit)?;

        Ok(PasswordConfig {
            salt: Base64::decode_vec(&password_salt)?,
            nonce: Base64::decode_vec(&password_nonce)?,
            encrypted_key: Base64::decode_vec(&password_encrypted_key)?,
        })
    }

    async fn set_password_config(&mut self, config: PasswordConfig) -> DefendorResult<()> {
        self.store
            .set("password_salt", &Base64::encode_string(&config.salt))
            .await;
        self.store
            .set("password_nonce", &Base64::encode_string(&config.nonce))
            .await;
        self.store
            .set(
                "password_encrypted_key",
                &Base64::encode_string(&config.encrypted_key),
            )
            .await;

        Ok(())
    }

    async fn delete_password_config(&mut self) -> DefendorResult<()> {
        self.store.delete("password_salt").await;
        self.store.delete("password_nonce").await;
        self.store.delete("password_encrypted_key").await;

        Ok(())
    }
}

#[cfg(feature = "biometric")]
impl<S: Store> Biometric for Defendor<S> {
    type BiometricError = DefendorError;
    async fn get_biometric_config(&self) -> DefendorResult<BiometricConfig> {
        let biometric_challenge = self
            .store
            .get("biometric_challenge")
            .await
            .ok_or(DefendorError::CryptoNotInit)?;

        let biometric_nonce = self
            .store
            .get("biometric_nonce")
            .await
            .ok_or(DefendorError::CryptoNotInit)?;

        let biometric_encrypted_key = self
            .store
            .get("biometric_encrypted_key")
            .await
            .ok_or(DefendorError::CryptoNotInit)?;

        Ok(BiometricConfig {
            challenge: Base64::decode_vec(&biometric_challenge)?,
            nonce: Base64::decode_vec(&biometric_nonce)?,
            encrypted_key: Base64::decode_vec(&biometric_encrypted_key)?,
        })
    }

    async fn set_biometric_config(&mut self, config: BiometricConfig) -> DefendorResult<()> {
        self.store
            .set(
                "biometric_challenge",
                &Base64::encode_string(&config.challenge),
            )
            .await;
        self.store
            .set("biometric_nonce", &Base64::encode_string(&config.nonce))
            .await;
        self.store
            .set(
                "biometric_encrypted_key",
                &Base64::encode_string(&config.encrypted_key),
            )
            .await;

        Ok(())
    }

    async fn delete_biometric_config(&mut self) -> DefendorResult<()> {
        self.store.delete("biometric_challenge").await;
        self.store.delete("biometric_nonce").await;
        self.store.delete("biometric_encrypted_key").await;

        Ok(())
    }
}

pub const VERSION: u16 = 1;

impl<S: Store> Defendor<S> {
    pub fn with_store(store: S) -> Self {
        Self { key: None, store }
    }

    pub async fn init_key(&mut self) -> DefendorResult<&mut Self> {
        let bytes = get_random_bytes(KEY_LENGTH)?;
        let key = SecretBox::new(Box::new(bytes));
        self.key = Some(key);
        Ok(self)
    }

    pub async fn is_init(&self) -> bool {
        let has_password_config = self.get_password_config().await.is_ok();

        #[cfg(feature = "biometric")]
        let has_biometric_config = self.get_biometric_config().await.is_ok();

        #[cfg(not(feature = "biometric"))]
        let has_biometric_config = false;

        has_password_config || has_biometric_config
    }

    pub async fn clear(&mut self) -> DefendorResult<&mut Self> {
        self.delete_password_config().await?;
        #[cfg(feature = "biometric")]
        self.delete_biometric_config().await?;
        self.key = None;

        Ok(self)
    }

    /// 加密数据，仅返回加密后的数据
    pub async fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> DefendorResult<Vec<u8>> {
        let key = self.get_key().await?;
        let encrypted = encrypt_data(data, &key, nonce)?;

        Ok(encrypted)
    }
    /// 解密数据，仅返回解密后的数据
    pub async fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> DefendorResult<Vec<u8>> {
        let key = self.get_key().await?;
        let decrypted = decrypt_data(data, &key, nonce)?;

        Ok(decrypted)
    }

    /// 加密数据，并自动生成随机 nonce
    /// 返回包含版本、nonce 和加密数据的原始字节
    pub async fn encrypt(&self, data: &[u8]) -> DefendorResult<Vec<u8>> {
        let nonce = get_random_bytes(NONCE_LENGTH)?;
        let encrypted = self.encrypt_with_nonce(data, &nonce).await?;
        let data = Data::new(VERSION, nonce, encrypted);

        Ok(data.to_bytes())
    }

    /// 解密包含版本、nonce 和加密数据的原始字节
    /// 返回解密后的数据
    pub async fn decrypt(&self, data: &[u8]) -> DefendorResult<Vec<u8>> {
        let data = Data::from_bytes(data)?;
        let decrypted = self
            .decrypt_with_nonce(&data.encrypted, &data.nonce)
            .await?;

        Ok(decrypted)
    }
}
