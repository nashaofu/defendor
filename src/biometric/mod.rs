use secrecy::{ExposeSecret, SecretBox};

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
use windows::derive_key_by_biometric_impl;

use crate::{
    NONCE_LENGTH,
    error::{DefendorError, DefendorResult},
    key_manager::KeyManager,
    utils::{decrypt_data, encrypt_data, get_random_bytes},
};

#[derive(Debug)]
pub struct BiometricConfig {
    pub challenge: Vec<u8>,
    pub nonce: Vec<u8>,
    pub encrypted_key: Vec<u8>,
}

pub trait Biometric: KeyManager {
    type BiometricError: From<Self::KeyManagerError> + From<DefendorError>;
    fn get_biometric_config(
        &self,
    ) -> impl Future<Output = Result<BiometricConfig, Self::BiometricError>>;
    fn set_biometric_config(
        &mut self,
        config: BiometricConfig,
    ) -> impl Future<Output = Result<(), Self::BiometricError>>;
    fn delete_biometric_config(&mut self) -> impl Future<Output = Result<(), Self::BiometricError>>;
    fn init_biometric(
        &mut self,
        name: &str,
    ) -> impl Future<Output = Result<&mut Self, Self::BiometricError>> {
        async {
            let key = self.get_key().await?;
            let challenge = get_random_bytes(NONCE_LENGTH)?;
            let unlock_key = derive_key_by_biometric(&challenge, name).await?;

            let nonce = get_random_bytes(NONCE_LENGTH)?;
            let encrypted_key = encrypt_data(key.expose_secret(), &unlock_key, &nonce)?;

            self.set_biometric_config(BiometricConfig {
                challenge,
                nonce,
                encrypted_key,
            })
            .await?;

            Ok(self)
        }
    }

    /// 加载密钥库
    fn load_by_biometric(
        &mut self,
        name: &str,
    ) -> impl Future<Output = Result<&mut Self, Self::BiometricError>> {
        async {
            let biometric_config = self.get_biometric_config().await?;
            let unlock_key = derive_key_by_biometric(&biometric_config.challenge, name).await?;

            let key = decrypt_data(
                &biometric_config.encrypted_key,
                &unlock_key,
                &biometric_config.nonce,
            )?;

            self.set_key(SecretBox::new(Box::new(key))).await?;

            Ok(self)
        }
    }
}

pub async fn derive_key_by_biometric(
    challenge: &[u8],
    name: &str,
) -> DefendorResult<SecretBox<Vec<u8>>> {
    derive_key_by_biometric_impl(challenge, name)
}
