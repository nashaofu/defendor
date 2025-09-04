use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::{
    KEY_LENGTH,
    error::{DefendorError, DefendorResult},
    key_manager::KeyManager,
    utils::{decrypt_data, encrypt_data, get_random_bytes},
};

// 32 bytes for salt
const SALT_LENGTH: usize = 32;

#[derive(Debug)]
pub struct PasswordConfig {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub encrypted_key: Vec<u8>,
}

pub trait Password: KeyManager {
    type PasswordError: From<Self::KeyManagerError> + From<DefendorError>;
    fn get_password_config(
        &self,
    ) -> impl Future<Output = Result<PasswordConfig, Self::PasswordError>>;
    fn set_password_config(
        &mut self,
        config: PasswordConfig,
    ) -> impl Future<Output = Result<(), Self::PasswordError>>;
    fn delete_password_config(&mut self) -> impl Future<Output = Result<(), Self::PasswordError>>;
    /// 初始化密钥库
    fn init_password<Z>(
        &mut self,
        password: Z,
    ) -> impl Future<Output = Result<&mut Self, Self::PasswordError>>
    where
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        async {
            let key = self.get_key().await?;
            let salt = get_random_bytes(SALT_LENGTH)?;
            let unlock_key = derive_key_by_password(&password.into(), &salt)?;
            let nonce = get_random_bytes(12)?;

            let encrypted_key = encrypt_data(key.expose_secret(), &unlock_key, &nonce)?;

            self.set_password_config(PasswordConfig {
                salt,
                nonce,
                encrypted_key,
            })
            .await?;

            Ok(self)
        }
    }

    /// 加载密钥库
    fn load_by_password<Z>(
        &mut self,
        password: Z,
    ) -> impl Future<Output = Result<&mut Self, Self::PasswordError>>
    where
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        async {
            let password_config = self.get_password_config().await?;

            let unlock_key = derive_key_by_password(&password.into(), &password_config.salt)?;

            let key = decrypt_data(
                &password_config.encrypted_key,
                &unlock_key,
                &password_config.nonce,
            )?;

            self.set_key(SecretBox::new(Box::new(key))).await?;

            Ok(self)
        }
    }

    fn change_password<Z>(
        &mut self,
        old_password: Z,
        new_password: Z,
    ) -> impl Future<Output = Result<(), Self::PasswordError>>
    where
        Z: Into<Zeroizing<Vec<u8>>>,
    {
        async {
            let password_config = self.get_password_config().await?;
            let old_unlock_key =
                derive_key_by_password(&old_password.into(), &password_config.salt)?;
            let old_key = decrypt_data(
                &password_config.encrypted_key,
                &old_unlock_key,
                &password_config.nonce,
            )?;

            let key = self.get_key().await?;

            if key.expose_secret() != &old_key {
                return Err(DefendorError::PasswordError.into());
            }

            let salt = get_random_bytes(SALT_LENGTH)?;
            let unlock_key = derive_key_by_password(&new_password.into(), &salt)?;

            let nonce = get_random_bytes(12)?;
            let encrypted_key = encrypt_data(key.expose_secret(), &unlock_key, &nonce)?;

            self.set_password_config(PasswordConfig {
                salt,
                nonce,
                encrypted_key,
            })
            .await?;

            Ok(())
        }
    }
}

/// 密码和盐派生密钥，使用更高安全参数
fn derive_key_by_password(
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
