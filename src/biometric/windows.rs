use secrecy::SecretBox;
use sha2::{Digest, Sha256};
use windows::{
    Security::{
        Credentials::{KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus},
        Cryptography::CryptographicBuffer,
    },
    core::{Array, HSTRING},
};

use crate::error::{DefendorError, DefendorResult};

pub fn derive_key_by_biometric_impl(
    challenge: &[u8],
    name: &str,
) -> DefendorResult<SecretBox<Vec<u8>>> {
    let name = HSTRING::from(name);

    // 1. 先尝试打开现有凭证
    let result = match KeyCredentialManager::OpenAsync(&name)?.get() {
        Ok(open_res) => open_res,
        Err(_) => {
            // 不存在则创建
            let create_res = KeyCredentialManager::RequestCreateAsync(
                &name,
                KeyCredentialCreationOption::FailIfExists,
            )?
            .get()?;

            if create_res.Status()? != KeyCredentialStatus::Success {
                return Err(DefendorError::BiometricInitializationFailed);
            }
            create_res
        }
    };

    let credential = result.Credential()?;

    // 2. 准备 challenge（建议固定）
    let challenge_buffer = CryptographicBuffer::CreateFromByteArray(challenge)?;

    // 3. 请求签名
    let signature = credential.RequestSignAsync(&challenge_buffer)?.get()?;
    if signature.Status()? != KeyCredentialStatus::Success {
        return Err(DefendorError::BiometricInitializationFailed);
    }

    // 4. 取签名结果
    let signature_buffer = signature.Result()?;
    let mut signature_value = Array::<u8>::with_len(signature_buffer.Length()? as usize);
    CryptographicBuffer::CopyToByteArray(&signature_buffer, &mut signature_value)?;

    // 5. 派生 256-bit 密钥
    let key = Sha256::digest(signature_value.as_ref());

    Ok(SecretBox::new(Box::new(key.to_vec())))
}
