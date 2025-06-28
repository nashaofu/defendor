use thiserror::Error;

#[derive(Debug, Error)]
pub enum DefendorError {
    #[error(transparent)]
    GetrandomError(#[from] getrandom::Error),

    #[error(transparent)]
    Argon2Error(#[from] argon2::Error),

    #[error(transparent)]
    AesGcmError(#[from] aes_gcm::Error),

    #[error(transparent)]
    StdIoError(#[from] std::io::Error),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    #[error(transparent)]
    Base64ctError(#[from] base64ct::Error),

    #[error("Vault file already exists")]
    VaultFileExists,

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid encrypted data")]
    InvalidEncryptedData,
}

pub type DefendorResult<T> = Result<T, DefendorError>;
