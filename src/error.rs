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

    #[error("Invalid key length")]
    InvalidKeyLength,
}

pub type DefendorResult<T> = Result<T, DefendorError>;
