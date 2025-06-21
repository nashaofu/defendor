use crate::{
    DefendorError, DefendorResult,
    defendor::{NONCE_LENGTH, VERSION_LENGTH},
};

pub struct Data {
    pub version: u16,
    pub nonce: Vec<u8>,
    pub encrypted: Vec<u8>,
}

impl Data {
    pub fn new(version: u16, nonce: Vec<u8>, encrypted: Vec<u8>) -> Self {
        Self {
            version,
            nonce,
            encrypted,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(VERSION_LENGTH + NONCE_LENGTH + self.encrypted.len());
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&self.nonce);
        buffer.extend_from_slice(&self.encrypted);

        buffer
    }
    pub fn from_bytes(buffer: &[u8]) -> DefendorResult<Self> {
        if buffer.len() < VERSION_LENGTH + NONCE_LENGTH {
            return Err(DefendorError::InvalidEncryptedData);
        }

        let version_bytes = &buffer[..VERSION_LENGTH];
        let nonce_bytes = &buffer[VERSION_LENGTH..VERSION_LENGTH + NONCE_LENGTH];
        let encrypted_bytes = &buffer[VERSION_LENGTH + NONCE_LENGTH..];

        let version = u16::from_le_bytes(
            version_bytes
                .try_into()
                .map_err(|_| DefendorError::InvalidEncryptedData)?,
        );

        Ok(Self {
            version,
            nonce: nonce_bytes.to_vec(),
            encrypted: encrypted_bytes.to_vec(),
        })
    }
}
