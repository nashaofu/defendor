use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct KeyStore {
    pub salt: String,
    pub encrypted_key: String,
}

impl Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("salt", &"[REDACTED]")
            .field("encrypted_key", &"[REDACTED]")
            .finish()
    }
}

impl KeyStore {
    pub fn new(salt: String, encrypted_key: String) -> Self {
        KeyStore {
            salt,
            encrypted_key,
        }
    }
}
