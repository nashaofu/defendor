#[cfg(feature = "biometric")]
pub mod biometric;
pub mod data;
pub mod defendor;
pub mod error;
pub mod key_manager;
pub mod password;
pub mod store;
pub mod utils;

// 12 bytes for nonce
pub const NONCE_LENGTH: usize = 12;
// 32 bytes for AES-256
pub const KEY_LENGTH: usize = 32;
// 2 bytes for VERSION
pub const VERSION_LENGTH: usize = 2;
