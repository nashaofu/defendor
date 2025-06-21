use base64ct::{Base64, Encoding};
use defendor::Defendor;
use tokio::fs;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    fs::create_dir_all(".temp").await.unwrap();
    let c = Defendor::new(
        "target/vault",
        Zeroizing::new(String::from("password123").into()),
    )
    .await
    .expect("Failed to initialize Defendor");

    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("Failed to fill nonce");

    let data = c.encrypt(b"data", &nonce).expect("Failed to encrypt data");

    println!("Encrypted data: {:?}", Base64::encode_string(&data));

    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).expect("Failed to fill nonce");
    let data = c.encrypt(b"data", &nonce).expect("Failed to encrypt data");

    println!("Encrypted data: {:?}", Base64::encode_string(&data));
}
