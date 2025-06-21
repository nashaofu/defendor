use base64ct::{Base64, Encoding};
use defendor::Defendor;
use tokio::fs;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() {
    fs::create_dir_all("target").await.unwrap();
    let mut defendor = Defendor::new(
        "target/vault",
        Zeroizing::new(String::from("password123").into()),
    )
    .await
    .expect("Failed to initialize Defendor");

    let nonce = Defendor::random(12).expect("Failed to generate nonce");

    let encrypted = defendor
        .encrypt(b"Hello, world!", &nonce)
        .expect("Failed to encrypt data");

    println!("Encrypted data: {:?}", Base64::encode_string(&encrypted));

    defendor
        .rotate_key("password456".as_bytes().to_vec())
        .await
        .expect("Failed to rotate key");

    println!("Key rotated successfully");

    let decrypted = defendor
        .decrypt(&encrypted, &nonce)
        .expect("Failed to decrypt data after key rotation");

    println!(
        "Decrypted data after key rotation: {:?}",
        String::from_utf8(decrypted).expect("Failed to convert to string")
    );

    let defendor = Defendor::new(
        "target/vault",
        Zeroizing::new(String::from("password456").into()),
    )
    .await
    .expect("Failed to initialize Defendor");

    let decrypted = defendor
        .decrypt(&encrypted, &nonce)
        .expect("Failed to decrypt data after key rotation");

    println!(
        "Decrypted data after re new Defendor: {:?}",
        String::from_utf8(decrypted).expect("Failed to convert to string")
    );

    // fs::remove_file("target/vault")
    //     .await
    //     .expect("Failed to remove vault file");
}
