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

    let encrypted = defendor
        .encrypt(b"Hello, world!")
        .expect("Failed to encrypt data");

    println!("Encrypted data: {:?}", Base64::encode_string(&encrypted));

    change_password(&mut defendor, &encrypted).await;

    let mut defendor = re_init(&encrypted).await;

    rotate_key(&mut defendor, b"Hello, world!").await;

    fs::remove_file("target/vault")
        .await
        .expect("Failed to remove vault file");
}

async fn change_password(defendor: &mut Defendor, encrypted: &[u8]) {
    defendor
        .change_password("password456".as_bytes().to_vec())
        .await
        .expect("Failed to rotate key");

    println!("Key rotated successfully");

    let decrypted = defendor
        .decrypt(&encrypted)
        .expect("Failed to decrypt data after change password");

    println!(
        "Decrypted data after change password: {:?}",
        String::from_utf8(decrypted).expect("Failed to convert to string")
    );
}

async fn re_init(encrypted: &[u8]) -> Defendor {
    let defendor = Defendor::new(
        "target/vault",
        Zeroizing::new(String::from("password456").into()),
    )
    .await
    .expect("Failed to initialize Defendor");

    let decrypted = defendor
        .decrypt(&encrypted)
        .expect("Failed to decrypt data after key rotation");

    println!(
        "Decrypted data after re new Defendor: {:?}",
        String::from_utf8(decrypted).expect("Failed to convert to string")
    );

    defendor
}

async fn rotate_key(defendor: &mut Defendor, data: &[u8]) {
    defendor
        .rotate_key("password456".as_bytes().to_vec())
        .await
        .unwrap();

    let encrypt = defendor
        .encrypt(data)
        .expect("Failed to re-encrypt data after key rotation");

    println!(
        "Re-encrypted data after key rotation: {:?}",
        Base64::encode_string(&encrypt)
    );

    let decrypted = defendor.decrypt(&encrypt).unwrap();

    println!(
        "Decrypted data after key rotation: {:?}",
        String::from_utf8(decrypted).expect("Failed to convert to string")
    );
}
