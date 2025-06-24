# Defendor

Defendor 是一个基于 Rust 的安全密钥封装与加密库，支持异步操作，适用于本地密钥管理、加密存储等场景。

## 特性

- 使用 AES-256-GCM 算法进行数据加密
- 密钥派生采用 Argon2id 算法，支持自定义密码
- 支持密钥轮换（rotate_key）
- 所有敏感数据均用 Zeroizing/SecretBox 包裹，防止内存残留
- 支持异步文件操作
- encrypt/decrypt API 自动管理 nonce 和密文格式，安全易用

## 快速开始

### 依赖

```toml
[dependencies]
defendor = "*"
tokio = { version = "1", features = ["full"] }
zeroize = "1"
base64ct = "1"
```

### 示例

```rust
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

    // 加密数据（自动生成 nonce 并封装格式）
    let encrypted = defendor
        .encrypt(b"Hello, world!")
        .expect("Failed to encrypt data");
    println!("Encrypted data: {}", Base64::encode_string(&encrypted));

    // 密钥轮换
    defendor
        .rotate_key("password456".as_bytes().to_vec())
        .await
        .expect("Failed to rotate key");
    println!("Key rotated successfully");

    // 解密
    let decrypted = defendor
        .decrypt(&encrypted)
        .expect("Failed to decrypt data after key rotation");
    println!(
        "Decrypted data after key rotation: {}",
        String::from_utf8(decrypted).expect("Failed to convert to string")
    );

    // 重新加载
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
        "Decrypted data after re new Defendor: {}",
        String::from_utf8(decrypted).expect("Failed to convert to string")
    );

    fs::remove_file("target/vault")
        .await
        .expect("Failed to remove vault file");
}
```

## API 说明

- `Defendor::new(path, password)`：初始化或加载密钥库
- `Defendor::init(path, password)`：初始化密钥库
- `Defendor::load(path, password)`：加载密钥库
- `Defendor::encrypt(data)`：加密数据，自动生成 nonce 并封装格式，推荐使用
- `Defendor::decrypt(data)`：解密数据，自动解析格式，推荐使用
- `Defendor::change_password(new_password)`：更换解锁密码
- `Defendor::rotate_key(new_password)`：轮换密钥
- `Defendor::random(size)`：生成安全随机字节

## 安全建议

- 推荐使用 `encrypt`/`decrypt`，避免 nonce 重用风险
- 每次加密都应生成全新 nonce，且与密文一同保存（API 已自动处理）
- 密钥轮换后历史密文仍可解密，如需彻底轮换请重新加密历史数据
- 生产环境请妥善管理密码与密钥文件权限

## License

Apache-2.0
