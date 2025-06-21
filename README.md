# Defendor

Defendor 是一个基于 Rust 的安全密钥封装与加密库，支持异步操作，适用于本地密钥管理、加密存储等场景。

## 特性

- 使用 AES-256-GCM 算法进行数据加密
- 密钥派生采用 Argon2id 算法，支持自定义密码
- 支持密钥轮换（rotate key）
- 所有敏感数据均用 Zeroizing/SecretBox 包裹，防止内存残留
- 支持异步文件操作

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
use defendor::Defendor;
use zeroize::Zeroizing;
use base64ct::{Base64, Encoding};
use tokio::fs;

#[tokio::main]
async fn main() {
    let mut defendor = Defendor::new(
        "target/vault",
        Zeroizing::new("password123".as_bytes().to_vec()),
    ).await.expect("Failed to initialize Defendor");

    let nonce = Defendor::random(12).unwrap();
    let encrypted = defendor.encrypt(b"Hello, world!", &nonce).unwrap();
    println!("Encrypted: {}", Base64::encode_string(&encrypted));

    // 密钥轮换
    defendor.rotate_key("newpassword".as_bytes().to_vec()).await.unwrap();
    println!("Key rotated");

    let decrypted = defendor.decrypt(&encrypted, &nonce).unwrap();
    println!("Decrypted: {}", String::from_utf8(decrypted).unwrap());
}
```

## API 说明

- `Defendor::new(path, password)`：初始化或加载密钥库
- `Defendor::init(path, password)`：初始化密钥库
- `Defendor::load(path, password)`：加载密钥库
- `Defendor::encrypt(data, nonce)`：加密数据
- `Defendor::decrypt(data, nonce)`：解密数据
- `Defendor::rotate_key(new_password)`：轮换密钥（更换解锁密码）
- `Defendor::random(size)`：生成安全随机字节

## 安全建议

- 每次加密都应生成全新 nonce，且与密文一同保存
- 密钥轮换后历史密文仍可解密，如需彻底轮换请重新加密历史数据
- 生产环境请妥善管理密码与密钥文件权限

## License

Apache-2.0 license
