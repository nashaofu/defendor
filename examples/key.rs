use defendor::{biometric::Biometric, defendor::Defendor, password::Password, store::Store};
use std::{collections::HashMap, ops::Deref, sync::Arc};
use tokio::{fs, sync::RwLock};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
struct Config {
    store: Arc<RwLock<HashMap<String, String>>>,
}

impl Config {
    fn new(store: HashMap<String, String>) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
        }
    }
}

impl Store for Config {
    async fn get(&self, key: &str) -> Option<String> {
        let g = self.store.read().await;
        let s = g.get(key);
        s.map(|s| s.to_string())
    }

    async fn set(&mut self, key: &str, val: &str) {
        self.store.write().await.insert(key.into(), val.into());
    }

    async fn delete(&mut self, key: &str) {
        self.store.write().await.remove(key);
    }
}

// cargo run --example key --features biometric
#[tokio::main]
async fn main() {
    let p = "target/store.json";
    if !fs::try_exists(p).await.unwrap() {
        fs::write(p, "{}").await.unwrap();
    }
    let s = fs::read_to_string(p).await.unwrap();
    let store: HashMap<String, String> = serde_json::from_str(&s).unwrap();

    let config = Config::new(store);
    let mut defendor = Defendor::with_store(config.clone());

    if defendor.is_init().await {
        println!("defendor is init");

        defendor
            .load_by_password(Zeroizing::new(String::from("password123").into()))
            .await
            .unwrap()
            .load_by_biometric("test")
            .await
            .unwrap();
    } else {
        println!("defendor not init");

        defendor
            .init_key()
            .await
            .unwrap()
            .init_password(Zeroizing::new(String::from("password123").into()))
            .await
            .unwrap()
            .init_biometric("test")
            .await
            .unwrap();

        let s = config.store.read().await;
        let store = s.deref();
        fs::write(p, serde_json::to_string_pretty(store).unwrap())
            .await
            .unwrap();
    }

    let s = defendor.encrypt(b"data").await.unwrap();

    println!("s {s:?}");
    let d = defendor.decrypt(&s).await.unwrap();
    println!("d {}", String::from_utf8_lossy(&d));
    // println!("{defendor:?}");
}
