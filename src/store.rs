pub trait Store: Send + Sync {
    fn get(&self, key: &str) -> impl Future<Output = Option<String>>;
    fn set(&mut self, key: &str, value: &str) -> impl Future<Output = ()>;
    fn delete(&mut self, key: &str) -> impl Future<Output = ()>;
}
