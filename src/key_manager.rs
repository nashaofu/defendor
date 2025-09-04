use secrecy::SecretBox;

pub trait KeyManager {
    type KeyManagerError;
    fn set_key(
        &mut self,
        val: SecretBox<Vec<u8>>,
    ) -> impl Future<Output = Result<(), Self::KeyManagerError>>;
    fn get_key(&self) -> impl Future<Output = Result<SecretBox<Vec<u8>>, Self::KeyManagerError>>;
}
