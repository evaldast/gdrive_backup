use aes_gcm::{
    aead::{AeadCore, KeyInit, OsRng},
    AeadInPlace, Aes256Gcm, Key,
};
use base64::Engine;
use std::str;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Failed to base64 decode encryption key")]
    DecodeEncryptionKey(#[from] base64::DecodeError),

    #[error("Failed to create AES key")]
    CreateAesKey(aes_gcm::Error),
}

impl From<aes_gcm::Error> for CryptoError {
    fn from(err: aes_gcm::Error) -> Self {
        CryptoError::CreateAesKey(err)
    }
}


pub struct Crypto {
    encryption_key_bytes: Vec<u8>
}

impl Crypto {
    pub fn new(encryption_key: &str) -> Result<Self, CryptoError> {
        let encryption_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(encryption_key)?;

        Ok(Crypto {
            encryption_key_bytes
        })
    }

    pub fn encrypt_in_place(&self, data: &mut Vec<u8>) -> Result<(), CryptoError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
        let tag = cipher.encrypt_in_place_detached(&nonce, &[], data)?;
    
        data.splice(0..0, nonce);
        data.splice(0..0, tag);
    
        Ok(())
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key_bytes);
        let cipher = Aes256Gcm::new(key);
    
        let tag_length = 16;
        let nonce_length = 12;
        let (tag_and_nonce, ciphertext) = data.split_at(tag_length + nonce_length);
        let (tag, nonce) = tag_and_nonce.split_at(tag_length);
    
        let mut decrypted_data = Vec::from(ciphertext);
    
        cipher.decrypt_in_place_detached(nonce.into(), &[], &mut decrypted_data, tag.into())?;
    
        Ok(decrypted_data)
    }
}