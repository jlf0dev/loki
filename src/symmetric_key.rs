use crate::cipher_string::{Decrypt, Encrypt};
use crate::stretched_master_key::StretchedMasterKey;

pub struct SymmetricKey {
    pub key: Vec<u8>,
    pub mac: Vec<u8>,
}
impl Encrypt for SymmetricKey {}
impl Decrypt for SymmetricKey {}

impl SymmetricKey {
    pub fn from_encrypted_string(s: &str, key: StretchedMasterKey) -> Self {
        let encrypted = Self::parse_encrypted_string(s);
        let decrypted = Self::decrypt(encrypted, &key.enc_key, &key.mac);
        Self {
            key: decrypted.data[..32].to_vec(),
            mac: decrypted.data[32..].to_vec(),
        }
    }
}
