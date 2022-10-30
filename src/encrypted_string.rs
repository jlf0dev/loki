use std::{fmt, str};

use crate::cipher_string::{Decrypt, Encrypt};
use crate::decrypted_string::DecryptedString;
use crate::symmetric_key::SymmetricKey;

pub struct EncryptedString {
    pub iv: Vec<u8>,
    pub enc_data: Vec<u8>,
    pub mac: Vec<u8>,
}

impl Encrypt for EncryptedString {}
impl Decrypt for EncryptedString {}

impl fmt::Display for EncryptedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let iv = base64::encode(self.iv.as_slice());
        let data = base64::encode(self.enc_data.as_slice());
        let mac = base64::encode(self.mac.as_slice());

        write!(f, "2.{}|{}|{}", iv, data, mac)
    }
}

impl EncryptedString {
    pub fn from_encrypted_string(s: &str) -> Self {
        Self::parse_encrypted_string(s)
    }

    pub fn to_decrypted_string(self, encryption_key: SymmetricKey) -> DecryptedString {
        Self::decrypt(self, &encryption_key.key, &encryption_key.mac)
    }
}
