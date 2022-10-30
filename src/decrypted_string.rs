use std::{fmt, str};

use crate::cipher_string::Encrypt;
use crate::encrypted_string::EncryptedString;
use crate::symmetric_key::SymmetricKey;

pub struct DecryptedString {
    pub data: Vec<u8>,
}

impl DecryptedString {
    pub fn from_string(s: &str) -> Self {
        DecryptedString {
            data: s.as_bytes().to_vec(),
        }
    }
    pub fn to_encrypted_string(self, encryption_key: SymmetricKey) -> EncryptedString {
        Self::encrypt(self, encryption_key)
    }
}

impl Encrypt for DecryptedString {}

impl fmt::Display for DecryptedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", str::from_utf8(self.data.as_slice()).unwrap())
    }
}
