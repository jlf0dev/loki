use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;

use crate::decrypted_string::DecryptedString;
use crate::encrypted_string::EncryptedString;
use crate::symmetric_key::SymmetricKey;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

pub trait Decrypt {
    fn decrypt(
        mut encrypted_string: EncryptedString,
        encryption_key: &[u8],
        mac: &[u8],
    ) -> DecryptedString {
        // Create HMAC key
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, mac);
        // Combine IV and Data
        let data: Vec<_> = encrypted_string
            .iv
            .iter()
            .chain(encrypted_string.enc_data.iter())
            .copied()
            .collect();

        // Verify HMAC
        if ring::hmac::verify(&key, &data, encrypted_string.mac.as_slice()).is_err() {
            panic!("Invalid MAC on encrypted string")
        }

        // Decrypt encrypted data
        let data = Aes256CbcDec::new(encryption_key.into(), encrypted_string.iv.as_slice().into())
            .decrypt_padded_mut::<Pkcs7>(encrypted_string.enc_data.as_mut_slice())
            .unwrap()
            .to_vec();

        DecryptedString { data }
    }
}

pub trait Encrypt {
    fn encrypt(decrypted_string: DecryptedString, encryption_key: SymmetricKey) -> EncryptedString {
        // Generate IV
        let iv = random_iv();

        let mut buf = [0u8; 48];
        let enc_data =
            Aes256CbcEnc::new(encryption_key.key.as_slice().into(), iv.as_slice().into())
                .encrypt_padded_b2b_mut::<Pkcs7>(&decrypted_string.data, &mut buf)
                .unwrap();

        let mut digest = ring::hmac::Context::with_key(&ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &encryption_key.mac.as_slice(),
        ));
        digest.update(&iv);
        digest.update(enc_data);
        let mac = digest.sign();

        let enc_data = enc_data.to_vec();
        let mac = mac.as_ref().to_vec();

        EncryptedString { iv, enc_data, mac }
    }

    fn parse_encrypted_string(s: &str) -> EncryptedString {
        // Parse string
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            panic!("Invalid encrypted string")
        }

        let ty = parts[0].as_bytes();
        if ty.len() != 1 {
            panic!("Invalid encrypted string")
        }

        let ty = ty[0] - b'0';
        let contents = parts[1];

        if ty != 2 {
            panic!("Unsupported encrypted string type")
        }

        let parts: Vec<&str> = contents.split('|').collect();
        if parts.len() != 3 {
            panic!("Unsupported encrypted string type")
        }

        let iv = base64::decode(parts[0]).expect("Encrypted string mut have IV");
        let enc_data = base64::decode(parts[1]).expect("Encrypted string must have data");
        let mac = base64::decode(parts[2]).expect("Encrypted string must have MAC");

        EncryptedString { iv, enc_data, mac }
    }
}

fn random_iv() -> Vec<u8> {
    let mut iv = vec![0_u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    iv
}
