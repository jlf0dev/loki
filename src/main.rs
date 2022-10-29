use aes::cipher::{
    block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use ring::{
    hkdf::{self, HKDF_SHA512},
    hmac,
};
use std::num::NonZeroU32;

use clap::Parser;

static PBKDF2_ALG: ring::pbkdf2::Algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA256;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    email: String,
    #[arg(short, long)]
    password: String,
    /// Protected Symmetric Key saved in Bitwarden database
    #[arg(short, long)]
    key: String,
    // String to encrypt
    #[arg(short, long)]
    value: String,
}

pub struct StretchedMasterKey {
    key: [u8; 64],
}

impl StretchedMasterKey {
    pub fn new(key: [u8; 64]) -> Self {
        Self { key }
    }

    pub fn enc_key_mut(&mut self) -> &mut [u8] {
        self.key[..32].as_mut()
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.key[..32]
    }

    pub fn mac_key_mut(&mut self) -> &mut [u8] {
        self.key[32..].as_mut()
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.key[32..]
    }
}

struct SymmetricKey {
    iv: Vec<u8>,
    data: Vec<u8>,
    mac: Vec<u8>,
}

impl SymmetricKey {
    fn from_protected_symmetric_key(s: &str) -> Result<Self, &'static str> {
        let parts: Vec<&str> = s.split('.').collect();
        // if parts.len() != 2 {
        //     return Err(Error::InvalidCipherString {
        //         reason: "couldn't find type".to_string(),
        //     });
        // }

        let ty = parts[0].as_bytes();
        // if ty.len() != 1 {
        //     return Err(Error::UnimplementedCipherStringType {
        //         ty: parts[0].to_string(),
        //     });
        // }

        let ty = ty[0] - b'0';
        let contents = parts[1];

        if ty == 2 {
            let parts: Vec<&str> = contents.split('|').collect();
            // if parts.len() < 2 || parts.len() > 3 {
            //     return Err(Error::InvalidCipherString {
            //         reason: format!(
            //             "type 2 cipherstring with {} parts",
            //             parts.len()
            //         ),
            //     });
            // }

            let iv = base64::decode(parts[0]).unwrap();
            let data = base64::decode(parts[1]).unwrap();
            let mac = base64::decode(parts[2]).unwrap();

            return Ok(Self { iv, data, mac });
        }
        Err("none")
    }
}

fn main() {
    let args = Args::parse();

    println!("Email: {:?}", args.email);
    println!("Password: {:?}", args.password);

    let mut master_key = [0u8; 32];
    ring::pbkdf2::derive(
        PBKDF2_ALG,
        NonZeroU32::new(100_000).unwrap(),
        args.email.as_bytes(),
        args.password.as_bytes(),
        &mut master_key,
    );
    println!("Master Key: {}", base64::encode(master_key));

    let mut stretched_master_key = StretchedMasterKey::new([0u8; 64]);
    let hkdf = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, &master_key);
    hkdf.expand(&[b"enc"], ring::hkdf::HKDF_SHA256)
        .unwrap()
        .fill(stretched_master_key.enc_key_mut())
        .unwrap();

    hkdf.expand(&[b"mac"], ring::hkdf::HKDF_SHA256)
        .unwrap()
        .fill(stretched_master_key.mac_key_mut())
        .unwrap();
    println!(
        "Stretched Master Key: {}",
        base64::encode(stretched_master_key.key)
    );

    let mut protected_symm_key =
        SymmetricKey::from_protected_symmetric_key(args.key.as_str()).unwrap();

    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, stretched_master_key.mac_key_mut());
    let data: Vec<_> = protected_symm_key
        .iv
        .iter()
        .chain(protected_symm_key.data.iter())
        .copied()
        .collect();

    if ring::hmac::verify(&key, &data, &protected_symm_key.mac).is_err() {
        panic!("mac doesn't match")
    }

    //     let symmetric_key = block_modes::Cbc::<
    //             aes::Aes256,
    //             block_modes::block_padding::Pkcs7,
    // >::new_var(keys.enc_key(), &self.iv)
    let decrypted_symm_key = Aes256CbcDec::new(
        stretched_master_key.enc_key().into(),
        protected_symm_key.iv.as_slice().into(),
    )
    .decrypt_padded_mut::<Pkcs7>(protected_symm_key.data.as_mut_slice())
    .unwrap();
    println!(
        "Decrypted Symmetric Key: {}",
        base64::encode(decrypted_symm_key)
    );

    let fake_iv = base64::decode("jYvVBvakaKsYJiw0esB26Q==").unwrap();
    let mut buf = [0u8; 48];
    let encrypted_value =
        Aes256CbcEnc::new(decrypted_symm_key[..32].into(), fake_iv.as_slice().into())
            .encrypt_padded_b2b_mut::<Pkcs7>(&args.value.as_bytes(), &mut buf)
            .unwrap();

    let mut digest = ring::hmac::Context::with_key(&ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        &decrypted_symm_key[32..],
    ));
    digest.update(&fake_iv);
    digest.update(encrypted_value);
    let mac = digest.sign();
    println!("Encypted Value: {}", base64::encode(encrypted_value));
    println!("Mac: {}", base64::encode(mac));
}
