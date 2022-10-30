use std::num::NonZeroU32;

static PBKDF2_ALG: ring::pbkdf2::Algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA256;

pub struct StretchedMasterKey {
    pub enc_key: [u8; 32],
    pub mac: [u8; 32],
}

impl StretchedMasterKey {
    pub fn new(enc_key: [u8; 32], mac: [u8; 32]) -> Self {
        Self { enc_key, mac }
    }

    pub fn from_creds(email: &str, password: &str) -> Self {
        // Create 256 bit Master Key by using PBKDF2-SHA256 with 100,000 iterations
        let mut master_key = [0u8; 32];
        ring::pbkdf2::derive(
            PBKDF2_ALG,
            NonZeroU32::new(100_000).unwrap(),
            email.as_bytes(),
            password.as_bytes(),
            &mut master_key,
        );

        // Create new HKDF Prk with existing MasterKey
        let hkdf = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, &master_key);

        // Use HDKF to build key
        let mut enc_key = [0u8; 32];
        hkdf.expand(&[b"enc"], ring::hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut enc_key)
            .unwrap();

        // Use HKDF to build mac
        let mut mac = [0u8; 32];
        hkdf.expand(&[b"mac"], ring::hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut mac)
            .unwrap();

        Self { enc_key, mac }
    }

    pub fn enc_key_mut(&mut self) -> &mut [u8] {
        self.enc_key.as_mut()
    }

    pub fn mac_mut(&mut self) -> &mut [u8] {
        self.mac.as_mut()
    }
}
