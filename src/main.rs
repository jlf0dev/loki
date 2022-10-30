use aes::cipher::{
    block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use ring::{
    hkdf::{self, HKDF_SHA512},
    hmac,
};

use clap::Parser;

use crate::{
    encrypted_string::{DecryptedString, EncryptedString, SymmetricKey},
    stretched_master_key::StretchedMasterKey,
};

mod encrypted_string;
mod stretched_master_key;

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

fn main() {
    let args = Args::parse();

    let master_key = StretchedMasterKey::from_creds(&args.email, &args.password);

    let symmetric_key = SymmetricKey::from_encrypted_string(args.key.as_str(), master_key);

    let decrypted_string = DecryptedString {
        data: args.value.as_bytes().to_vec(),
    };

    let encrypted_string = decrypted_string.to_encrypted_string(symmetric_key);

    println!("{}", encrypted_string);
}
