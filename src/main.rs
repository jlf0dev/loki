use clap::Parser;

use decrypted_string::DecryptedString;
use encrypted_string::EncryptedString;
use stretched_master_key::StretchedMasterKey;
use symmetric_key::SymmetricKey;

mod cipher_string;
mod decrypted_string;
mod encrypted_string;
mod stretched_master_key;
mod symmetric_key;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Encrypt option, ignore to decrypt
    #[arg(long)]
    encrypt: bool,
    /// Bitwarden email, used to generate Master Key
    #[arg(short, long)]
    email: String,
    /// Bitwarden password, used to generate Master Key
    #[arg(short, long)]
    password: String,
    /// Protected Symmetric Key saved in Bitwarden database
    #[arg(short, long)]
    key: String,
    /// Data to encrypt/decrypt
    #[arg(short, long)]
    input: String,
}

fn main() {
    let args = Args::parse();

    let master_key = StretchedMasterKey::from_creds(&args.email, &args.password);
    let symmetric_key = SymmetricKey::from_encrypted_string(args.key.as_str(), master_key);

    if args.encrypt {
        println!(
            "{}",
            DecryptedString::from_string(args.input.as_str()).to_encrypted_string(symmetric_key)
        );
    } else {
        println!(
            "{}",
            EncryptedString::from_encrypted_string(args.input.as_str())
                .to_decrypted_string(symmetric_key)
        );
    }
}
