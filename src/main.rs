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
        let decrypted_string = DecryptedString {
            data: args.input.as_bytes().to_vec(),
        };

        let encrypted_string = decrypted_string.to_encrypted_string(symmetric_key);

        println!("{}", encrypted_string);
    } else {
        let encrypted_string = EncryptedString::from_encrypted_string(args.input.as_str());

        let decrypted_string = encrypted_string.to_decrypted_string(symmetric_key);

        println!("{}", decrypted_string);
    }
}
