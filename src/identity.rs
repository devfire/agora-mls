use std::{fs, path::Path};

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

use ssh_key::PrivateKey;
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct MyIdentity {
    // Our Ed25519 identity (for signatures/verification from the SSH key)
    pub signing_key: SigningKey,     // comes from the SSH private key
    pub verifying_key: VerifyingKey, // VerifyingKey is the public key counterpart to SigningKey

    // User-friendly identifier (not cryptographically significant)
    pub handle: String,
}

impl MyIdentity {
    /// Loads an Ed25519 SSH private key from a file and extracts the signing/verifying key pair.
    ///
    /// Handles both encrypted and unencrypted SSH keys. For encrypted keys, securely prompts
    /// for the passphrase and immediately zeroizes it after use. Only supports Ed25519 keys.
    ///
    /// # Arguments
    /// * `path` - Path to the SSH private key file in OpenSSH format
    ///
    /// # Returns
    /// A tuple containing the `(SigningKey, VerifyingKey)` pair
    ///
    /// # Errors
    /// * If the file cannot be read
    /// * If the key format is invalid or unsupported
    /// * If the key is encrypted but decryption fails
    /// * If the key is not an Ed25519 key
    fn load_ssh_ed25519_key(key_path: &Path) -> Result<(SigningKey, VerifyingKey)> {
        let expanded_path =
            shellexpand::tilde(key_path.to_str().expect("Expected to find the key file"))
                .to_string();
        let key_data = fs::read_to_string(expanded_path)?;

        let ssh_private_key = PrivateKey::from_openssh(&key_data)?;

        let ssh_private_key_decrypted = if ssh_private_key.is_encrypted() {
            eprint!("SSH key is encrypted; please provide the password: ");

            // The most secure approach: never let an unprotected String exist
            let passphrase = {
                let raw_passphrase = rpassword::read_password()?;
                // Immediately move into Zeroizing to minimize exposure window
                Zeroizing::new(raw_passphrase)
            };
            // Note: The raw_passphrase String still existed briefly, but this minimizes the window

            ssh_private_key
                .decrypt(&passphrase)
                .context("Failed to decrypt SSH private key (wrong passphrase?)")?
        } else {
            ssh_private_key
        };

        let key_bytes = ssh_private_key_decrypted
            .key_data()
            .ed25519()
            .context("SSH key is not Ed25519")?;

        let signing_key = SigningKey::from_bytes(&key_bytes.private.to_bytes());
        let verifying_key = signing_key.verifying_key();

        Ok((signing_key, verifying_key))
    }

    pub fn new(key_file_path: &Path, display_name: &str) -> Result<Self> {
        let (signing_key, verifying_key) = Self::load_ssh_ed25519_key(key_file_path)?;

        Ok(MyIdentity {
            signing_key,
            verifying_key,
            handle: display_name.to_string(),
        })
    }
}
