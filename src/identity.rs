use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Digest;
use ssh_key::PrivateKey;
use tracing::{debug, error};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;


pub struct Identity {
    client_identity: Vec<u8>, // Public key loaded from SSH ED25519 format
}

impl Identity {
    fn load_ssh_ed25519_key(path: &Path) -> anyhow::Result<(SigningKey, VerifyingKey)> {
        // Read the SSH private key file
        let key_data = fs::read_to_string(path)
            .with_context(|| format!("Failed to read file {}", path.display()))?;

        // Parse it
        let ssh_private_key = PrivateKey::from_openssh(&key_data)?;

        // Ensure the key is not encrypted
        let ssh_private_key_decrypted = if ssh_private_key.is_encrypted() {
            eprint!("SSH key is encrypted; please provide the password:");
            let passphrase = rpassword::read_password()?;

            // This line creates a secure wrapper around sensitive data (a passphrase)
            // that automatically wipes the memory when it goes out of scope.
            // The code is decrypting an encrypted SSH private key,
            // so the passphrase contains sensitive cryptographic material that must not be left in memory after use.
            //
            // What it does:
            //  1. Takes the passphrase string read from terminal input
            //  2. Wraps it in a Zeroizing<String> type from the zeroize crate
            //  3. When pass_z is dropped (goes out of scope), the memory containing the passphrase is automatically overwritten with zeros
            let pass_z = Zeroizing::new(passphrase);

            ssh_private_key
                .decrypt(&pass_z)
                .context("Failed to decrypt SSH private key (wrong passphrase?)")?
        } else {
            ssh_private_key
        };
        // Extract the raw Ed25519 key bytes
        let key_bytes = ssh_private_key_decrypted
            .key_data()
            .ed25519()
            .context("SSH key is not Ed25519")?;

        let signing_key = SigningKey::from_bytes(&key_bytes.private.to_bytes());

        // This is the same as PublicKey::from(&signing_key);
        // VerifyingKey is the public key counterpart to SigningKey.
        let verifying_key = signing_key.verifying_key();

        Ok((signing_key, verifying_key))
    }
}
