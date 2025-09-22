use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use std::{
    fs,
    path::{self, Path},
};

use anyhow::{Context, Result, anyhow};

use ed25519_dalek::{SigningKey, VerifyingKey};

use ssh_key::PrivateKey;
use tracing::{debug, error};

use zeroize::Zeroizing;

pub struct OpenMlsKeyPackage {
    // client_identity: Vec<u8>, // Public key loaded from SSH ED25519 format

    // ... and the crypto provider to use.
    provider: OpenMlsRustCrypto,
}

impl OpenMlsKeyPackage {
    fn load_ssh_ed25519_key(path: &Path) -> Result<(SigningKey, VerifyingKey)> {
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
                // make sure ssh-key = { version = "0.6.7", features = ["ed25519", "encryption"] }
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

    /// Creates and stores OpenMLS credentials from an OpenSSH ED25519 private key file.
    ///
    /// This function loads an SSH ED25519 private key from the specified path, extracts the
    /// cryptographic material, and creates the necessary OpenMLS credential structures.
    /// The resulting credential and signature key pair are essential for establishing
    /// authenticated MLS (Messaging Layer Security) sessions.
    ///
    /// # Parameters
    ///
    /// * `ciphersuite` - The cryptographic ciphersuite to use for the MLS operations.
    ///   This determines the signature algorithm and other cryptographic parameters.
    /// * `path` - Path to the SSH ED25519 private key file in OpenSSH format.
    ///   The key may be encrypted with a passphrase, which will be prompted for interactively.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing:
    /// * `CredentialWithKey` - The MLS credential containing the public key for identity verification
    /// * `SignatureKeyPair` - The signature key pair used for signing MLS messages
    ///
    /// # Behavior
    ///
    /// 1. **Key Loading**: Reads and parses the SSH private key file using the `ssh-key` crate
    /// 2. **Decryption**: If the key is encrypted, prompts for passphrase and decrypts it securely
    /// 3. **Key Validation**: Ensures the key is an ED25519 key (other key types are not supported)
    /// 4. **Credential Creation**: Creates a `BasicCredential` from the public key bytes
    /// 5. **Signature Setup**: Generates a new `SignatureKeyPair` using the ciphersuite's signature algorithm
    /// 6. **Storage**: Stores the signature key in the provider's key store for OpenMLS access
    ///
    /// # Security Considerations
    ///
    /// * Passphrases are handled using the `zeroize` crate to ensure secure memory cleanup
    /// * Private key material is never exposed in logs or error messages
    /// * The function uses secure random number generation for key pair creation
    /// * All sensitive operations follow cryptographic best practices
    ///
    /// # Error Handling
    ///
    /// The function will exit the process with code 1 if:
    /// * The SSH key file cannot be read
    /// * The key file is corrupted or invalid
    /// * The key is not an ED25519 key
    /// * The key decryption fails (wrong passphrase)
    ///
    /// Other OpenMLS-related errors are returned as `anyhow::Result` for caller handling.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut key_package = OpenMlsKeyPackage { provider: OpenMlsRustCrypto::default() };
    /// let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    /// let path = Path::new("/path/to/ssh/key");
    ///
    /// let (credential, signer) = key_package.create_openmls_credential_from_openssh_key(ciphersuite, path)?;
    /// // Use credential and signer for MLS operations
    /// ```
    fn create_openmls_credential_from_openssh_key(
        &mut self,
        ciphersuite: Ciphersuite,
        path: &Path, // Path to the SSH ED25519 private key
                     // signature_algorithm: SignatureScheme,
                     // provider: &impl OpenMlsProvider,
    ) -> anyhow::Result<(CredentialWithKey, SignatureKeyPair)> {
        debug!("Loading SSH Ed25519 key from {}", path.display());
        let (signing_key, verifying_key) = match Self::load_ssh_ed25519_key(path) {
            Ok((sk, vk)) => (sk, vk),
            Err(e) => {
                error!(
                    "Error loading SSH Ed25519 key from {}: {}",
                    path.display(),
                    e
                );
                std::process::exit(1);
            }
        };

        // Convert the ed25519_dalek::VerifyingKey to bytes
        let public_key_bytes = verifying_key.to_bytes().to_vec();

        // Convert the ed25519_dalek::SigningKey to bytes
        // let private_key_bytes = signing_key.to_bytes().to_vec();

        let signature_scheme = ciphersuite.signature_algorithm();

        // Create an OpenMLS Identity from the public key bytes
        // let openmls_signature_keypair = SignatureKeyPair::from_raw(signature_scheme, private_key_bytes, public_key_bytes);

        let credential = BasicCredential::new(public_key_bytes);
        let signature_keys = SignatureKeyPair::new(signature_scheme)
            .expect("Error generating a signature key pair.");

        // Store the signature key into the key store so OpenMLS has access to it
        signature_keys.store(self.provider.storage())?;

        Ok((
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keys.public().into(),
            },
            signature_keys,
        ))
    }

    pub fn create_key_package_bundle(&mut self, path: &Path) -> anyhow::Result<KeyPackageBundle> {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

        let (credential_with_key, signer) =
            self.create_openmls_credential_from_openssh_key(ciphersuite, path)?;

        KeyPackage::builder()
            .build(ciphersuite, &self.provider, &signer, credential_with_key)
            .map_err(|e| anyhow!("Error creating KeyPackageBundle: {}", e))
    }

    pub fn new() -> Self {
        OpenMlsKeyPackage {
            provider: OpenMlsRustCrypto::default(),
        }
    }
}
