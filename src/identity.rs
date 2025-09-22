use openmls::{
    ciphersuite,
    prelude::{tls_codec::*, *},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use std::{fs, path::Path};

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

    // A helper to create and store credentials.
    fn create_openmls_credential_from_openssh_key(
        &mut self,
        ciphersuite: Ciphersuite,
        path: &Path, // Path to the SSH ED25519 private key
                     // signature_algorithm: SignatureScheme,
                     // provider: &impl OpenMlsProvider,
    ) -> anyhow::Result<(CredentialWithKey, SignatureKeyPair)> {
        // hardcoded to ensure compatibility with OpenSSH ED25519 keys
        // let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        // ... and the crypto provider to use.

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

    pub fn new(
        &self,
        ciphersuite: Ciphersuite,
        // provider: &impl OpenMlsProvider,
        // signer: &SignatureKeyPair,
        // credential_with_key: CredentialWithKey,
        path: &Path,
    ) -> anyhow::Result<KeyPackageBundle> {
        // let provider = &OpenMlsRustCrypto::default();

        // First, we get the credential with key and the signature keypair from the SSH ED25519 key
        let (credential_with_key, signer) =
            Self::create_openmls_credential_from_openssh_key(ciphersuite, path)?;

        // Create the key package
        match KeyPackage::builder().build(ciphersuite, &self.provider, &signer, credential_with_key)
        {
            Ok(kpb) => Ok(kpb),
            Err(e) => Err(anyhow!("Error creating KeyPackageBundle: {}", e)),
        }
    }
}
