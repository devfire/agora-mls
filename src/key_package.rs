use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use anyhow::{Context, Result};

pub struct OpenMlsKeyPackage {
    // client_identity: Vec<u8>, // Public key loaded from SSH ED25519 format

    // ... and the crypto provider to use.
    pub provider: OpenMlsRustCrypto,
    ciphersuite: Ciphersuite,
    signature_algorithm: SignatureScheme,
}

impl OpenMlsKeyPackage {
    /// Generates a credential with an associated signature key pair.
    ///
    /// Creates a BasicCredential from the provided identity bytes, generates a new
    /// SignatureKeyPair using the configured signature algorithm, and stores the keys
    /// in the crypto provider's key store for OpenMLS access.
    ///
    /// # Arguments
    /// * `identity` - Raw bytes representing the identity for the credential
    ///
    /// # Returns
    /// A tuple containing:
    /// * `CredentialWithKey` - The credential with embedded signature key
    /// * `SignatureKeyPair` - The full key pair for signing operations
    ///
    /// # Panics
    /// Panics if signature key generation or key store storage fails.
    pub fn generate_credential_with_key(
        &mut self,
        identity: Vec<u8>,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let credential = BasicCredential::new(identity);
        let signature_keys = SignatureKeyPair::new(self.signature_algorithm)
            .expect("Error generating a signature key pair.");

        // Store the signature key into the key store so OpenMLS has access
        // to it.
        signature_keys
            .store(self.provider.storage())
            .expect("Error storing signature keys in key store.");

        (
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keys.public().into(),
            },
            signature_keys,
        )
    }

    // A helper to create key package bundles.
    pub fn generate_key_package(
        &mut self,
        credential_with_key: &CredentialWithKey,
        signer: &SignatureKeyPair,
    ) -> Result<KeyPackageBundle> {
        // Create the key package
        KeyPackage::builder()
            .build(
                self.ciphersuite,
                &self.provider,
                signer,
                credential_with_key.clone(),
            )
            .context("Error creating key package bundle.")
    }

    pub fn new() -> Self {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        OpenMlsKeyPackage {
            provider: OpenMlsRustCrypto::default(),
            ciphersuite,
            signature_algorithm: ciphersuite.signature_algorithm(),
        }
    }
}
