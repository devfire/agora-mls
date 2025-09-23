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
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
}

impl OpenMlsKeyPackage {
    // A helper to create and store credentials.
    fn generate_credential_with_key(
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
    fn generate_key_package(
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        signer: &SignatureKeyPair,
        credential_with_key: CredentialWithKey,
    ) -> Result<KeyPackageBundle> {
        // Create the key package
        KeyPackage::builder()
            .build(ciphersuite, provider, signer, credential_with_key)
            .context("Error creating key package bundle.")
    }

    pub fn new() -> Self {
        OpenMlsKeyPackage {
            provider: OpenMlsRustCrypto::default(),
            credential_type: CredentialType::Basic,
            signature_algorithm: Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
                .signature_algorithm(),
        }
    }
}
