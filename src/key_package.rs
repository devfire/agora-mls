use kameo::actor::ActorRef;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::identity_actor::{IdentityActor, IdentityRequest};

#[derive(Debug)]
pub struct OpenMlsIdentity {
    // client_identity: Vec<u8>, // Public key loaded from SSH ED25519 format

    // ... and the crypto provider to use.
    // pub provider: OpenMlsRustCrypto,
    pub ciphersuite: Ciphersuite,
    pub signature_algorithm: SignatureScheme,
    pub mls_key_package: KeyPackageBundle,
    pub credential_with_key: CredentialWithKey,
    pub signature_keypair: SignatureKeyPair,
}

impl OpenMlsIdentity {
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
    // fn generate_credential_with_key(
    //     &mut self,
    //     identity: Vec<u8>,
    // ) -> (CredentialWithKey, SignatureKeyPair) {
    //     let credential = BasicCredential::new(identity);
    //     let signature_key_pair = SignatureKeyPair::new(self.signature_algorithm)
    //         .expect("Error generating a signature key pair.");

    //     // Store the signature key into the key store so OpenMLS has access
    //     // to it.
    //     signature_key_pair
    //         .store(self.provider.storage())
    //         .expect("Error storing signature keys in key store.");

    //     // self.signature_keypair = Some(signature_key_pair);
    //     self.credential_with_key = Some(CredentialWithKey {
    //         credential: credential.clone().into(),
    //         signature_key: signature_key_pair.public().into(),
    //     });

    //     (
    //         CredentialWithKey {
    //             credential: credential.into(),
    //             signature_key: signature_key_pair.public().into(),
    //         },
    //         signature_key_pair,
    //     )
    // }

    // A helper to create key package bundles.
    // pub fn generate_key_package_bundle(
    //     &mut self,
    //     // credential_with_key: &CredentialWithKey,
    //     // signer: &SignatureKeyPair,
    // ) -> Result<KeyPackageBundle> {
    //     let credential_with_key = self
    //         .credential_with_key
    //         .context("Credential with key not set; call generate_credential_with_key first.")?
    //         .clone();

    //     let signer = self
    //         .signature_keypair
    //         .as_ref()
    //         .context("Signature key pair not set; call generate_credential_with_key first.")?;

    //     // Create the key package
    //     KeyPackage::builder()
    //         .build(
    //             self.ciphersuite,
    //             &self.provider,
    //             signer,
    //             credential_with_key.clone(),
    //         )
    //         .context("Error creating key package bundle.")
    // }

    pub async fn new(identity: ActorRef<IdentityActor>) -> Self {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let provider = &OpenMlsRustCrypto::default();


        let verifying_key = identity
            .ask(IdentityRequest)
            .await
            .expect("Failed to get verifying key from IdentityActor.")
            .verifying_key;

        let credential = BasicCredential::new(verifying_key.to_bytes().to_vec());
        let signature_keypair = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .expect("Error generating a signature key pair.");

        //     // Store the signature key into the key store so OpenMLS has access
        //     // to it.
        signature_keypair
            .store(provider.storage())
            .expect("Error storing signature keys in key store.");

        //     // self.signature_keypair = Some(signature_key_pair);
        let credential_with_key = CredentialWithKey {
            credential: credential.clone().into(),
            signature_key: signature_keypair.public().into(),
        };

        // let mut mls_key_package = OpenMlsIdentity::new();

        let mls_key_package = KeyPackage::builder()
            .build(
                ciphersuite,
                &OpenMlsRustCrypto::default(),
                &signature_keypair,
                credential_with_key.clone(),
            )
            .expect("Error creating key package bundle.");

        OpenMlsIdentity {
            ciphersuite,
            signature_algorithm: ciphersuite.signature_algorithm(),
            mls_key_package,
            signature_keypair,
            credential_with_key,
        }
    }
}
