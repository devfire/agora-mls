use kameo::prelude::*;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::sync::Arc;

use crate::identity_actor::{IdentityActor, IdentityActorMsg};

#[derive(Actor, Debug, Clone)]
pub struct OpenMlsActor {
    // client_identity: Vec<u8>, // Public key loaded from SSH ED25519 format
    pub ciphersuite: Ciphersuite,
    pub signature_algorithm: SignatureScheme,
    pub mls_key_package: KeyPackageBundle,
    pub credential_with_key: CredentialWithKey,
    pub signature_keypair: Arc<SignatureKeyPair>,
    pub crypto_provider: Arc<OpenMlsRustCrypto>, // Shared crypto provider with stored keys
}

// Define the message
pub struct OpenMlsIdentityRequest;

#[derive(Reply, Debug)]
pub struct OpenMlsIdentityReply {
    pub mls_key_package: KeyPackageBundle,
    pub credential_with_key: CredentialWithKey,
    pub signature_keypair: Arc<SignatureKeyPair>, // neither Clone nor Copy is implemented, bummer. So we wrap it in an Arc.
    pub ciphersuite: Ciphersuite,
    pub crypto_provider: Arc<OpenMlsRustCrypto>, // Shared crypto provider with stored keys
}

// Implement the message handling for HelloWorldActor
impl Message<OpenMlsIdentityRequest> for OpenMlsActor {
    type Reply = OpenMlsIdentityReply;

    async fn handle(
        &mut self,
        _msg: OpenMlsIdentityRequest, // Destructure the Greet message to get the greeting string
        _: &mut Context<Self, Self::Reply>, // The message handling context
    ) -> Self::Reply {
        OpenMlsIdentityReply {
            mls_key_package: self.mls_key_package.clone(),
            credential_with_key: self.credential_with_key.clone(),
            signature_keypair: self.signature_keypair.clone(),
            ciphersuite: self.ciphersuite,
            crypto_provider: self.crypto_provider.clone(),
        }
    }
}

impl OpenMlsActor {
    /// Creates a new OpenMLS identity with cryptographic keys and credentials.
    ///
    /// Generates a signature keypair, creates a basic credential from the provided
    /// identity's verifying key, and builds a key package for MLS protocol use.
    ///
    /// # Arguments
    /// * `identity` - Reference to the IdentityActor to obtain the verifying key
    ///
    /// # Panics
    /// * If unable to get verifying key from IdentityActor
    /// * If signature keypair generation fails
    /// * If key storage or key package creation fails
    pub async fn new(identity: &ActorRef<IdentityActor>) -> Self {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        // Create a shared crypto provider that will be reused across all MLS operations
        let provider = Arc::new(OpenMlsRustCrypto::default());

        let identity_reply = identity
            .ask(IdentityActorMsg {
                handle_update: None,
            })
            .await
            .expect("Failed to get verifying key from IdentityActor.");

        let credential = BasicCredential::new(identity_reply.verifying_key.to_bytes().to_vec());

        // Convert the ed25519_dalek SigningKey into the format OpenMLS expects.
        let signature_keypair = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            identity_reply.signing_key.to_bytes().to_vec(),  // private key
            identity_reply.verifying_key.to_bytes().to_vec(), // public key
        );

        // Store the signature key into the key store so OpenMLS has access to it.
        signature_keypair
            .store(provider.as_ref().storage())
            .expect("Error storing signature keys in key store.");

        //     // self.signature_keypair = Some(signature_key_pair);
        let credential_with_key = CredentialWithKey {
            credential: credential.clone().into(),
            signature_key: signature_keypair.public().into(),
        };

        // Build KeyPackage (username will be sent via protobuf wrapper, not extension)
        let mls_key_package = KeyPackage::builder()
            .build(
                ciphersuite,
                provider.as_ref(),
                &signature_keypair,
                credential_with_key.clone(),
            )
            .expect("Error creating key package bundle.");

        OpenMlsActor {
            ciphersuite,
            signature_algorithm: ciphersuite.signature_algorithm(),
            mls_key_package,
            signature_keypair: Arc::new(signature_keypair),
            credential_with_key,
            crypto_provider: provider,
        }
    }
}
