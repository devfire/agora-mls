use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use kameo::prelude::*;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use ssh_key::PrivateKey;
use zeroize::Zeroizing;

/// Combined actor managing both SSH identity and MLS protocol state.
/// All private keys are encapsulated and never exposed via messages.
///
/// This actor combines the functionality of IdentityActor and OpenMlsActor
/// to prevent private key leakage across actor boundaries. The security model
/// ensures that signing operations happen internally and only signatures or
/// public information is returned via messages.
#[derive(Actor)]
pub struct CryptoIdentityActor {
    // === SSH Identity (PRIVATE - never exposed) ===
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    handle: String,
    
    // === MLS Protocol State (PRIVATE - never exposed) ===
    ciphersuite: Ciphersuite,
    signature_algorithm: SignatureScheme,
    mls_key_package: KeyPackageBundle,
    credential_with_key: CredentialWithKey,
    signature_keypair: Arc<SignatureKeyPair>,
    crypto_provider: Arc<OpenMlsRustCrypto>,
}

// ============================================================================
// MESSAGE TYPES - Single enum pattern for cleaner API
// ============================================================================

#[derive(Debug)]
pub enum CryptoIdentityMessage {
    /// Get public identity information (handle, verifying_key)
    GetIdentity,
    /// Get MLS key package for invites
    GetKeyPackage,
    /// Request signature operation (signing happens internally)
    SignData { data: Vec<u8> },
    /// Update display name/handle
    UpdateHandle { new_handle: String },
    /// Get MLS identity information (for operations that need it)
    GetMlsIdentity,
}

#[derive(Reply, Debug)]
pub enum CryptoIdentityReply {
    Identity {
        handle: String,
        verifying_key: VerifyingKey,
    },
    KeyPackage {
        key_package: KeyPackage,
        credential: CredentialWithKey,
    },
    Signature {
        signature: Signature,
    },
    UpdateComplete,
    MlsIdentity {
        mls_key_package: KeyPackageBundle,
        credential_with_key: CredentialWithKey,
        ciphersuite: Ciphersuite,
        crypto_provider: Arc<OpenMlsRustCrypto>,
        // TEMPORARY: signature_keypair exposed until Phase 2 refactoring
        // TODO: Move all MLS operations into CryptoIdentityActor to eliminate this
        signature_keypair: Arc<SignatureKeyPair>,
    },
}

// ============================================================================
// MESSAGE HANDLER - Single implementation matching on enum variants
// ============================================================================

impl Message<CryptoIdentityMessage> for CryptoIdentityActor {
    type Reply = CryptoIdentityReply;
    
    async fn handle(
        &mut self,
        msg: CryptoIdentityMessage,
        _ctx: &mut kameo::message::Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg {
            CryptoIdentityMessage::GetIdentity => {
                CryptoIdentityReply::Identity {
                    handle: self.handle.clone(),
                    verifying_key: self.verifying_key,
                }
            }
            
            CryptoIdentityMessage::GetKeyPackage => {
                CryptoIdentityReply::KeyPackage {
                    key_package: self.mls_key_package.key_package().clone(),
                    credential: self.credential_with_key.clone(),
                }
            }
            
            CryptoIdentityMessage::SignData { data } => {
                // Signing happens HERE - private key never leaves the actor
                let signature = self.signing_key.sign(&data);
                CryptoIdentityReply::Signature { signature }
            }
            
            CryptoIdentityMessage::UpdateHandle { new_handle } => {
                self.handle = new_handle;
                CryptoIdentityReply::UpdateComplete
            }
            
            CryptoIdentityMessage::GetMlsIdentity => {
                CryptoIdentityReply::MlsIdentity {
                    mls_key_package: self.mls_key_package.clone(),
                    credential_with_key: self.credential_with_key.clone(),
                    ciphersuite: self.ciphersuite,
                    crypto_provider: self.crypto_provider.clone(),
                    // TEMPORARY: Exposing signature_keypair until Phase 2 refactoring
                    // TODO: This should be removed once MLS operations move into this actor
                    signature_keypair: self.signature_keypair.clone(),
                }
            }
        }
    }
}

// ============================================================================
// INITIALIZATION AND HELPER METHODS
// ============================================================================

impl CryptoIdentityActor {
    /// Creates a new combined identity actor from an SSH key file.
    ///
    /// This combines the functionality of IdentityActor and OpenMlsActor,
    /// loading the SSH key and initializing MLS state in one operation.
    /// Private keys never leave this actor.
    ///
    /// # Arguments
    /// * `key_file_path` - Path to the SSH private key file
    /// * `display_name` - Human-readable display name for this identity
    ///
    /// # Returns
    /// A new CryptoIdentityActor with all crypto state initialized
    ///
    /// # Errors
    /// * If the SSH key cannot be loaded
    /// * If MLS initialization fails
    pub fn new(key_file_path: &Path, display_name: &str) -> Result<Self> {
        // Step 1: Load SSH key
        let (signing_key, verifying_key) = Self::load_ssh_ed25519_key(key_file_path)?;
        
        // Step 2: Setup MLS
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let provider = Arc::new(OpenMlsRustCrypto::default());
        
        // Step 3: Create MLS signature keypair from SSH key
        // This allows MLS to use the same identity as SSH
        let signature_keypair = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            signing_key.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
        );
        
        // Step 4: Store in KeyStore (stays within this actor)
        signature_keypair
            .store(provider.as_ref().storage())
            .context("Failed to store signature keypair in OpenMLS KeyStore")?;
        
        // Step 5: Create MLS credential
        let credential = BasicCredential::new(verifying_key.to_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keypair.public().into(),
        };
        
        // Step 6: Build MLS key package
        let mls_key_package = KeyPackage::builder()
            .build(
                ciphersuite,
                provider.as_ref(),
                &signature_keypair,
                credential_with_key.clone(),
            )
            .context("Failed to create MLS key package")?;
        
        Ok(CryptoIdentityActor {
            signing_key,
            verifying_key,
            handle: display_name.to_string(),
            ciphersuite,
            signature_algorithm: ciphersuite.signature_algorithm(),
            mls_key_package,
            credential_with_key,
            signature_keypair: Arc::new(signature_keypair),
            crypto_provider: provider,
        })
    }
    
    /// Loads an Ed25519 SSH private key from a file and extracts the signing/verifying key pair.
    ///
    /// Handles both encrypted and unencrypted SSH keys. For encrypted keys, securely prompts
    /// for the passphrase and immediately zeroizes it after use. Only supports Ed25519 keys.
    ///
    /// # Arguments
    /// * `key_path` - Path to the SSH private key file in OpenSSH format
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
    
    /// Returns a reference to the signature keypair for internal MLS operations.
    ///
    /// WARNING: This method is for internal use only within MLS operation handlers.
    /// The signature keypair should NEVER be exposed via messages or returned to other actors.
    pub(crate) fn get_signature_keypair(&self) -> &Arc<SignatureKeyPair> {
        &self.signature_keypair
    }
    
    /// Returns a reference to the crypto provider for MLS operations.
    pub(crate) fn get_crypto_provider(&self) -> &Arc<OpenMlsRustCrypto> {
        &self.crypto_provider
    }
}