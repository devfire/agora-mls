use std::{collections::HashMap, fs, path::Path, sync::Arc};

use anyhow::{Context, Result, anyhow};
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
    mls_key_package: KeyPackageBundle,
    credential_with_key: CredentialWithKey,
    signature_keypair: Arc<SignatureKeyPair>,
    crypto_provider: Arc<OpenMlsRustCrypto>,

    // === MLS Group Management (MOVED from StateActor for security) ===
    groups: HashMap<GroupId, MlsGroup>,
    active_group: Option<GroupId>,
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

    /// Get MLS identity information (TEMPORARY - for backward compatibility)
    GetMlsIdentity,

    // === MLS Group Operations ===
    /// Create a new MLS group
    CreateGroup { group_name: String },

    /// Add a member to the active group
    AddMember { key_package: KeyPackage },
    /// Encrypt a message for the current active group
    EncryptMessage { plaintext: Vec<u8> },
    /// Process an incoming MLS message
    ProcessMessage { mls_message_in: MlsMessageIn },
    /// Join a group via Welcome message
    JoinGroup { welcome: Welcome },
    /// List all groups
    ListGroups,
    /// Get the active group name
    GetActiveGroup,
    /// Set the active group
    SetActiveGroup(GroupId),
}

#[derive(Reply)]
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
    },

    // === MLS Operation Replies (NEW - Phase 2) ===
    /// Group created successfully
    GroupCreated(GroupId),
    /// Member added successfully
    MemberAdded {
        commit: MlsMessageOut,
        welcome: MlsMessageOut,      // Welcome wrapped in MlsMessageOut
        group_info: Option<Vec<u8>>, // Serialized GroupInfo
    },
    /// Message encrypted successfully
    MessageEncrypted {
        ciphertext: MlsMessageOut,
    },
    /// Message processed successfully
    MessageProcessed {
        result: ProcessedMessageResult,
    },
    /// Group joined successfully
    GroupJoined {
        group_name: String,
    },
    /// List of groups
    Groups {
        groups: Vec<String>,
    },
    /// Active group name
    ActiveGroup {
        group_id: Option<GroupId>,
    },
    /// Generic success
    Success,
    /// Operation failed
    Failure(anyhow::Error),
}

/// Result of processing an incoming MLS message
#[derive(Debug)]
pub enum ProcessedMessageResult {
    /// Decrypted application message
    ApplicationMessage(String),
    /// Received a proposal (not yet committed)
    ProposalMessage,
    /// Received an external join proposal
    ExternalJoinProposal,
    /// Staged commit merged successfully
    StagedCommitMerged,
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
            CryptoIdentityMessage::GetIdentity => CryptoIdentityReply::Identity {
                handle: self.handle.clone(),
                verifying_key: self.verifying_key,
            },

            CryptoIdentityMessage::GetKeyPackage => CryptoIdentityReply::KeyPackage {
                key_package: self.mls_key_package.key_package().clone(),
                credential: self.credential_with_key.clone(),
            },

            CryptoIdentityMessage::SignData { data } => {
                // Signing happens HERE - private key never leaves the actor
                let signature = self.signing_key.sign(&data);
                CryptoIdentityReply::Signature { signature }
            }

            CryptoIdentityMessage::GetMlsIdentity => CryptoIdentityReply::MlsIdentity {
                mls_key_package: self.mls_key_package.clone(),
                credential_with_key: self.credential_with_key.clone(),
                ciphersuite: self.ciphersuite,
                crypto_provider: self.crypto_provider.clone(),
            },

            // === MLS Group Operation Handlers ===
            CryptoIdentityMessage::CreateGroup { group_name } => {
                self.handle_create_group(group_name)
            }

            CryptoIdentityMessage::AddMember { key_package } => {
                self.handle_add_member_to_group(key_package)
            }

            CryptoIdentityMessage::EncryptMessage { plaintext } => {
                self.handle_encrypt_message(plaintext)
            }

            CryptoIdentityMessage::ProcessMessage { mls_message_in } => {
                self.handle_process_message(mls_message_in)
            }

            CryptoIdentityMessage::JoinGroup { welcome } => self.handle_join_group(welcome),

            CryptoIdentityMessage::ListGroups =>
            // 1. Get list of group IDs
            // 2. Fetch the corresponding MlsGroup references from the HashMap
            // 3. Extract group names from each MlsGroup
            {
                CryptoIdentityReply::Groups {
                    groups: self
                        .groups
                        .values()
                        .filter_map(|group| Self::extract_group_name(group))
                        .collect(),
                }
            }

            CryptoIdentityMessage::GetActiveGroup => CryptoIdentityReply::ActiveGroup {
                group_id: self.active_group.clone(),
            },

            CryptoIdentityMessage::SetActiveGroup(group_id) => {
                if self.groups.contains_key(&group_id) {
                    self.active_group = Some(group_id);
                    CryptoIdentityReply::Success
                } else {
                    CryptoIdentityReply::Failure(anyhow!("Group not found"))
                }
            }
        }
    }
}

// ============================================================================
// INITIALIZATION AND HELPER METHODS
// ============================================================================

impl CryptoIdentityActor {
    // ========================================================================
    // MLS GROUP OPERATION HANDLERS
    // ========================================================================

    /// Create a new MLS group with the specified name
    fn handle_create_group(&mut self, group_name: String) -> CryptoIdentityReply {
        const GROUP_NAME_EXTENSION_ID: u16 = 13;

        // Create group name extension
        let group_name_bytes = group_name.as_bytes();
        let unknown_ext_data = UnknownExtension(group_name_bytes.to_vec());
        let group_name_extension = Extension::Unknown(
            ExtensionType::from(GROUP_NAME_EXTENSION_ID).into(),
            unknown_ext_data,
        );
        let extensions = Extensions::single(group_name_extension);

        // Build group configuration
        let mls_group_create_config = match MlsGroupCreateConfig::builder()
            .ciphersuite(self.ciphersuite)
            .with_group_context_extensions(extensions)
        {
            Ok(builder) => builder.use_ratchet_tree_extension(true).build(),
            Err(e) => {
                return CryptoIdentityReply::Failure(anyhow!("Invalid extension: {e}",));
            }
        };

        // Create the group (signature_keypair stays private)
        let group = match MlsGroup::new(
            self.crypto_provider.as_ref(),
            &*self.signature_keypair,
            &mls_group_create_config,
            self.credential_with_key.clone(),
        ) {
            Ok(g) => g,
            Err(e) => {
                return CryptoIdentityReply::Failure(anyhow!("Group creation failed: {e}"));
            }
        };

        // Get the GroupId value by cloning
        let group_id = group.group_id().clone();

        // Store the group and set as active
        self.groups.insert(group_id.clone(), group);
        self.active_group = Some(group_id.clone());

        CryptoIdentityReply::GroupCreated(group_id)
    }

    /// Add a member to the active MLS group
    fn handle_add_member_to_group(&mut self, key_package: KeyPackage) -> CryptoIdentityReply {
        // Determine which group to use
        let active_group_id = match &self.active_group {
            Some(id) => id,
            None => {
                return CryptoIdentityReply::Failure(anyhow!("No active group found"));
            }
        };
        // Get the group
        let active_group_ref = match self.groups.get_mut(&active_group_id) {
            Some(g) => g,
            None => {
                return CryptoIdentityReply::Failure(anyhow!("No active group found"));
            }
        };

        // Add member (signature_keypair used HERE - stays private)
        let (mls_message_out, welcome, group_info) = match active_group_ref.add_members(
            self.crypto_provider.as_ref(),
            &*self.signature_keypair,
            &[key_package],
        ) {
            Ok(result) => result,
            Err(e) => {
                return CryptoIdentityReply::Failure(anyhow!("Failed to add member: {e}"));
            }
        };

        // Merge the pending commit
        if let Err(e) = active_group_ref.merge_pending_commit(self.crypto_provider.as_ref()) {
            return CryptoIdentityReply::Failure(anyhow!("Failed to merge pending commit: {e}"));
        }

        // Serialize group_info if present
        use openmls::prelude::tls_codec::Serialize;
        let group_info_bytes = group_info.and_then(|gi| gi.tls_serialize_detached().ok());

        CryptoIdentityReply::MemberAdded {
            commit: mls_message_out,
            welcome,
            group_info: group_info_bytes,
        }
    }

    /// Encrypt a message for a group
    fn handle_encrypt_message(&mut self, plaintext: Vec<u8>) -> CryptoIdentityReply {
        // get the active group id from the active group
        let group_id = match &self.active_group {
            Some(id) => id,
            None => {
                return CryptoIdentityReply::Failure(anyhow!("No active group found"));
            }
        };
        // Get the group
        let group_ref = match self.groups.get_mut(&group_id) {
            Some(g) => g,
            None => {
                return CryptoIdentityReply::Failure(anyhow!("No active group found"));
            }
        };

        // Encrypt message (signature_keypair used HERE - stays private)
        let mls_message_out = match group_ref.create_message(
            self.crypto_provider.as_ref(),
            &*self.signature_keypair,
            &plaintext,
        ) {
            Ok(msg) => msg,
            Err(e) => {
                return CryptoIdentityReply::Failure(anyhow!("Failed to encrypt message: {e}"));
            }
        };

        CryptoIdentityReply::MessageEncrypted {
            ciphertext: mls_message_out,
        }
    }

    /// Process an incoming MLS message
    fn handle_process_message(&mut self, mls_message_in: MlsMessageIn) -> CryptoIdentityReply {
        // // Determine which group to use
        // let target_group_name = match group_name.or_else(|| self.active_group.clone()) {
        //     Some(name) => name,
        //     None => {
        //         return CryptoIdentityReply::Failed {
        //             message: "No active group specified".to_string(),
        //         };
        //     }
        // };

        // // Get the group
        // let group = match self.groups.get_mut(&target_group_name) {
        //     Some(g) => g,
        //     None => {
        //         return CryptoIdentityReply::Failed {
        //             message: format!("Group '{}' not found", target_group_name),
        //         };
        //     }
        // };
        // let active_group_name = self
        //     .active_group
        //     .as_ref()
        //     .ok_or()?;

        // let incoming_group_id = mls_message_in.group_id();

        // // extract the group name from the MlsGroup inbound
        // let group_name = Self::extract_group_name(&mls_message_in);

        // Convert to ProtocolMessage
        let protocol_message = match mls_message_in.try_into_protocol_message() {
            Ok(pm) => pm,
            Err(e) => {
                return CryptoIdentityReply::Failure(anyhow!(
                    "Failed to convert to ProtocolMessage: {e}"
                ));
            }
        };

        // Get the group ID from the message
        let group_id = protocol_message.group_id();

        // Get the group
        let group = match self.groups.get_mut(&group_id) {
            Some(g) => g,
            None => {
                return CryptoIdentityReply::Failure(anyhow!(
                    "Group with ID '{:?}' not found",
                    group_id
                ));
            }
        };

        // Process the message (crypto_provider has access to keys)
        let processed_message =
            match group.process_message(self.crypto_provider.as_ref(), protocol_message) {
                Ok(pm) => pm,
                Err(e) => {
                    return CryptoIdentityReply::Failure(anyhow!("Failed to process message: {e}"));
                }
            };

        // Handle different content types
        let result = match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                match String::from_utf8(app_msg.into_bytes()) {
                    Ok(text) => ProcessedMessageResult::ApplicationMessage(text),
                    Err(e) => {
                        return CryptoIdentityReply::Failure(anyhow!(
                            "Invalid UTF-8 in message: {e}"
                        ));
                    }
                }
            }
            ProcessedMessageContent::ProposalMessage(_) => ProcessedMessageResult::ProposalMessage,
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                ProcessedMessageResult::ExternalJoinProposal
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                // Merge the staged commit
                if let Err(e) =
                    group.merge_staged_commit(self.crypto_provider.as_ref(), *staged_commit)
                {
                    return CryptoIdentityReply::Failure(anyhow!(
                        "Failed to merge staged commit: {e}"
                    ));
                }
                ProcessedMessageResult::StagedCommitMerged
            }
        };

        CryptoIdentityReply::MessageProcessed { result }
    }

    /// Join a group via Welcome message
    fn handle_join_group(&mut self, welcome: Welcome) -> CryptoIdentityReply {
        // Create join configuration
        let mls_group_join_config = MlsGroupJoinConfig::default();

        // Stage the Welcome message
        let staged_welcome = match StagedWelcome::new_from_welcome(
            self.crypto_provider.as_ref(),
            &mls_group_join_config,
            welcome,
            None, // ratchet_tree typically not needed
        ) {
            Ok(sw) => sw,
            Err(e) => {
                return CryptoIdentityReply::Failure(anyhow!(
                    "Failed to stage Welcome message: {}",
                    e
                ));
            }
        };

        // Convert to MlsGroup (uses stored keys from crypto_provider)
        let group = match staged_welcome.into_group(self.crypto_provider.as_ref()) {
            Ok(g) => g,
            Err(e) => {
                return CryptoIdentityReply::Failure(anyhow!("Failed to join group: {}", e));
            }
        };

        // Extract group name from extensions, we only need it for the return confirmation
        let group_name = match Self::extract_group_name(&group) {
            Some(name) => name,
            None => return CryptoIdentityReply::Failure(anyhow!("Failed to extract group name.")),
        };

        let group_id = group.group_id().clone();

        // Store the group and set as active
        self.groups.insert(group_id.clone(), group);
        self.active_group = Some(group_id.clone());

        CryptoIdentityReply::GroupJoined { group_name }
    }

    /// Extract group name from MlsGroup extensions
    fn extract_group_name(group: &MlsGroup) -> Option<String> {
        const GROUP_NAME_EXTENSION_ID: u16 = 13;

        // Get the group context extensions
        let extensions = group.extensions();

        // Find the specific extension by type
        let group_name_ext_type = ExtensionType::from(GROUP_NAME_EXTENSION_ID);

        extensions.iter().find_map(|ext| {
            match ext {
                Extension::Unknown(ext_type, unknown_ext) => {
                    // Check if this is our group name extension
                    if *ext_type == Into::<u16>::into(group_name_ext_type) {
                        // Extract the bytes from UnknownExtension
                        let name_bytes = &unknown_ext.0;
                        // Convert bytes to String
                        String::from_utf8(name_bytes.clone()).ok()
                    } else {
                        None
                    }
                }
                _ => None,
            }
        })
    }

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
            mls_key_package,
            credential_with_key,
            signature_keypair: Arc::new(signature_keypair),
            crypto_provider: provider,
            groups: HashMap::new(),
            active_group: None,
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
}
