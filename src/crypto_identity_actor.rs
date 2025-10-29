use crate::agora_chat;

use std::{collections::HashMap, fs, path::Path, sync::Arc};

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::{SigningKey, VerifyingKey};
use kameo::prelude::*;
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use ssh_key::PrivateKey;
use tracing::debug;
use zeroize::Zeroizing;

/// Combined actor managing both SSH identity and MLS protocol state.
/// All private keys are encapsulated and never exposed via messages.
///
/// The security model ensures that signing operations happen internally and only signatures or
/// public information is returned via messages.
#[derive(Actor)]
pub struct CryptoIdentityActor {
    // === MLS Protocol State (PRIVATE - never exposed) ===
    ciphersuite: Ciphersuite,

    username: String,

    mls_key_package_bundle: KeyPackageBundle,
    credential_with_key: CredentialWithKey,
    signature_keypair: Arc<SignatureKeyPair>,
    crypto_provider: Arc<OpenMlsRustCrypto>,

    // === MLS Group Management ===
    groups: HashMap<GroupId, MlsGroup>,
    // current_group: Option<GroupId>,

    // == User nick to KeyPackage mapping ===
    user_cache: HashMap<UserIdentity, KeyPackageIn>,

    // TODO: needs to be merged with groups so the key is a struct with name + id.
    // Otherwise, I can create a group and someone else can create a group with the same name but different ID.
    // Which is OK but will cause collisions when switching groups by name.
    // Will also need to display group+id in /groups output and stdin chat intake.
    group_name_to_id: HashMap<String, GroupId>,
}

// ============================================================================
// MESSAGE TYPES - Single enum pattern for cleaner API
// ============================================================================

#[derive(Debug)]
pub enum CryptoIdentityMessage {
    // === MLS Group Operations ===
    /// Create a new MLS group
    CreateGroup {
        group_name: String,
    },

    /// Add a member to the current active group
    InviteMemberToGroup {
        key_package: KeyPackage,
        group_name: String,
    },

    /// Encrypt a message for the current active group
    EncryptMessage {
        plaintext: Vec<u8>,
        group_name: String,
    },

    /// Process an incoming MLS message
    ProcessMessage {
        mls_message_in: MlsMessageIn,
    },

    /// List all groups
    ListGroups,

    /// List all users in cache
    ListUsers,

    /// Handle user invites
    InviteUser {
        user_identity: UserIdentity,
        group_name: String,
    },

    CreateAnnouncement, // --> returns CryptoIdentityReply::UserAnnouncement(UserIdentity)

    /// Add a new user from their announcement
    AddNewUser {
        user_announcement: UserAnnouncement,
    },

    /// Process received HPKE-encrypted GroupInfo and create external commit
    ProcessEncryptedGroupInfo {
        encrypted_group_info: crate::agora_chat::EncryptedGroupInfo,
    },
}

#[derive(Reply)]
pub enum CryptoIdentityReply {
    // === MLS Operation Replies ===
    /// Group created successfully
    GroupCreated(String),

    /// HPKE-encrypted GroupInfo for external commit join
    EncryptedGroupInfoForExternalInvite {
        encrypted_group_info: AgoraPacket, // EncryptedGroupInfo wrapped in AgoraPacket, not MlsMessageOut
    },
    /// Message encrypted successfully
    MlsMessageOut(MlsMessageOut),
    /// Message processed successfully
    MessageProcessed { result: ProcessedMessageResult },
    /// Group joined successfully
    GroupJoined { group_name: String },
    /// List of groups returned in response to ListGroups command or /groups
    Groups { groups: Vec<String> },

    /// List of known users returned in response to ListUsers command or /users
    Users { users: Vec<String> },

    /// A user announcement is a custom protocol message containing username and key package, not an MLS protocol message.
    /// Therefore, it wraps an AgoraPacket, not MlsMessageOut.
    /// This is used for announcing one's identity to others in response to the /announce command.
    UserAnnouncement(AgoraPacket),

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
            CryptoIdentityMessage::CreateGroup { group_name } => {
                match self.handle_create_group(group_name) {
                    Ok(reply) => reply,
                    Err(e) => CryptoIdentityReply::Failure(e),
                }
            }
            CryptoIdentityMessage::InviteMemberToGroup {
                key_package,
                group_name,
            } => match self.invite_new_member_to_group(key_package, &group_name) {
                Ok(reply) => reply,
                Err(e) => CryptoIdentityReply::Failure(e),
            },
            CryptoIdentityMessage::EncryptMessage {
                plaintext,
                group_name,
            } => self.handle_encrypt_message(plaintext, &group_name),
            CryptoIdentityMessage::ProcessMessage { mls_message_in } => {
                self.handle_mls_message(mls_message_in)
            }
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
            CryptoIdentityMessage::InviteUser {
                user_identity,
                group_name,
            } => match self.handle_invite_user(user_identity, &group_name) {
                Ok(reply) => reply,
                Err(e) => CryptoIdentityReply::Failure(e),
            },
            CryptoIdentityMessage::CreateAnnouncement => match self.create_user_announcement() {
                Ok(reply) => reply,
                Err(e) => CryptoIdentityReply::Failure(e),
            },
            CryptoIdentityMessage::AddNewUser { user_announcement } => {
                match self.handle_new_user_announcement(user_announcement) {
                    Ok(reply) => reply,
                    Err(e) => CryptoIdentityReply::Failure(e),
                }
            }
            CryptoIdentityMessage::ListUsers => {
                let users: Vec<String> = self
                    .user_cache
                    .keys()
                    .map(|user_identity| user_identity.to_string())
                    .collect();
                CryptoIdentityReply::Users { users }
            }
            CryptoIdentityMessage::ProcessEncryptedGroupInfo {
                encrypted_group_info,
            } => match self.handle_encrypted_group_info(encrypted_group_info) {
                Ok(reply) => reply,
                Err(e) => CryptoIdentityReply::Failure(e),
            },
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
    fn handle_create_group(&mut self, group_name: String) -> Result<CryptoIdentityReply> {
        // First check if the group already exists
        if self.group_name_to_id.contains_key(&group_name) {
            return Err(anyhow!("Group '{}' already exists", group_name));
        }
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
                return Err(anyhow!("Invalid extension: {e}",));
            }
        };

        // Create the group (signature_keypair stays private)
        let group = MlsGroup::new(
            self.crypto_provider.as_ref(),
            &*self.signature_keypair,
            &mls_group_create_config,
            self.credential_with_key.clone(),
        )
        .context("Group creation failed")?;

        // Get the GroupId value by cloning
        let group_id = group.group_id().clone();

        // Store the group and set as active
        self.groups.insert(group_id.clone(), group);

        // Store the group name for future reference when the user wants to switch groups by name
        self.group_name_to_id
            .insert(group_name.clone(), group_id.clone());

        Ok(CryptoIdentityReply::GroupCreated(group_name))
    }

    /// Export GroupInfo for external commit join, encrypted with recipient's KeyPackage
    ///
    /// This function exports the group's public state (GroupInfo) and encrypts it using
    /// HPKE with the recipient's public key from their KeyPackage. This provides transport-level
    /// encryption of the GroupInfo before transmission.
    ///
    /// Security model:
    /// 1. GroupInfo is encrypted using HPKE with recipient's HpkePublicKey
    /// 2. Only the recipient with the corresponding private key can decrypt
    /// 3. The encrypted ciphertext is sent over the network
    /// 4. Recipient decrypts and uses GroupInfo to create external commit
    /// 5. Current members process and accept the external commit proposal
    ///
    /// Flow:
    /// 1. Export GroupInfo from current group state
    /// 2. Extract recipient's HPKE public key from their KeyPackage
    /// 3. Encrypt GroupInfo bytes using HPKE seal operation
    /// 4. Send encrypted ciphertext to recipient
    /// 5. Recipient decrypts with their HPKE private key
    /// 6. Recipient uses GroupInfo to create external commit
    fn invite_new_member_to_group(
        &mut self,
        key_package: KeyPackage,
        group_name: &str,
    ) -> Result<CryptoIdentityReply> {
        // Determine which group to use
        let target_group_id = match self.group_name_to_id.get(group_name) {
            Some(id) => id,
            None => {
                return Err(anyhow!("No active group found"));
            }
        };

        // Get the group
        let target_group_ref = match self.groups.get(&target_group_id) {
            Some(g) => g,
            None => {
                return Err(anyhow!("No active group found"));
            }
        };

        // Export the GroupInfo for the external joiner
        let group_info_out = target_group_ref
            .export_group_info(
                &RustCrypto::default(),
                &*self.signature_keypair,
                true, // with_ratchet_tree - include the ratchet tree for external commits
            )
            .context("Failed to export GroupInfo")?;

        // Serialize GroupInfo to bytes for encryption
        // let group_info_bytes = match group_info_out.tls_serialize_detached() {
        //     Ok(bytes) => bytes,
        //     Err(e) => {
        //         return Err(anyhow!("Failed to serialize GroupInfo: {e}"));
        //     }
        // };

        // Extract the HPKE public key from the recipient's KeyPackage
        let recipient_hpke_key = key_package.hpke_init_key();

        // Get the ciphersuite from the group for HPKE configuration
        let ciphersuite = target_group_ref.ciphersuite();

        // Encrypt the GroupInfo using HPKE with the recipient's public key
        // info: context string for HPKE
        // aad: additional authenticated data (can be empty or include metadata in our case just the app name)
        let info = b"GroupInfo HPKE Encryption for External Commit";
        let aad = "agora-mls".as_bytes();

        let group_info_bytes = match group_info_out.tls_serialize_detached() {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(anyhow!("Failed to serialize GroupInfo: {e}"));
            }
        };

        let confidential_payload = (
            group_info_bytes, // We put the raw bytes in
            target_group_ref.group_id().clone(),
        );

        let confidential_bytes_final = confidential_payload
            .tls_serialize_detached()
            .context("Failed to serialize confidential payload tuple")?;

        // Use openmls_rust_crypto's HPKE implementation via OpenMlsCryptoProvider trait
        let crypto = RustCrypto::default();

        // Convert HpkePublicKey to bytes for the seal operation
        let recipient_pk_bytes = recipient_hpke_key.as_slice();

        let hpke_ciphertext = match crypto.hpke_seal(
            ciphersuite.hpke_config(),
            recipient_pk_bytes,
            info,
            aad,
            &confidential_bytes_final,
        ) {
            Ok(ct) => ct,
            Err(e) => {
                return Err(anyhow!("Failed to HPKE encrypt GroupInfo: {e}"));
            }
        };

        // Create the EncryptedGroupInfo protobuf message with separate KEM output and ciphertext
        let encrypted_group_info_proto = agora_chat::EncryptedGroupInfo {
            kem_output: hpke_ciphertext.kem_output.as_slice().to_vec(),
            ciphertext: hpke_ciphertext.ciphertext.as_slice().to_vec(),
            sender_username: self.username.clone(),
            sender_key_package: self
                .mls_key_package_bundle
                .key_package()
                .tls_serialize_detached()
                .context("Failed to serialize sender's KeyPackage")?,
        };

        // Wrap in AgoraPacket
        let agora_packet = agora_chat::AgoraPacket {
            version: agora_chat::ProtocolVersion::Mls10 as i32,
            body: Some(agora_chat::agora_packet::Body::EncryptedGroupInfo(
                encrypted_group_info_proto,
            )),
        };

        // Return the encrypted GroupInfo wrapped in AgoraPacket for transmission
        Ok(CryptoIdentityReply::EncryptedGroupInfoForExternalInvite {
            encrypted_group_info: agora_packet,
        })
    }

    /// Encrypt a message for a group
    fn handle_encrypt_message(
        &mut self,
        plaintext: Vec<u8>,
        group_name: &str,
    ) -> CryptoIdentityReply {
        // get the target group id from the groups map
        let group_id = match self.group_name_to_id.get(group_name) {
            Some(id) => id,
            None => {
                return CryptoIdentityReply::Failure(anyhow!("Current group not found"));
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

        CryptoIdentityReply::MlsMessageOut(mls_message_out)
    }

    /// Process an incoming MLS message from crypto_actor.ask(CryptoIdentityMessage::ProcessMessage { mls_message_in }) in processor.rs
    fn handle_mls_message(&mut self, mls_message_in: MlsMessageIn) -> CryptoIdentityReply {
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
                    CryptoIdentityActorError::GroupNotFound(format!("{:?}", group_id))
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

        // Handle different content types. Only ApplicationMessage and StagedCommitMessage are supported here.
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
            // We are merging staged commits because the MLS protocol uses a two-phase commit process:
            // when another group member sends a commit message (e.g., to add/remove members or update keys),
            // the client first validates and "stages" the commit to ensure it's cryptographically valid and authorized,
            // then explicitly "merges" it into our local group state to apply the changes.
            //
            // This merge operation updates the group's epoch, ratchet tree, and encryption keys to stay synchronized with other members.
            // If we skip the merge, the local state becomes stale and we won't be able to decrypt future messages from the group.
            //
            // IN THEORY!! the staged commit pattern gives us a chance to inspect changes before committing to them,
            // though in our implementation we merge immediately after successful staging since we trust the network's MLS validation.
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
            _ => {
                return CryptoIdentityReply::Failure(anyhow!("Unsupported message content type"));
            }
        };

        CryptoIdentityReply::MessageProcessed { result }
    }

    /// Handle the new user invite request
    fn handle_invite_user(
        &mut self,
        user_identity: UserIdentity,
        group_name: &str,
    ) -> Result<CryptoIdentityReply> {
        // Check if we have the user in our cache
        let key_package_in = match self.user_cache.get(&user_identity) {
            Some(kp) => kp.clone(),
            None => {
                return Err(anyhow!("User '{}' not found in cache", user_identity));
            }
        };

        // Validate the KeyPackageIn
        let validated_keypackage =
            match key_package_in.validate(&RustCrypto::default(), ProtocolVersion::Mls10) {
                Ok(vkp) => vkp,
                Err(e) => {
                    return Err(anyhow!(
                        "Invalid KeyPackage for user '{}': {}",
                        user_identity,
                        e
                    ));
                }
            };

        // Invite the member to the active group
        Ok(self.invite_new_member_to_group(validated_keypackage, group_name)?)
    }

    /// Process a received HPKE-encrypted GroupInfo to initiate an external join.
    ///
    /// This function is called by a new user who has received an invitation. It performs
    /// the following steps:
    /// 1. Decrypts the GroupInfo using the actor's own HPKE private key.
    /// 2. Deserializes the plaintext GroupInfo.
    /// 3. Creates a new MlsGroup instance from the GroupInfo.
    /// 4. Creates an external commit message.
    /// 5. Returns the commit message, which must then be broadcast to the group.
    fn handle_encrypted_group_info(
        &mut self,
        encrypted_group_info: crate::agora_chat::EncryptedGroupInfo,
    ) -> Result<CryptoIdentityReply> {
        // 1. DECRYPT THE PAYLOAD
        // ======================

        // AAD must match what the sender used.
        let aad = "agora-mls".as_bytes();

        // The info string must also match the sender's.
        let info = b"GroupInfo HPKE Encryption for External Commit";

        // Reconstruct the HpkeCiphertext struct from the separate fields
        let hpke_ciphertext = HpkeCiphertext {
            kem_output: encrypted_group_info.kem_output.clone().into(),
            ciphertext: encrypted_group_info.ciphertext.clone().into(),
        };

        // Use openmls_rust_crypto's HPKE implementation via OpenMlsCryptoProvider trait
        let crypto = RustCrypto::default();

        // Decrypt using our OWN HPKE private key from our KeyPackageBundle.
        let confidential_bytes = crypto
            .hpke_open(
                self.ciphersuite.hpke_config(),
                &hpke_ciphertext,
                self.mls_key_package_bundle.init_private_key(),
                info,
                aad,
            )
            .context("Failed to HPKE decrypt GroupInfo")?;

        // ============================
        // 2. DESERIALIZE THE GroupInfo + GroupId TUPLE
        // ============================
        // This works because:
        // TlsDeserialize is a generic trait that tls_codec (the library OpenMLS uses) provides.
        //
        // tls_codec provides an implementation of this trait for tuples (T, U) as long as T and U also implement TlsDeserialize.
        // Both VerifiableGroupInfo and GroupId implement TlsDeserialize.
        // By providing the explicit type hint (VerifiableGroupInfo, GroupId), we are telling the Rust compiler which implementation of TlsDeserialize::tls_deserialize to use.
        // The compiler sees (T, U) and correctly invokes the deserializer for the tuple.

        let (group_info_bytes, group_id): (Vec<u8>, GroupId) =
            Deserialize::tls_deserialize(&mut &confidential_bytes[..])
                .context("Failed to deserialize confidential payload tuple")?;

        let deserialized_mls_message_in = MlsMessageIn::tls_deserialize(&mut &group_info_bytes[..])
            .context("Failed to deserialize MlsMessageIn from decrypted payload")?;

        let verifiable_group_info = match deserialized_mls_message_in.extract() {
            MlsMessageBodyIn::GroupInfo(group_info) => group_info,
            _ => {
                return Err(anyhow!(
                    "Expected GroupInfo in MlsMessageIn, got different message type"
                ));
            }
        };

        let (mut new_group_to_join, commit_message_bundle) = MlsGroup::external_commit_builder()
            .with_aad(group_id.to_vec())
            .build_group(
                self.crypto_provider.as_ref(),
                verifiable_group_info,
                self.credential_with_key.clone(),
            )
            .context("error building group")?
            .load_psks(self.crypto_provider.as_ref().storage())
            .context("error loading psks")?
            .build(
                self.crypto_provider.rand(),
                self.crypto_provider.crypto(),
                self.signature_keypair.as_ref(),
                |_| true,
            )
            .context("error building external commit")?
            .finalize(self.crypto_provider.as_ref())
            .context("error finalizing external commit")?;

        // Extract the commit message that we will broadcast
        let (commit_message, _welcome, _group_info) = commit_message_bundle.into_contents();

        // Merge the pending commit to finalize our addition to the group
        // This applies the external commit to our local group state
        new_group_to_join
            .merge_pending_commit(self.crypto_provider.as_ref())
            .context("Failed to self merge pending external commit")?;

        // Extract group name
        let group_name = match Self::extract_group_name(&new_group_to_join) {
            Some(name) => name,
            None => "Unnamed Group".to_string(), // I think we should fail here instead
        };

        // =============================
        let group_id = new_group_to_join.group_id().clone();
        self.groups.insert(group_id.clone(), new_group_to_join);

        // Add the group name to self.group_name_to_id
        self.group_name_to_id.insert(group_name.clone(), group_id);

        Ok(CryptoIdentityReply::MlsMessageOut(commit_message))
    }

    fn create_user_announcement(&mut self) -> Result<CryptoIdentityReply> {
        // Serialize the KeyPackage to bytes
        let key_package_bytes = self
            .mls_key_package_bundle
            .key_package()
            .tls_serialize_detached()
            .context("Failed to serialize key package")?;
        let user_announcement = crate::agora_chat::UserAnnouncement {
            username: self.username.clone(),
            tls_serialized_key_package: key_package_bytes,
        };

        let proto_message = crate::agora_chat::AgoraPacket {
            version: crate::agora_chat::ProtocolVersion::Mls10 as i32,
            body: Some(crate::agora_chat::agora_packet::Body::UserAnnouncement(
                user_announcement,
            )),
        };

        Ok(CryptoIdentityReply::UserAnnouncement(proto_message))
    }

    /// Handle new user announcement
    fn handle_new_user_announcement(
        &mut self,
        user_announcement: UserAnnouncement,
    ) -> Result<CryptoIdentityReply> {
        // Deserialize the KeyPackage from the announcement
        let key_package_in =
            KeyPackageIn::tls_deserialize(&mut &user_announcement.tls_serialized_key_package[..])
                .context("Failed to deserialize KeyPackage from announcement")?;

        let user_identity =
            UserIdentity::from_key_package(&user_announcement.username, &key_package_in)
                .context("Failed to create UserIdentity from KeyPackage")?;

        // Store in user cache
        self.user_cache.insert(user_identity, key_package_in);
        Ok(CryptoIdentityReply::Success)
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
        let mls_key_package_bundle = KeyPackage::builder()
            .build(
                ciphersuite,
                provider.as_ref(),
                &signature_keypair,
                credential_with_key.clone(),
            )
            .context("Failed to create MLS key package")?;

        Ok(CryptoIdentityActor {
            ciphersuite,
            credential_with_key,
            mls_key_package_bundle,
            username: display_name.to_string(),
            signature_keypair: Arc::new(signature_keypair),
            crypto_provider: provider,
            groups: HashMap::new(),
            user_cache: HashMap::new(),
            group_name_to_id: HashMap::new(),
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
            shellexpand::tilde(key_path.to_str().context("Expected to find the key file")?)
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

use std::fmt;

use crate::{
    agora_chat::{AgoraPacket, UserAnnouncement},
    error::CryptoIdentityActorError,
};

/// User identity combining username and key fingerprint
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserIdentity {
    pub username: String,
    pub fingerprint: String,
}

impl UserIdentity {
    /// Create from username and KeyPackageIn
    pub fn from_key_package(username: &str, key_package: &KeyPackageIn) -> anyhow::Result<Self> {
        let signature_key = key_package.unverified_credential().signature_key;
        let fingerprint = hex::encode(&signature_key.as_slice()[..4]);
        Ok(Self {
            username: username.to_owned(),
            fingerprint,
        })
    }
}

impl std::str::FromStr for UserIdentity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('@').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid identity format. Expected 'username@fingerprint', got '{}'",
                s
            ));
        }
        Ok(Self {
            username: parts[0].to_string(),
            fingerprint: parts[1].to_string(),
        })
    }
}

// Standard Display trait
impl fmt::Display for UserIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.username, self.fingerprint)
    }
}
