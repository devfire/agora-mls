use openmls_rust_crypto::RustCrypto;
use std::{collections::HashMap, vec};

use prost::Message;
use tracing::{debug, error};

use kameo::{message::Message as KameoMessage, prelude::*};
use openmls::prelude::{tls_codec::Deserialize, *};

use crate::{
    command::Command,
    error::StateActorError,
    identity_actor::{IdentityActor, IdentityActorMsg},
    openmls_actor::{OpenMlsActor, OpenMlsIdentityRequest},
    protobuf_wrapper::{ProtoMlsMessageIn, ProtoMlsMessageOut},
    safety_number::{SafetyNumber, generate_safety_number},
};

#[derive(Actor)]
pub struct StateActor {
    // membership: HashMap<VerifyingKey, Vec<Group>>, // Maps handle to channels
    groups: HashMap<String, MlsGroup>, // Maps group name to MlsGroup
    active_group: Option<String>,      // Currently active group name, if any
    identity_actor: ActorRef<IdentityActor>,
    mls_identity_actor: ActorRef<OpenMlsActor>,
    key_packages: HashMap<String, KeyPackageIn>, // composite_key -> KeyPackageIn cache
}

pub enum StateActorMessage {
    Command(Command),
    Encrypt(String),
    Decrypt(ProtoMlsMessageIn),
}

#[derive(Reply)]
pub enum StateActorReply {
    Groups(Option<Vec<String>>),      // List of group names, if any
    StateActorError(StateActorError), // Err(StateActorError) for failure
    ChatHandle(String),
    SafetyNumber(SafetyNumber),
    ActiveGroup(Option<String>), // Currently active group, if any
    MlsMessageOut(Vec<ProtoMlsMessageOut>),
    DecryptedMessage(String),
    Users(Option<Vec<String>>),
    Success(String),
}

impl KameoMessage<StateActorMessage> for StateActor {
    // https://docs.page/tqwewe/kameo/core-concepts/replies
    type Reply = StateActorReply;

    async fn handle(
        &mut self,
        msg: StateActorMessage,
        _ctx: &mut kameo::message::Context<Self, StateActorReply>,
    ) -> Self::Reply {
        // Logic to process the message and generate a reply
        match self.handle_state_actor_message(msg).await {
            Ok(reply) => reply,
            Err(e) => {
                // Return the categorized error to the caller.
                StateActorReply::StateActorError(e)
            }
        }
    }
}

impl StateActor {
    /// Extract a short fingerprint from a KeyPackageIn's credential
    /// Returns the first 8 characters of the hex-encoded public key
    fn get_key_fingerprint_from_in(
        key_package_in: &KeyPackageIn,
    ) -> Result<String, StateActorError> {
        // Use the public API to get the signature key
        let signature_key = key_package_in.unverified_credential().signature_key;
        let public_key_bytes = signature_key.as_slice();

        // Create a short hex fingerprint (first 8 chars = 4 bytes)
        let fingerprint = hex::encode(&public_key_bytes[..4]);

        Ok(fingerprint)
    }

    /// Build a composite key from username and KeyPackageIn
    fn build_composite_key_from_in(
        username: &str,
        key_package_in: &KeyPackageIn,
    ) -> Result<String, StateActorError> {
        let fingerprint = Self::get_key_fingerprint_from_in(key_package_in)?;
        Ok(format!("{}@{}", username, fingerprint))
    }

    /// List all composite keys matching a username prefix
    /// Example: list_keys_for_username("john") returns ["john@a1b2c3d4", "john@9f8e7d6c"]
    pub fn list_keys_for_username(&self, username: &str) -> Vec<String> {
        let prefix = format!("{}@", username);
        self.key_packages
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect()
    }

    /// Parse a composite key into username and fingerprint
    pub fn parse_composite_key(composite_key: &str) -> Result<(String, String), StateActorError> {
        let parts: Vec<&str> = composite_key.split('@').collect();
        if parts.len() != 2 {
            return Err(StateActorError::InvalidCompositeKey);
        }
        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    async fn handle_state_actor_message(
        &mut self,
        msg: StateActorMessage,
    ) -> Result<StateActorReply, StateActorError> {
        match msg {
            StateActorMessage::Command(command) => {
                match command {
                    Command::Create { name } => {
                        self.create_mls_group(&name).await?;

                        debug!("Successfully created MLS group '{}'", name);
                        Ok(StateActorReply::Success(
                            "Successfully created MLS group".to_string(),
                        ))
                    }

                    Command::Safety => {
                        // First, let's get the verifyingkey from the identity actor
                        let verifying_key = match self
                            .identity_actor
                            .ask(crate::identity_actor::IdentityActorMsg {
                                handle_update: None,
                            })
                            .await
                        {
                            Ok(reply) => reply.verifying_key,
                            Err(e) => {
                                error!("Failed to get verifying key from IdentityActor: {e}");
                                return Err(StateActorError::MissingVerifyingKey);
                            }
                        };

                        // Generate the safety number for the user
                        match generate_safety_number(&verifying_key) {
                            Ok(safety_number) => {
                                debug!("Your safety number is: {safety_number}");
                                Ok(StateActorReply::SafetyNumber(safety_number))
                            }
                            Err(_) => Err(StateActorError::SafetyNumberGenerationFailed),
                        }
                    }
                    Command::Group { name: group_name } => {
                        if let Some(name) = group_name {
                            // User wants to set the active group
                            if self.groups.contains_key(&name) {
                                self.active_group = Some(name);
                                Ok(StateActorReply::Success("Group found.".to_string()))
                            } else {
                                Err(StateActorError::GroupNotFound)
                            }
                        } else {
                            // User wants to get the current active group
                            if let Some(active_name) = &self.active_group {
                                Ok(StateActorReply::ActiveGroup(Some(active_name.clone())))
                            } else {
                                // This should not happen; active_group should always be in groups
                                Ok(StateActorReply::ActiveGroup(None))
                            }
                        }
                    }
                    Command::Announce => {
                        let mls_identity =
                            self.mls_identity_actor.ask(OpenMlsIdentityRequest).await?;

                        // Get username from identity actor
                        let identity_reply = self
                            .identity_actor
                            .ask(IdentityActorMsg {
                                handle_update: None,
                            })
                            .await?;

                        // Serialize KeyPackage directly (not wrapped in MlsMessageOut)
                        use openmls::prelude::tls_codec::Serialize;
                        let key_package_bytes = mls_identity
                            .mls_key_package
                            .key_package()
                            .tls_serialize_detached()
                            .map_err(|_e| StateActorError::EncryptionFailed)?;

                        // Create UserAnnouncement protobuf (consistent with try_into pattern)
                        let proto_message = Self::create_user_announcement(
                            identity_reply.handle,
                            key_package_bytes,
                        );

                        // a quick vec to be shipped back
                        let reply_vec = vec![proto_message];

                        // Return wrapped message for network multicast
                        Ok(StateActorReply::MlsMessageOut(reply_vec))
                    }

                    Command::Users => {
                        // get they hashmap keys as the Vec
                        let known_users: Vec<String> = self.key_packages.keys().cloned().collect();
                        Ok(StateActorReply::Users(Some(known_users)))
                    }

                    Command::Invite { nick, password: _p } => {
                        let mls_identity =
                            self.mls_identity_actor.ask(OpenMlsIdentityRequest).await?;

                        // first check if the user being invited is known.
                        // If not, we bail - no user, no key package - no invite.
                        let key_package_in = match self.key_packages.get(&nick) {
                            Some(key_package_in) => key_package_in,
                            None => {
                                return Err(StateActorError::UserNotFound);
                            }
                        };

                        // verified the user, let's get the current group name
                        let current_group_name = match &self.active_group {
                            Some(g) => g,
                            None => {
                                return Err(StateActorError::NoActiveGroup);
                            }
                        };

                        // now we get the MlsGroup data for the group
                        let current_mls_group_details =
                            match self.groups.get_mut(current_group_name) {
                                Some(mls_group) => mls_group,
                                None => return Err(StateActorError::GroupNotFound),
                            };

                        // Validate the KeyPackageIn to get a KeyPackage
                        let validated_key_package = key_package_in
                            .clone()
                            .validate(&RustCrypto::default(), ProtocolVersion::Mls10)?;

                        // guess we got the user, let's invite them
                        let (mls_message_out, welcome, _group_info) = current_mls_group_details
                            .add_members(
                                mls_identity.crypto_provider.as_ref(),
                                &*mls_identity.signature_keypair,
                                core::slice::from_ref(&validated_key_package),
                            )?;

                        // CRITICAL: Merge the pending commit so Alice's group advances to the new epoch
                        current_mls_group_details
                            .merge_pending_commit(mls_identity.crypto_provider.as_ref())?;
                        debug!(
                            "Merged pending commit after adding members - group now at epoch {}",
                            current_mls_group_details.epoch()
                        );

                        let reply_vec = vec![mls_message_out.try_into()?, welcome.try_into()?];
                        // Return wrapped message for network multicast
                        Ok(StateActorReply::MlsMessageOut(reply_vec))
                        // Ok(StateActorReply::Success("User invited".to_string()))
                    }

                    Command::Groups => {
                        let groups: Vec<String> = self.groups.keys().cloned().collect();

                        Ok(StateActorReply::Groups(Some(groups)))
                    }
                    _ => Err(StateActorError::NotImplemented),
                }
            }
            StateActorMessage::Encrypt(plaintext_payload) => {
                debug!("Encrypting message for transport");

                let mls_identity = self.mls_identity_actor.ask(OpenMlsIdentityRequest).await?;

                // Let's get the active group name first
                let active_group_name = self
                    .active_group
                    .as_ref()
                    .ok_or(StateActorError::NoActiveGroup)?;
                let mls_group_ref = self
                    .groups
                    .get_mut(active_group_name)
                    .ok_or(StateActorError::GroupNotFound)?;

                // OK, let's try to encrypt the message
                let mls_msg_out = mls_group_ref.create_message(
                    mls_identity.crypto_provider.as_ref(),
                    &*mls_identity.signature_keypair,
                    plaintext_payload.encode_to_vec().as_slice(),
                )?;

                let protobuf_message: ProtoMlsMessageOut = mls_msg_out.try_into()?;
                // a quick vec to be shipped back
                let reply_vec = vec![protobuf_message];

                // Return wrapped message for network multicast
                Ok(StateActorReply::MlsMessageOut(reply_vec))
            }
            StateActorMessage::Decrypt(chat_packet) => {
                // Check if this is a UserAnnouncement at the protobuf level first
                if let Some(crate::agora_chat::mls_message_out::Body::UserAnnouncement(
                    user_announcement,
                )) = &chat_packet.0.body
                {
                    debug!(
                        "Received UserAnnouncement from: {}",
                        user_announcement.username
                    );

                    // Deserialize the KeyPackage from the announcement
                    let key_package_in = KeyPackageIn::tls_deserialize(
                        &mut &user_announcement.tls_serialized_key_package[..],
                    )?;

                    // For now, we'll work with KeyPackageIn directly
                    // Validation happens when users are added to groups
                    // Build composite key (username@fingerprint)
                    let composite_key = Self::build_composite_key_from_in(
                        &user_announcement.username,
                        &key_package_in,
                    )?;

                    // Check if this is a duplicate announcement
                    if self.key_packages.contains_key(&composite_key) {
                        debug!(
                            "Received duplicate announcement for: {} (overwriting)",
                            composite_key
                        );
                    } else {
                        debug!("Caching new KeyPackage for: {}", composite_key);
                    }

                    // Store with composite key
                    self.key_packages.insert(composite_key, key_package_in);

                    return Ok(StateActorReply::Success(
                        "Received a new user announcement.".to_string(),
                    ));
                }

                // For other message types, convert to MlsMessageIn
                let proto_in: MlsMessageIn = chat_packet.try_into()?;

                match proto_in.extract() {
                    MlsMessageBodyIn::PublicMessage(msg) => {
                        let mls_identity =
                            self.mls_identity_actor.ask(OpenMlsIdentityRequest).await?;

                        let active_group_name = self
                            .active_group
                            .as_ref()
                            .ok_or(StateActorError::NoActiveGroup)?;
                        let mls_group_ref = self
                            .groups
                            .get_mut(active_group_name)
                            .ok_or(StateActorError::GroupNotFound)?;
                        let protocol_message = ProtocolMessage::from(msg);
                        let processed_message = mls_group_ref.process_message(
                            mls_identity.crypto_provider.as_ref(),
                            protocol_message,
                        )?;

                        match processed_message.into_content() {
                            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                                let decrypted_text = String::from_utf8(app_msg.into_bytes())?;
                                debug!("Successfully decrypted message: {}", decrypted_text);
                                Ok(StateActorReply::DecryptedMessage(decrypted_text))
                            }
                            ProcessedMessageContent::ProposalMessage(_) => {
                                debug!("Received proposal message");
                                Err(StateActorError::NotImplemented)
                            }
                            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                                debug!("Received external join proposal");
                                Err(StateActorError::NotImplemented)
                            }
                            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                                debug!("Received staged commit - merging changes");
                                mls_group_ref.merge_staged_commit(
                                    mls_identity.crypto_provider.as_ref(),
                                    *staged_commit,
                                )?;
                                Ok(StateActorReply::Success(
                                    "Staged commit received.".to_string(),
                                ))
                            }
                        }
                    }
                    MlsMessageBodyIn::PrivateMessage(msg) => {
                        let mls_identity =
                            self.mls_identity_actor.ask(OpenMlsIdentityRequest).await?;

                        let protocol_message = ProtocolMessage::from(msg);

                        let active_group_name = self
                            .active_group
                            .as_ref()
                            .ok_or(StateActorError::NoActiveGroup)?;
                        let mls_group_ref = self
                            .groups
                            .get_mut(active_group_name)
                            .ok_or(StateActorError::GroupNotFound)?;
                        let processed_message = mls_group_ref.process_message(
                            mls_identity.crypto_provider.as_ref(),
                            protocol_message,
                        )?;

                        match processed_message.into_content() {
                            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                                let decrypted_text = String::from_utf8(app_msg.into_bytes())?;
                                debug!("Successfully decrypted message: {}", decrypted_text);
                                Ok(StateActorReply::DecryptedMessage(decrypted_text))
                            }
                            ProcessedMessageContent::ProposalMessage(_) => {
                                debug!("Received proposal message");
                                Err(StateActorError::NotImplemented)
                            }
                            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                                debug!("Received external join proposal");
                                Err(StateActorError::NotImplemented)
                            }
                            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                                debug!("Received staged commit - merging changes");
                                mls_group_ref.merge_staged_commit(
                                    mls_identity.crypto_provider.as_ref(),
                                    *staged_commit,
                                )?;
                                Ok(StateActorReply::Success(
                                    "Staged commit received.".to_string(),
                                ))
                            }
                        }
                    }

                    MlsMessageBodyIn::Welcome(welcome) => {
                        debug!("Received Welcome message - processing group join");

                        // Get MLS identity to access the shared crypto provider
                        let mls_identity =
                            self.mls_identity_actor.ask(OpenMlsIdentityRequest).await?;

                        debug!(
                            "Retrieved MLS identity, ciphersuite: {:?}",
                            mls_identity.ciphersuite
                        );

                        // Create configuration for joining a group
                        let mls_group_join_config = MlsGroupJoinConfig::default();

                        // FIXED: Use the shared crypto provider that has our stored keys
                        let provider = mls_identity.crypto_provider.as_ref();
                        debug!("Using shared crypto provider with stored keys");

                        // Stage the Welcome message first
                        debug!("Attempting to stage Welcome message...");
                        let staged_welcome = match StagedWelcome::new_from_welcome(
                            provider,
                            &mls_group_join_config,
                            welcome,
                            None, // ratchet_tree - typically not needed for basic joins
                        ) {
                            Ok(sw) => {
                                debug!("✓ Successfully staged Welcome message");
                                sw
                            }
                            Err(e) => {
                                error!(
                                    "✗ Failed to stage Welcome message with shared provider: {:?}",
                                    e
                                );
                                error!("Error type: {}", std::any::type_name_of_val(&e));
                                return Err(e.into());
                            }
                        };

                        // Convert staged welcome into an MlsGroup
                        let mls_group = staged_welcome.into_group(provider)?;

                        // Extract group name from extensions, or generate from group ID if not found
                        let group_name = if let Some(name) = Self::get_group_name(&mls_group) {
                            debug!("Successfully extracted group name {name}");
                            name
                        } else {
                            return Err(StateActorError::GroupNotFound);
                        };

                        debug!("Successfully joined group: {}", group_name);

                        // Store the group in our groups map
                        self.groups.insert(group_name.clone(), mls_group);

                        // Set as active group
                        self.active_group = Some(group_name.clone());

                        Ok(StateActorReply::Success(format!(
                            "Successfully joined group: {}",
                            group_name
                        )))
                    }
                    _ => Err(StateActorError::InvalidReceivedMessage),
                }
            }
        }
    }

    /// Extract group name from MlsGroup extensions
    fn get_group_name(group: &MlsGroup) -> Option<String> {
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

    /// Helper method to create a UserAnnouncement protobuf message
    fn create_user_announcement(
        username: String,
        key_package_bytes: Vec<u8>,
    ) -> ProtoMlsMessageOut {
        let user_announcement = crate::agora_chat::UserAnnouncement {
            username,
            tls_serialized_key_package: key_package_bytes,
        };

        let proto_message = crate::agora_chat::MlsMessageOut {
            version: crate::agora_chat::ProtocolVersion::Mls10 as i32,
            body: Some(crate::agora_chat::mls_message_out::Body::UserAnnouncement(
                user_announcement,
            )),
        };

        ProtoMlsMessageOut(proto_message)
    }
}
impl StateActor {
    pub fn new(
        identity_actor: ActorRef<IdentityActor>,
        mls_identity_actor: ActorRef<OpenMlsActor>,
    ) -> Self {
        Self {
            groups: HashMap::new(),
            active_group: None,
            identity_actor,
            mls_identity_actor,
            key_packages: HashMap::new(),
        }
    }

    async fn create_mls_group(&mut self, group_name: &str) -> anyhow::Result<()> {
        const GROUP_NAME_EXTENSION_ID: u16 = 13;
        let mls_identity = self.mls_identity_actor.ask(OpenMlsIdentityRequest).await?;

        // 1. Define your custom group name as bytes
        let group_name_bytes = group_name.as_bytes();
        // 1. Wrap the raw bytes in the `UnknownExtension` struct.
        let unknown_ext_data = UnknownExtension(group_name_bytes.to_vec());

        // 2. Pass BOTH the type and the struct to the `Extension::Unknown` variant.
        let group_name_extension = Extension::Unknown(
            ExtensionType::from(GROUP_NAME_EXTENSION_ID).into(),
            unknown_ext_data,
        );

        // 3. Continue with the configuration.
        let extensions = Extensions::single(group_name_extension);

        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(mls_identity.ciphersuite)
            .with_group_context_extensions(extensions)?
            .use_ratchet_tree_extension(true) // Include ratchet tree in Welcome messages
            .build();

        // Create the group with default configuration
        let group = openmls::group::MlsGroup::new(
            &openmls_rust_crypto::OpenMlsRustCrypto::default(),
            &*mls_identity.signature_keypair,
            &mls_group_create_config,
            mls_identity.credential_with_key,
        )?;

        // Add the group to the HashMap
        self.groups.insert(group_name.to_owned(), group);

        // Set the active group appropriately
        self.active_group = Some(group_name.to_owned());

        Ok(())
    }
}

/// Test helper to demonstrate the composite key functionality
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_composite_key() {
        let (username, fingerprint) = StateActor::parse_composite_key("alice@9f8e7d6c").unwrap();
        assert_eq!(username, "alice");
        assert_eq!(fingerprint, "9f8e7d6c");

        // Test invalid format
        assert!(StateActor::parse_composite_key("alice").is_err()); // No @ at all
        assert!(StateActor::parse_composite_key("alice@@9f8e7d6c").is_err()); // Multiple @
        assert!(StateActor::parse_composite_key("9f8e7d6c").is_err()); // No @ at all (just fingerprint)
        assert!(StateActor::parse_composite_key("").is_err()); // Empty string
    }
}
