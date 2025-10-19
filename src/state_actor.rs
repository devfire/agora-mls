use openmls_rust_crypto::RustCrypto;
use std::{collections::HashMap, vec};

use prost::Message;
use tracing::{debug, error};

use kameo::{message::Message as KameoMessage, prelude::*};
use openmls::prelude::{tls_codec::Deserialize, *};

use anyhow::anyhow;

use crate::{
    command::Command,
    crypto_identity_actor::{CryptoIdentityActor, CryptoIdentityMessage, CryptoIdentityReply},
    protobuf_wrapper::{ProtoMlsMessageIn, ProtoMlsMessageOut},
    safety_number::{SafetyNumber, generate_safety_number},
};

#[derive(Actor)]
pub struct StateActor {
    crypto_identity: ActorRef<CryptoIdentityActor>, // Combined identity and MLS actor
    key_packages: HashMap<String, KeyPackageIn>,    // composite_key -> KeyPackageIn cache
    // group_name -> GroupId. We need this because humans refer to groups by name but MlsGroup is keyed by GroupId in CryptoIdentityActor
    groups: HashMap<String, GroupId>,
}

pub enum StateActorMessage {
    Command(Command),
    Encrypt(String),
    Decrypt(ProtoMlsMessageIn),
}

#[derive(Reply)]
pub enum StateActorReply {
    Groups(Option<Vec<String>>),    // List of group names, if any
    StateActorError(anyhow::Error), // Err(StateActorError) for failure
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
                // Return the error to the caller.
                StateActorReply::StateActorError(anyhow!("StateActor error: {e}"))
            }
        }
    }
}

impl StateActor {
    /// Extract a short fingerprint from a KeyPackageIn's credential
    /// Returns the first 8 characters of the hex-encoded public key
    fn get_key_fingerprint_from_in(key_package_in: &KeyPackageIn) -> anyhow::Result<String> {
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
    ) -> anyhow::Result<String> {
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
    pub fn parse_composite_key(composite_key: &str) -> anyhow::Result<(String, String)> {
        let parts: Vec<&str> = composite_key.split('@').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid composite key format"));
        }
        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    async fn handle_state_actor_message(
        &mut self,
        msg: StateActorMessage,
    ) -> anyhow::Result<StateActorReply> {
        match msg {
            StateActorMessage::Command(command) => {
                match command {
                    Command::Create { name } => {
                        // Delegate to CryptoIdentityActor - all MLS operations happen there
                        match self
                            .crypto_identity
                            .ask(CryptoIdentityMessage::CreateGroup {
                                group_name: name.clone(),
                            })
                            .await
                        {
                            Ok(CryptoIdentityReply::GroupCreated(group_id)) => {
                                // Update the HashMap for future reference like during group activation
                                self.groups.insert(name, group_id);
                                debug!("Successfully created MLS group '{}'", name);
                                Ok(StateActorReply::Success(
                                    "Successfully created MLS group".to_string(),
                                ))
                            }
                            Ok(CryptoIdentityReply::Failure(message)) => {
                                Err(anyhow!("Failed to create group: {}", message))
                            }
                            Ok(_) => unreachable!("Unexpected reply type from CryptoIdentityActor"),
                            Err(e) => {
                                error!("Failed to create group: {}", e);
                                Err(anyhow!("Group creation failed: {e}"))
                            }
                        }
                    }

                    Command::Safety => {
                        // Get the verifying key from the crypto identity actor
                        let verifying_key = match self
                            .crypto_identity
                            .ask(CryptoIdentityMessage::GetIdentity)
                            .await
                        {
                            Ok(CryptoIdentityReply::Identity { verifying_key, .. }) => {
                                verifying_key
                            }
                            Ok(_) => {
                                unreachable!("Unexpected reply type from CryptoIdentityActor");
                            }
                            Err(e) => {
                                error!("Failed to get verifying key from CryptoIdentityActor: {e}");
                                return Err(anyhow!("Failed to get verifying key"));
                            }
                        };

                        // Generate the safety number for the user
                        match generate_safety_number(&verifying_key) {
                            Ok(safety_number) => {
                                debug!("Your safety number is: {safety_number}");
                                Ok(StateActorReply::SafetyNumber(safety_number))
                            }
                            Err(_) => Err(anyhow!("Failed to generate safety number")),
                        }
                    }
                    Command::Group { name: group_name } => {
                        // First, convert group name to GroupId
                        let group_id = match self.groups.get(&group_name) {
                            Some(gid) => gid.clone(),
                            None => return Err(anyhow!("Group {group_name} not found")),
                        };
                        // User wants to set the active group - delegate to CryptoIdentityActor
                        match self
                            .crypto_identity
                            .ask(CryptoIdentityMessage::SetActiveGroup(group_id))
                            .await
                        {
                            Ok(CryptoIdentityReply::Success) => {
                                Ok(StateActorReply::Success("Group set as active.".to_string()))
                            }
                            Ok(CryptoIdentityReply::Failure { .. }) => {
                                Err(anyhow!("Failed to set active group"))
                            }
                            Ok(_) => unreachable!("Unexpected reply type from CryptoIdentityActor"),
                            Err(e) => {
                                error!("Failed to set active group: {}", e);
                                Err(anyhow!("Failed to send message to CryptoIdentityActor"))
                            }
                        }
                    }
                    Command::Announce => {
                        let crypto_identity = self
                            .crypto_identity
                            .ask(CryptoIdentityMessage::GetMlsIdentity)
                            .await?;

                        // Serialize KeyPackage directly (not wrapped in MlsMessageOut)
                        use openmls::prelude::tls_codec::Serialize;
                        let key_package_bytes = mls_key_package
                            .key_package()
                            .tls_serialize_detached()
                            .map_err(|_e| StateActorError::EncryptionFailed)?;

                        // Create UserAnnouncement protobuf (consistent with try_into pattern)
                        let proto_message =
                            Self::create_user_announcement(handle, key_package_bytes);

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
                        // Check if the user being invited is known
                        let key_package_in = match self.key_packages.get(&nick) {
                            Some(kp) => kp,
                            None => return Err(StateActorError::UserNotFound),
                        };

                        // Get active group name
                        let CryptoIdentityReply::ActiveGroup {
                            group_id: group_name,
                        } = self
                            .crypto_identity
                            .ask(CryptoIdentityMessage::GetActiveGroup)
                            .await?
                        else {
                            return Err(StateActorError::EncryptionFailed);
                        };

                        let current_group_name =
                            group_name.ok_or(StateActorError::NoActiveGroup)?;

                        // Validate the KeyPackageIn to get a KeyPackage
                        let validated_key_package = key_package_in
                            .clone()
                            .validate(&RustCrypto::default(), ProtocolVersion::Mls10)?;

                        // Delegate to CryptoIdentityActor - add member operation happens there
                        match self
                            .crypto_identity
                            .ask(CryptoIdentityMessage::AddMember {
                                group_name: current_group_name,
                                key_package: validated_key_package,
                            })
                            .await
                        {
                            Ok(CryptoIdentityReply::MemberAdded {
                                commit, welcome, ..
                            }) => {
                                debug!("Successfully added member to group");
                                // Convert to protobuf messages for network transmission
                                let reply_vec = vec![commit.try_into()?, welcome.try_into()?];
                                Ok(StateActorReply::MlsMessageOut(reply_vec))
                            }
                            Ok(CryptoIdentityReply::Failure { message }) => {
                                error!("Failed to add member: {}", message);
                                Err(StateActorError::EncryptionFailed)
                            }
                            Ok(_) => Err(StateActorError::EncryptionFailed),
                            Err(e) => {
                                error!("Failed to add member: {}", e);
                                Err(StateActorError::EncryptionFailed)
                            }
                        }
                    }

                    Command::Groups => {
                        // Delegate to CryptoIdentityActor - groups are managed there now
                        match self
                            .crypto_identity
                            .ask(CryptoIdentityMessage::ListGroups)
                            .await
                        {
                            Ok(CryptoIdentityReply::Groups { groups }) => {
                                if groups.is_empty() {
                                    Ok(StateActorReply::Groups(None))
                                } else {
                                    Ok(StateActorReply::Groups(Some(groups)))
                                }
                            }
                            Ok(_) => Err(StateActorError::EncryptionFailed),
                            Err(e) => {
                                error!("Failed to list groups: {}", e);
                                Err(StateActorError::EncryptionFailed)
                            }
                        }
                    }
                    _ => Err(StateActorError::NotImplemented),
                }
            }
            StateActorMessage::Encrypt(plaintext_payload) => {
                debug!("Encrypting message for transport");

                // Get active group name from CryptoIdentityActor
                let CryptoIdentityReply::ActiveGroup {
                    group_id: group_name,
                } = self
                    .crypto_identity
                    .ask(CryptoIdentityMessage::GetActiveGroup)
                    .await?
                else {
                    return Err(StateActorError::EncryptionFailed);
                };

                let active_group_name = group_name.ok_or(StateActorError::NoActiveGroup)?;

                // Delegate encryption to CryptoIdentityActor
                match self
                    .crypto_identity
                    .ask(CryptoIdentityMessage::EncryptMessage {
                        group_name: active_group_name,
                        plaintext: plaintext_payload.encode_to_vec(),
                    })
                    .await
                {
                    Ok(CryptoIdentityReply::MessageEncrypted { ciphertext }) => {
                        let protobuf_message: ProtoMlsMessageOut = ciphertext.try_into()?;
                        Ok(StateActorReply::MlsMessageOut(vec![protobuf_message]))
                    }
                    Ok(CryptoIdentityReply::Failure { message }) => {
                        error!("Failed to encrypt message: {}", message);
                        Err(StateActorError::EncryptionFailed)
                    }
                    Ok(_) => Err(StateActorError::EncryptionFailed),
                    Err(e) => {
                        error!("Failed to encrypt message: {}", e);
                        Err(StateActorError::EncryptionFailed)
                    }
                }
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
                        // let CryptoIdentityReply::MlsIdentity {
                        //     crypto_provider, ..
                        // } = self
                        //     .crypto_identity
                        //     .ask(CryptoIdentityMessage::GetMlsIdentity)
                        //     .await?
                        // else {
                        //     return Err(StateActorError::EncryptionFailed);
                        // };

                        // let active_group_name = match self
                        //     .crypto_identity
                        //     .ask(CryptoIdentityMessage::GetActiveGroup)
                        //     .await
                        // {
                        //     Ok(CryptoIdentityReply::ActiveGroup { group_name }) => {
                        //         group_name.ok_or(StateActorError::NoActiveGroup)
                        //     }
                        //     Err(e) => {
                        //         error!("Failed to get active group: {}", e);
                        //         Err(StateActorError::NoActiveGroup)
                        //     }
                        //     Ok(_) => unreachable!("WTf lol"),
                        // }?;

                        let protocol_message = ProtocolMessage::from(msg);
                        let processed_message = mls_group_ref
                            .process_message(crypto_provider.as_ref(), protocol_message)?;

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
                                    crypto_provider.as_ref(),
                                    *staged_commit,
                                )?;
                                Ok(StateActorReply::Success(
                                    "Staged commit received.".to_string(),
                                ))
                            }
                        }
                    }
                    MlsMessageBodyIn::PrivateMessage(msg) => {
                        let CryptoIdentityReply::MlsIdentity {
                            crypto_provider, ..
                        } = self
                            .crypto_identity
                            .ask(CryptoIdentityMessage::GetMlsIdentity)
                            .await?
                        else {
                            return Err(StateActorError::EncryptionFailed);
                        };

                        let protocol_message = ProtocolMessage::from(msg);

                        let active_group_name = self
                            .active_group
                            .as_ref()
                            .ok_or(StateActorError::NoActiveGroup)?;
                        let mls_group_ref = self
                            .groups
                            .get_mut(active_group_name)
                            .ok_or(StateActorError::GroupNotFound)?;
                        let processed_message = mls_group_ref
                            .process_message(crypto_provider.as_ref(), protocol_message)?;

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
                                    crypto_provider.as_ref(),
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
                        let CryptoIdentityReply::MlsIdentity {
                            crypto_provider,
                            ciphersuite,
                            ..
                        } = self
                            .crypto_identity
                            .ask(CryptoIdentityMessage::GetMlsIdentity)
                            .await?
                        else {
                            return Err(StateActorError::EncryptionFailed);
                        };

                        debug!("Retrieved MLS identity, ciphersuite: {:?}", ciphersuite);

                        // Create configuration for joining a group
                        let mls_group_join_config = MlsGroupJoinConfig::default();

                        // FIXED: Use the shared crypto provider that has our stored keys
                        let provider = crypto_provider.as_ref();
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
    pub fn new(crypto_identity: ActorRef<CryptoIdentityActor>) -> Self {
        Self {
            groups: HashMap::new(),
            active_group: None,
            crypto_identity,
            key_packages: HashMap::new(),
        }
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
