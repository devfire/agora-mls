use std::collections::HashMap;

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
    key_packages: HashMap<String, KeyPackageIn>, // username -> KeyPackageIn cache
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
    MlsMessageOut(ProtoMlsMessageOut),
    DecryptedMessage(String),
    Success,
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
                        Ok(StateActorReply::Success)
                    }
                    Command::Nick { nickname } => {
                        if let Some(nick) = nickname {
                            self.identity_actor
                                .tell(IdentityActorMsg {
                                    handle_update: Some(nick),
                                })
                                .await?;
                            Ok(StateActorReply::Success)
                        } else {
                            let identity = self
                                .identity_actor
                                .ask(IdentityActorMsg {
                                    handle_update: None,
                                })
                                .await?;
                            Ok(StateActorReply::ChatHandle(identity.handle.clone()))
                        }
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
                                Ok(StateActorReply::Success)
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
                        let key_package_bytes = mls_identity.mls_key_package
                            .key_package()
                            .tls_serialize_detached()
                            .map_err(|_e| StateActorError::EncryptionFailed)?;

                        // Create UserAnnouncement protobuf (consistent with try_into pattern)
                        let proto_message = Self::create_user_announcement(
                            identity_reply.handle,
                            key_package_bytes,
                        );

                        // Return wrapped message for network multicast
                        Ok(StateActorReply::MlsMessageOut(proto_message))
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
                    &openmls_rust_crypto::OpenMlsRustCrypto::default(),
                    &*mls_identity.signature_keypair,
                    plaintext_payload.encode_to_vec().as_slice(),
                )?;

                let protobuf_message: ProtoMlsMessageOut = mls_msg_out.try_into()?;
                // Return the encrypted wrapped packet for network multicast
                Ok(StateActorReply::MlsMessageOut(protobuf_message))
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

                    let key_package = KeyPackageIn::tls_deserialize(
                        &mut &user_announcement.tls_serialized_key_package[..],
                    )?;

                    // Cache the KeyPackage by username
                    debug!(
                        "Caching KeyPackage for user: {}",
                        user_announcement.username
                    );
                    self.key_packages
                        .insert(user_announcement.username.clone(), key_package);

                    return Ok(StateActorReply::Success);
                }

                // For other message types, convert to MlsMessageIn
                let proto_in: MlsMessageIn = chat_packet.try_into()?;

                match proto_in.extract() {
                    MlsMessageBodyIn::PublicMessage(msg) => {
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
                            &openmls_rust_crypto::OpenMlsRustCrypto::default(),
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
                                    &openmls_rust_crypto::OpenMlsRustCrypto::default(),
                                    *staged_commit,
                                )?;
                                Ok(StateActorReply::Success)
                            }
                        }
                    }
                    MlsMessageBodyIn::PrivateMessage(msg) => {
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
                            &openmls_rust_crypto::OpenMlsRustCrypto::default(),
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
                                    &openmls_rust_crypto::OpenMlsRustCrypto::default(),
                                    *staged_commit,
                                )?;
                                Ok(StateActorReply::Success)
                            }
                        }
                    }

                    MlsMessageBodyIn::Welcome(_welcome) => {
                        debug!("Received Welcome message - processing group join");
                        // Handle Welcome messages for joining groups
                        // This would be used when this client wants to join a group
                        Err(StateActorError::NotImplemented)
                    }
                    _ => Err(StateActorError::InvalidReceivedMessage),
                }
            }
        }
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
