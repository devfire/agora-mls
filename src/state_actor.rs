use std::collections::HashMap;

use prost::Message;
use tracing::{debug, error};

use kameo::{message::Message as KameoMessage, prelude::*};
use openmls::prelude::*;

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
        match self.handle_command(msg).await {
            Ok(reply) => reply,
            Err(e) => {
                // Return the categorized error to the caller.
                StateActorReply::StateActorError(e)
            }
        }
    }
}

impl StateActor {
    // New function to contain the fallible logic
    async fn handle_command(
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

                        // OpenMLS provides a `From` implementation for this, so `.into()` works perfectly.
                        let mls_message_out: MlsMessageOut = mls_identity.mls_key_package.into();

                        let proto_key_package: ProtoMlsMessageOut = mls_message_out.try_into()?;

                        // Return the encrypted wrapped packet for network multicast
                        Ok(StateActorReply::MlsMessageOut(proto_key_package))
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
                let proto_in: MlsMessageIn = chat_packet.try_into()?;

                let active_group_name = self
                    .active_group
                    .as_ref()
                    .ok_or(StateActorError::NoActiveGroup)?;
                let mls_group_ref = self
                    .groups
                    .get_mut(active_group_name)
                    .ok_or(StateActorError::GroupNotFound)?;

                let protocol_message = match proto_in.extract() {
                    MlsMessageBodyIn::PublicMessage(msg) => ProtocolMessage::from(msg),
                    MlsMessageBodyIn::PrivateMessage(msg) => ProtocolMessage::from(msg),
                    _ => return Err(StateActorError::InvalidReceivedMessage),
                };

                let processed_message = mls_group_ref.process_message(
                    &openmls_rust_crypto::OpenMlsRustCrypto::default(),
                    protocol_message,
                )?; // check out the clean error conversion lol

                // Extract the application message from the processed message
                match processed_message.into_content() {
                    ProcessedMessageContent::ApplicationMessage(app_msg) => {
                        let decrypted_text = String::from_utf8(app_msg.into_bytes())?; // And another woot woot!
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
        }
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
