use std::collections::HashMap;

use anyhow::Context;
use prost::Message;
use tracing::{debug, error};

use kameo::{message::Message as KameoMessage, prelude::*};
use openmls::prelude::*;

use crate::{
    agora_chat::MlsMessageOut,
    command::Command,
    error::StateActorError,
    identity_actor::{IdentityActor, IdentityActorMsg},
    openmls_actor::{OpenMlsActor, OpenMlsIdentityRequest},
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

#[derive(Debug)]
pub enum StateActorMessage {
    Command(Command),
    Encrypt(String),
    Decrypt(MlsMessageIn),
}

#[derive(Reply)]
pub enum StateActorReply {
    Groups(Option<Vec<String>>),         // List of group names, if any
    Status(Result<(), StateActorError>), // Ok(()) for success, Err(StateActorError) for failure
    ChatHandle(String),
    SafetyNumber(SafetyNumber),
    ActiveGroup(Option<String>), // Currently active group, if any
    EncryptedMessage(MlsMessageOut),
}

// // implement Display for Reply
// impl std::fmt::Display for StateActorReply {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             StateActorReply::Groups(Some(channels)) => write!(f, "Channels: {:?}", channels),
//             StateActorReply::Groups(None) => write!(f, "No channels found"),
//             StateActorReply::Status(Ok(())) => write!(f, "Operation successful"),
//             StateActorReply::Status(Err(e)) => write!(f, "Operation failed: {}", e),
//             StateActorReply::ChatHandle(handle) => write!(f, "{handle}"),
//             StateActorReply::SafetyNumber(safety_number) => write!(
//                         f,
//                         "Safety Number: {}\nFull Hash: {}\nQR Code:\n{}",
//                         safety_number.display_string, safety_number.full_hex, safety_number.qrcode
//                     ),
//             StateActorReply::ActiveGroup(Some(mls_group)) => write!(f, "Active group tbd"),
//             StateActorReply::ActiveGroup(None) => write!(f, "No active group."),
// StateActorReply::EncryptedMessage(mls_message_out) => todo!(),
//         }
//     }
// }

impl KameoMessage<StateActorMessage> for StateActor {
    // https://docs.page/tqwewe/kameo/core-concepts/replies
    type Reply = StateActorReply;

    async fn handle(
        &mut self,
        msg: StateActorMessage,
        _ctx: &mut kameo::message::Context<Self, StateActorReply>,
    ) -> Self::Reply {
        // Logic to process the message and generate a reply
        debug!("StateActor received StateActorMessage: {:?}", msg);
        match msg {
            StateActorMessage::Command(command) => {
                match command {
                    Command::Invite {
                        nick: channel,
                        password,
                    } => todo!(),
                    Command::Leave { channel } => todo!(),
                    Command::Msg { user, message } => todo!(),
                    Command::Create { name } => {
                        if let Err(e) = self.create_mls_group(&name).await {
                            error!("Failed to create MLS group '{}': {e}", name);
                            StateActorReply::Status(Err(StateActorError::ChannelCreationFailed))
                        } else {
                            debug!("Successfully created MLS group '{}'", name);
                            StateActorReply::Status(Ok(()))
                        }
                    }
                    Command::Users => StateActorReply::Status(Ok(())),
                    Command::Groups => StateActorReply::Status(Ok(())),
                    Command::Quit => StateActorReply::Status(Ok(())),
                    Command::Nick { nickname } => {
                        if let Some(nick) = nickname {
                            self.identity_actor
                                .tell(IdentityActorMsg {
                                    handle_update: Some(nick),
                                })
                                .await
                                .expect("Failed to set identity in IdentityActor.");
                            StateActorReply::Status(Ok(()))
                        } else {
                            let identity = self
                                .identity_actor
                                .ask(IdentityActorMsg {
                                    handle_update: None,
                                })
                                .await
                                .expect("Failed to get identity from IdentityActor.");
                            StateActorReply::ChatHandle(identity.handle.clone())
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
                                return StateActorReply::Status(Err(
                                    StateActorError::SafetyNumberGenerationFailed,
                                ));
                            }
                        };

                        // Generate the safety number for the user
                        match generate_safety_number(&verifying_key) {
                            Ok(safety_number) => {
                                debug!("Your safety number is: {safety_number}");
                                StateActorReply::SafetyNumber(safety_number)
                            }
                            Err(_) => StateActorReply::Status(Err(
                                StateActorError::SafetyNumberGenerationFailed,
                            )),
                        }
                    }
                    Command::Group { name: group_name } => {
                        if let Some(name) = group_name {
                            // User wants to set the active group
                            if self.groups.contains_key(&name) {
                                self.active_group = Some(name);
                                StateActorReply::Status(Ok(()))
                            } else {
                                StateActorReply::Status(Err(StateActorError::GroupNotFound))
                            }
                        } else {
                            // User wants to get the current active group
                            if let Some(active_name) = &self.active_group {
                                StateActorReply::ActiveGroup(Some(active_name.clone()))
                            } else {
                                // This should not happen; active_group should always be in groups
                                StateActorReply::ActiveGroup(None)
                            }
                        }
                    }
                }
            }
            StateActorMessage::Encrypt(plaintext_payload) => {
                debug!("Encrypting message for transport");

                let mls_identity = self
                    .mls_identity_actor
                    .ask(OpenMlsIdentityRequest)
                    .await
                    .expect("Expected to successfully call the mls actor");

                // Let's get the active group name first
                let active_group_name = if let Some(active_group) = &self.active_group {
                    active_group
                } else {
                    return StateActorReply::Status(Err(StateActorError::NoActiveGroup));
                };

                // Now, armed with the active group, let's get a reference to the MlsGroup
                let mls_group_ref = if let Some(mls_group) = self.groups.get_mut(active_group_name)
                {
                    mls_group
                } else {
                    return StateActorReply::Status(Err(StateActorError::GroupNotFound));
                };

                // OK, let's try to encrypt the message
                let mls_msg_out = match mls_group_ref.create_message(
                    &openmls_rust_crypto::OpenMlsRustCrypto::default(),
                    &*mls_identity.signature_keypair,
                    plaintext_payload.encode_to_vec().as_slice(),
                ) {
                    Ok(m) => m,
                    Err(e) => {
                        // Handle both error types in one shot with a single return
                        let error = match e {
                            CreateMessageError::LibraryError(library_error) => {
                                error!(
                                    "Library error during message creation: {:?}",
                                    library_error
                                );
                                StateActorError::EncryptionFailed
                            }
                            CreateMessageError::GroupStateError(mls_group_state_error) => {
                                error!(
                                    "Group state error during message creation: {:?}",
                                    mls_group_state_error
                                );
                                StateActorError::GroupStateError
                            }
                        };
                        return StateActorReply::Status(Err(error));
                    }
                };

                StateActorReply::Status(Ok(()))
            }
            StateActorMessage::Decrypt(chat_packet) => todo!(),
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

    fn get_group_name(group: &openmls::group::MlsGroup) -> anyhow::Result<String> {
        const GROUP_NAME_EXTENSION_ID: u16 = 13;

        // Get the group context extensions
        let extensions = group.extensions();

        // Find the specific extension by type
        let group_name_ext_type = ExtensionType::from(GROUP_NAME_EXTENSION_ID);

        let group_name = extensions
            .iter()
            .find_map(|ext| {
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
            .context("Group name extension not found")?;

        Ok(group_name)
    }
}
