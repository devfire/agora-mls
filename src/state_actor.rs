
use anyhow::Context;
use ed25519_dalek::VerifyingKey;

use tracing::{debug, error};

use kameo::prelude::*;
use openmls::prelude::*;

use crate::{
    command::Command,
    error::StateActorError,
    identity_actor::{IdentityActor, IdentityActorMsg},
    openmls_actor::{OpenMlsIdentityActor, OpenMlsIdentityRequest},
    safety_number::{SafetyNumber, generate_safety_number},
};

// #[derive(Debug, Clone, PartialEq)]
// pub struct Group {
//     pub id: String,
//     pub name: String,
// }
// impl std::fmt::Display for Group {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{} ({})", self.name, self.id)
//     }
// }
// Define the state actor
/// This actor holds the current state of the application.
#[derive(Actor)]
pub struct StateActor {
    users: Vec<VerifyingKey>,
    // membership: HashMap<VerifyingKey, Vec<Group>>, // Maps handle to channels
    identity_actor: ActorRef<IdentityActor>,
    mls_identity_actor: ActorRef<OpenMlsIdentityActor>,
}

#[derive(Reply)]
pub enum StateActorReply {
    Users(Option<Vec<String>>),
    Channels(Option<Vec<String>>),
    Status(Result<(), StateActorError>), // Ok(()) for success, Err(StateActorError) for failure
    ChatHandle(String),
    SafetyNumber(SafetyNumber),
}

// implement Display for Reply
impl std::fmt::Display for StateActorReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateActorReply::Users(Some(users)) => write!(f, "Users: {:?}", users),
            StateActorReply::Users(None) => write!(f, "No users found"),
            StateActorReply::Channels(Some(channels)) => write!(f, "Channels: {:?}", channels),
            StateActorReply::Channels(None) => write!(f, "No channels found"),
            StateActorReply::Status(Ok(())) => write!(f, "Operation successful"),
            StateActorReply::Status(Err(e)) => write!(f, "Operation failed: {}", e),
            StateActorReply::ChatHandle(handle) => write!(f, "{handle}"),
            StateActorReply::SafetyNumber(safety_number) => write!(
                f,
                "Safety Number: {}\nFull Hash: {}\nQR Code:\n{}",
                safety_number.display_string, safety_number.full_hex, safety_number.qrcode
            ),
        }
    }
}

// #[derive(Debug)]
// pub enum Request {
//     OriginalCommand(Command), // pass the original command for processing
//     GetUsers(String),         // get all the users for the given channel
//     GetChannels,              // get all the channels
//     QuitChannel(String),      // quit the given channel
//     CreateChannel(String),    // join the given channel with optional password
//     ChatHandle,               // get my chat handle
// }

impl Message<Command> for StateActor {
    // https://docs.page/tqwewe/kameo/core-concepts/replies
    type Reply = StateActorReply;

    async fn handle(
        &mut self,
        msg: Command,
        _ctx: &mut kameo::message::Context<Self, StateActorReply>,
    ) -> Self::Reply {
        // Logic to process the message and generate a reply
        debug!("CommandHandler received command: {:?}", msg);
        match msg {
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
            Command::Users => todo!(),
            Command::Groups => {
                todo!()
                // if self.users.is_empty() {
                //     Reply::Channels(None)
                // } else {
                //     let channel_list: Vec<String> = self
                //         .users
                //         .iter()
                //         .map(|vk| vk.to_bytes())
                //         .filter_map(|bytes| self.group_names.get(&bytes).cloned())
                //         .collect();
                //     if channel_list.is_empty() {
                //         Reply::Channels(None)
                //     } else {
                //         Reply::Channels(Some(channel_list))
                //     }
                // }
            }
            Command::Quit => todo!(),
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
                    Err(_) => {
                        StateActorReply::Status(Err(StateActorError::SafetyNumberGenerationFailed))
                    }
                }
            }
            Command::Group => todo!(),
        }
    }
}

impl StateActor {
    pub fn new(
        identity_actor: ActorRef<IdentityActor>,
        mls_identity_actor: ActorRef<OpenMlsIdentityActor>,
    ) -> Self {
        Self {
            users: vec![],
            // membership: HashMap::new(),
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
