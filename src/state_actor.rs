use std::collections::HashMap;

use anyhow::Context;
use ed25519_dalek::VerifyingKey;

use tracing::debug;

use kameo::prelude::*;
use openmls::prelude::*;

use crate::{
    command::Command,
    identity_actor::IdentityActor,
    openmls_actor::{OpenMlsIdentityActor, OpenMlsIdentityRequest},
};

#[derive(Debug, Clone, PartialEq)]
pub struct Channel {
    pub channel_id: String,
    pub channel_name: String,
}
impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.channel_name, self.channel_id)
    }
}
// Define the state actor
/// This actor holds the current state of the application.
#[derive(Actor)]
pub struct StateActor {
    users: Vec<VerifyingKey>,
    membership: HashMap<VerifyingKey, Vec<Channel>>, // Maps handle to channels
    identity_actor: ActorRef<IdentityActor>,
    mls_identity_actor: ActorRef<OpenMlsIdentityActor>,
    group_names: HashMap<Vec<u8>, String>, // Maps group ID bytes to group name
}

#[derive(Reply, Debug)]
pub enum Reply {
    Users(Option<Vec<String>>),
    Channels(Option<Vec<String>>),
    Success,
    ChatHandle(String),
}

// implement Display for Reply
impl std::fmt::Display for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reply::Users(Some(users)) => write!(f, "Users: {:?}", users),
            Reply::Users(None) => write!(f, "No users found"),
            Reply::Channels(Some(channels)) => write!(f, "Channels: {:?}", channels),
            Reply::Channels(None) => write!(f, "No channels found"),
            Reply::Success => write!(f, "Success"),
            Reply::ChatHandle(handle) => write!(f, "{handle}"),
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
    type Reply = Reply;

    async fn handle(
        &mut self,
        msg: Command,
        ctx: &mut kameo::message::Context<Self, Reply>,
    ) -> Self::Reply {
        // Logic to process the message and generate a reply
        debug!("CommandHandler received command: {:?}", msg);
        match msg {
            Command::Invite { channel, password } => todo!(),
            Command::Leave { channel } => todo!(),
            Command::Msg { user, message } => todo!(),
            Command::Create { name } => todo!(),
            Command::Users => todo!(),
            Command::Channels => todo!(),
            Command::Quit => todo!(),
            Command::Nick { nickname } => {
                todo!()
                //     let identity = self
                //         .identity_actor
                //         .ask(crate::identity_actor::IdentityRequest)
                //         .await
                //         .expect("Failed to get identity from IdentityActor.");
                //     if let Some(nick) = nickname {
                //         identity.handle = nick;
                //         Reply::Success
                //     } else {
                //         Reply::ChatHandle(identity.handle.clone())
                //     }
            }
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
            membership: HashMap::new(),
            identity_actor,
            mls_identity_actor,
            group_names: HashMap::new(),
        }
    }

    async fn create_mls_group(&mut self, group_name: &str) -> anyhow::Result<()> {
        const GROUP_NAME_EXTENSION_ID: u16 = 13;
        let mls_identity = self
            .mls_identity_actor
            .ask(OpenMlsIdentityRequest)
            .await
            .expect("Failed to get verifying key from IdentityActor.");

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
            .with_group_context_extensions(extensions)
            .expect("Expected to build group context extensions")
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
