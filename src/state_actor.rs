use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;

use tracing::debug;

use kameo::prelude::*;

use crate::{command::Command, identity_actor::{IdentityActor, IdentityRequest}, openmls_actor::{OpenMlsIdentityActor, OpenMlsIdentityRequest}};

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
                // if let Some(nick) = nickname {
                //     self.identity.handle = nick;
                //     Reply::Success
                // } else {
                //     Reply::ChatHandle(self.identity.handle.clone())
                // }
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
        }
    }

    async fn create_mls_group(&self, group_name: &str) -> anyhow::Result<()> {
        // Now start a new group ...
        // let mut group = openmls::group::MlsGroup::new(
        //     &mls_key_package.provider,
        //     &signature_keypair,
        //     &openmls::group::MlsGroupCreateConfig::default(),
        //     credential_with_key,
        // )?;

        // let mut mls_key_package = OpenMlsKeyPackage::new();

        // let (credential_with_key, signature_keypair) = mls_key_package
        //     .generate_credential_with_key(identity.verifying_key.to_bytes().to_vec());

        // let key_package_bundle =
        //     mls_key_package.generate_key_package_bundle(&credential_with_key, &signature_keypair)?;

        // debug!(
        //     "Successfully created key package bundle: {:?}",
        //     key_package_bundle
        // );

        let mls_identity = self
            .mls_identity_actor
            .ask(OpenMlsIdentityRequest)
            .await
            .expect("Failed to get verifying key from IdentityActor.");

        // // Now start a new group ...
        // let mut group = openmls::group::MlsGroup::new(
        //     &openmls_rust_crypto::OpenMlsRustCrypto::default(),
        //     &mls_identity.signature_keypair,
        //     &openmls::group::MlsGroupCreateConfig::default(),
        //     credential_with_key,
        // )?;

        Ok(())
    }
}
