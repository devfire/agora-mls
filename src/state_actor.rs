use std::{collections::HashMap, hash::Hash};

use ed25519_dalek::VerifyingKey;
use tracing::debug;

use kameo::prelude::*;

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
#[derive(Default, Actor)]
pub struct StateActor {
    users: Vec<VerifyingKey>,
    membership: HashMap<VerifyingKey, Vec<Channel>>, // Maps handle to channels
}

#[derive(Reply, Debug)]
pub enum Reply {
    Users(Option<Vec<String>>),
    Channels(Option<Vec<String>>),
    Success,
}

#[derive(Debug)]
pub enum Request {
    GetUsers(String),                    // get all the users for the given channel
    GetChannels,                         // get all the channels
    QuitChannel(String),                 // quit the given channel
    JoinChannel(String, Option<String>), // join the given channel with optional password
}

impl Message<Request> for StateActor {
    // https://docs.page/tqwewe/kameo/core-concepts/replies
    type Reply = Reply;

    async fn handle(&mut self, msg: Request, _: &mut Context<Self, Self::Reply>) -> Self::Reply {
        // Logic to process the message and generate a reply
        debug!("CommandHandler received command: {:?}", msg);
        match msg {
            Request::GetUsers(_) => Reply::Success,
            Request::GetChannels => todo!(),
            Request::QuitChannel(_) => todo!(),
            Request::JoinChannel(_, _) => todo!(),
        }
    }
}
