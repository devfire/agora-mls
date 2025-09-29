use std::{collections::HashMap, hash::Hash};

use tracing::debug;

use kameo::prelude::*;

// Define the state actor
/// This actor holds the current state of the application.
#[derive(Default,Actor)]
pub struct StateActor {
    channels: Vec<String>,
    users: HashMap<String, Vec<String>>, // channel -> users
}

#[derive(Reply)]
pub struct CurrentState {
    pub status: bool,
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
    type Reply = CurrentState;

    async fn handle(&mut self, msg: Request, _: &mut Context<Self, Self::Reply>) -> Self::Reply {
        // Logic to process the message and generate a reply
        debug!("CommandHandler received command: {:?}", msg);
        match msg {
            Request::GetUsers(_) => CurrentState { status: true },
            Request::GetChannels => todo!(),
            Request::QuitChannel(_) => todo!(),
            Request::JoinChannel(_, _) => todo!(),
        }
    }
}
