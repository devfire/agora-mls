use std::collections::HashMap;

use tracing::debug;

use crate::identity::MyIdentity;
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

#[derive(Clone)]
pub struct AppState {
    pub channels: Vec<Channel>, // List of chat IDs (channels)
    pub membership: HashMap<String, Vec<Channel>>, // Maps handle to channels
}

impl AppState {
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            membership: HashMap::new(),
        }
    }

    /// Add a new channel (chat ID) to the state
    pub fn add_channel(&mut self, channel: Channel) {
        if !self.channels.contains(&channel) {
            self.channels.push(channel);
        } else {
            debug!("Channel {} already exists", channel);
        }
    }

    /// Add a member to a specific channel
    pub fn add_member_to_channel(&mut self, handle: &str, channel: Channel) {
        self.membership
            .entry(handle.to_string())
            .or_insert_with(Vec::new)
            .push(channel);
    }

    /// Get the list of channels
    pub fn get_channels(&self) -> &Vec<Channel> {
        &self.channels
    }

    // /// Get members of a specific channel
    // pub fn get_members_of_channel(&self, channel: &Channel) -> Option<Vec<String>> {
    //     self.membership.get(channel.channel_id.as_str())
    // }
}
