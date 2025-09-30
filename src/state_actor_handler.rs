use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use crate::command::Command;

#[derive(Clone, Debug)]
pub struct StateActorHandle {
    sender: mpsc::Sender<Command>,
}

// Gives you access to the underlying actor.
impl StateActorHandle {
     pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let mut actor = StateActorHandle::new(receiver);

        tokio::spawn(async move { actor.run().await });

        Self { sender }
    }

    /// Fetch the current chat state
    pub async fn get_value(&self, config_key: ConfigCommandParameter) -> Option<String> {
        debug!("Getting value for key: {:?}", config_key);
        let (send, recv) = oneshot::channel();
        let msg = ConfigActorMessage::GetConfigValue {
            config_key,
            respond_to: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check the
        // failure twice.
        let _ = self.sender.send(msg).await;

        // this is going back once the msg comes back from the actor.
        // NOTE: we might get None back, i.e. no value for the given key.
        if let Some(value) = recv.await.expect("Actor task has been killed") {
            Some(value)
        } else {
            None
        }
    }

    /// implements the redis CONFIG SET command, taking a key, value pair as input. Returns nothing.
    /// https://redis.io/commands/config-set/
    pub async fn set_value(&self, config_key: ConfigCommandParameter, config_value: &str) {
        let msg = ConfigActorMessage::SetConfigValue {
            config_key,
            config_value: config_value.to_string(),
        };

        debug!(
            "Setting value for key: {:?}, value: {}",
            config_key, config_value
        );
        // Ignore send errors.
        let _ = self.sender.send(msg).await.expect("Failed to set value.");
    }

    
}