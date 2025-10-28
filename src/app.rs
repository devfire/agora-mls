use crate::{
    command::Command,
    config::Config,
    crypto_identity_actor::CryptoIdentityActor,
    network::{NetworkConfigBuilder, NetworkManager},
    processor::Processor,
    // state_actor::StateActor,
};
use anyhow::Result;
use kameo::prelude::*;
use std::sync::Arc;

// use openmls::group::{MlsGroup, MlsGroupCreateConfig};
use tracing::debug;

pub struct App {
    config: Config,
}

impl App {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(&mut self) -> Result<()> {
        // First, we load the key package
        debug!("Using configuration: {:?}", self.config);

        // Create network configuration
        let network_config = NetworkConfigBuilder::builder()
            .multicast_address(self.config.multicast_address)
            .interface(self.config.interface.clone().unwrap_or_default())
            .buffer_size(65536) // 64KB buffer for better performance
            .build()?;

        // Initialize network manager
        let network_manager = Arc::new(NetworkManager::new(network_config).await?);

        // Create a channel for commands from stdin to the command handler
        let (command_sender, command_receiver) = tokio::sync::mpsc::channel::<Command>(100);

        // Create a channel for displaying messages to the user
        let (display_sender, display_receiver) = tokio::sync::mpsc::channel::<String>(100);

        // Create a channel for sending messages to the message handler
        let (message_sender, message_receiver) = tokio::sync::mpsc::channel::<String>(100);

        // Create the combined crypto identity actor (merges IdentityActor + OpenMlsActor)
        // This fixes the security vulnerability by keeping all private keys encapsulated
        let crypto_identity_ref = CryptoIdentityActor::spawn(CryptoIdentityActor::new(
            &self.config.key_file,
            &self.config.chat_id,
        )?);

        // Kick off the processor & share everything it needs
        let processor = Processor::new(self.config.chat_id.clone(), Arc::clone(&network_manager));

        // Note the distinct lack of .await here - we want to spawn these tasks and let them run concurrently
        // rather than waiting for each to complete before starting the next.
        let stdin_handle = processor.spawn_stdin_input_task(
            command_sender,
            message_sender.clone(),
        );

        let command_handle = processor.spawn_command_handler_task(
            crypto_identity_ref.clone(),
            command_receiver,
            display_sender.clone(),
        );

        let message_handle = processor.spawn_ui_input_handler_task(
            crypto_identity_ref.clone(),
            message_receiver,
            display_sender.clone(),
        );

        // Start the UDP intake task to listen for incoming messages
        let udp_intake_handle =
            processor.spawn_udp_input_task(crypto_identity_ref.clone(), display_sender.clone());

        // Start the display task to show messages to the user
        let display_handle = processor.spawn_message_display_task(display_receiver);

        // Wait for tasks to complete (they run indefinitely)
        // The stdin_input_handle is the only one designed to finish, triggering a shutdown.
        tokio::select! {
            _ = udp_intake_handle => debug!("UDP intake task completed unexpectedly."),
            _ = display_handle => debug!("Display task completed unexpectedly."),
            _ = command_handle => debug!("Command task completed unexpectedly."),
            _ = message_handle => debug!("Message task completed unexpectedly."),
            _ = stdin_handle => debug!("Stdin task complete. Shutting down."),
        }

        Ok(())
    }
}
