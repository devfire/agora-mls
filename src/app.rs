use crate::{
    command::Command,
    config::Config,
    identity::MyIdentity,
    network::{NetworkConfigBuilder, NetworkManager},
    processor::Processor,
};
use anyhow::Result;

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

        // // Let me establish my identity first
        let identity = MyIdentity::new(&self.config.key_file, &self.config.chat_id)?;

        // let mut mls_key_package = OpenMlsKeyPackage::new();

        // let (credential_with_key, signature_keypair) = mls_key_package
        //     .generate_credential_with_key(identity.verifying_key.to_bytes().to_vec());

        // let key_package_bundle =
        //     mls_key_package.generate_key_package(&credential_with_key, &signature_keypair)?;

        // debug!(
        //     "Successfully created key package bundle: {:?}",
        //     key_package_bundle
        // );

        // // Now start a new group ...
        // let mut group = MlsGroup::new(
        //     &mls_key_package.provider,
        //     &signature_keypair,
        //     &MlsGroupCreateConfig::default(),
        //     credential_with_key,
        // )?;

        // Create network configuration

        let network_config = NetworkConfigBuilder::builder()
            .multicast_address(self.config.multicast_address)
            .interface(self.config.interface.clone().unwrap_or_default())
            .buffer_size(65536) // 64KB buffer for better performance
            .build()?;

        // Initialize network manager
        let network_manager = Arc::new(NetworkManager::new(network_config).await?);

        let (command_sender, command_receiver) = tokio::sync::mpsc::channel::<Command>(100);

        let processor = Processor::new(identity, Arc::clone(&network_manager));

        // Note the distinct lack of .await here - we want to spawn these tasks and let them run concurrently
        // rather than waiting for each to complete before starting the next.
        let stdin_handle = processor.spawn_stdin_input_task(command_sender);
        let command_handle = processor.spawn_command_handler_task(command_receiver);

        // Wait for tasks to complete (they run indefinitely)
        // The stdin_input_handle is the only one designed to finish, triggering a shutdown.
        tokio::select! {
            // _ = udp_intake_handle => debug!("UDP intake task completed unexpectedly."),
            // _ = display_handle => debug!("Display task completed unexpectedly."),
            _ = command_handle => debug!("Command task completed unexpectedly."),
            _ = stdin_handle => debug!("Stdin task complete. Shutting down."),
        }

        Ok(())
    }
}
