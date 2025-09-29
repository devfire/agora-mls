use crate::{
    OpenMlsKeyPackage,
    config::Config,
    identity::MyIdentity,
    network::{NetworkConfig, NetworkConfigBuilder, NetworkManager},
    processor::Processor,
    state_actor::{self, StateActor},
};
use anyhow::Result;
use kameo::prelude::*;
use std::sync::Arc;

use openmls::group::{MlsGroup, MlsGroupCreateConfig};
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

        let mut mls_key_package = OpenMlsKeyPackage::new();

        let (credential_with_key, signature_keypair) = mls_key_package
            .generate_credential_with_key(identity.verifying_key.to_bytes().to_vec());

        let key_package_bundle =
            mls_key_package.generate_key_package(&credential_with_key, &signature_keypair)?;

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

        // Spawn the state actor
        let state_actor = StateActor::spawn(StateActor::default());

        let processor = Processor::new(Arc::clone(&network_manager));

        let stdin_handle = processor.spawn_stdin_input_task(state_actor, &self.config.chat_id);

        // Wait for tasks to complete (they run indefinitely)
        // The stdin_input_handle is the only one designed to finish, triggering a shutdown.
        tokio::select! {
            // _ = udp_intake_handle => debug!("UDP intake task completed unexpectedly."),
            // _ = display_handle => debug!("Display task completed unexpectedly."),
            _ = stdin_handle => debug!("Stdin task complete. Shutting down."),
        }

        Ok(())
    }
}
