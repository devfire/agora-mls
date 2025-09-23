use crate::{OpenMlsKeyPackage, config::Config, identity::MyIdentity, key_package};
use anyhow::Result;

use openmls::group::{MlsGroup, MlsGroupCreateConfig};
use tracing::{debug, error, info};

pub struct App {
    config: Config,
}

impl App {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn run(&mut self) -> Result<()> {
        // First, we load the key package
        debug!("Using configuration: {:?}", self.config);

        // Let me establish my identity first
        let identity = MyIdentity::new(&self.config.key_file, &self.config.chat_id)?;

        let mut mls_key_package = OpenMlsKeyPackage::new();

        let (credential_with_key, signature_keypair) = mls_key_package
            .generate_credential_with_key(identity.verifying_key.to_bytes().to_vec());

        let key_package_bundle =
            mls_key_package.generate_key_package(&credential_with_key, &signature_keypair)?;

        debug!(
            "Successfully created key package bundle: {:?}",
            key_package_bundle
        );

        // Now start a new group ...
        let mut group = MlsGroup::new(
            &mls_key_package.provider,
            &signature_keypair,
            &MlsGroupCreateConfig::default(),
            credential_with_key,
        )?;
        Ok(())
    }
}
