use crate::{OpenMlsKeyPackage, config::Config};
use anyhow::Result;

use tracing::{debug, error, info};
use tracing_subscriber::field::debug;

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

        let mut mls_key_package = OpenMlsKeyPackage::new();

        let my_bundle = mls_key_package.create_key_package_bundle(&self.config.key_file)?;

        debug!("Key package bundle created: {:?}", my_bundle);

        Ok(())
    }
}
