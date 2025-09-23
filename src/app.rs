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

        // Let me establish my identity first
        let identity =
            crate::identity::MyIdentity::new(&self.config.key_file, &self.config.chat_id)?;

        let mut mls_key_package = OpenMlsKeyPackage::new();

        Ok(())
    }
}
