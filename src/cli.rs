use clap::Parser;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// Command-line arguments for the AI Agent Swarm
#[derive(Parser, Debug)]
#[command(
    name = "agora",
    about = "Distributed chat app communicating via UDP multicast",
    long_about = "A distributed system of chat apps.",
    version
)]
pub struct ChatArgs {
    /// Unique identifier for this agent
    #[arg(
        short = 'c',
        // long = "chat-id",
        help = "Unique identifier for this chat, automatically generated if not provided",
        default_value_t = Uuid::new_v4().to_string(),
        value_name = "ID"
    )]
    pub chat_id: String,

    /// Log level filter
    #[arg(
        short = 'l',
        // long = "log-level",
        help = "Set the log level",
        default_value = "info",
        value_parser = ["error", "warn", "info", "debug", "trace"]
    )]
    pub log_level: String,

    /// UDP multicast address for agent communication
    #[arg(
        short = 'm',
        // long = "multicast-address",
        help = "UDP multicast address for agent communication",
        default_value = "239.255.255.250:8080",
        value_name = "ADDRESS:PORT"
    )]
    pub multicast_address: SocketAddr,

    /// Network interface to bind to (optional)
    #[arg(
        short = 'i',
        // long = "interface",
        help = "Network interface to bind to (e.g., 'eth0', '192.168.1.100')",
        value_name = "INTERFACE"
    )]
    pub interface: Option<String>,

    /// Private key file path (optional)
    #[arg(
        short = 'k',
        help = "Private key file path (optional) in Ed25519 format",
        value_parser=clap::value_parser!(PathBuf),
        value_name = "KEY_FILE_PATH"
    )]
    pub key_file: Option<PathBuf>,
}

impl ChatArgs {
    /// Validate the provided arguments
    pub fn validate(&self) -> Result<(), String> {
        // Validate agent ID is not empty
        if self.chat_id.trim().is_empty() {
            return Err("Agent ID cannot be empty".to_string());
        }

        // Validate agent ID contains only valid characters
        if !self
            .chat_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(
                "Chat client ID can only contain alphanumeric characters, hyphens, and underscores"
                    .to_string(),
            );
        }

        // Validate multicast address is in the multicast range
        if !self.multicast_address.ip().is_multicast() {
            return Err(format!(
                "Address {} is not a valid multicast address",
                self.multicast_address.ip()
            ));
        }

        // Validate key file if provided
        if let Some(ref key_path) = self.key_file {
            let expanded_path =
                shellexpand::tilde(key_path.to_str().expect("Expected to find the key file"))
                    .to_string();
            let path = Path::new(&expanded_path);
            if !path.exists() {
                return Err(format!("Key file '{}' does not exist", path.display()));
            }
        }
        Ok(())
    }
}