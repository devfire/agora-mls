pub mod app;
pub mod cli;
pub mod config;
pub mod identity;
pub mod key_package;
pub mod network;
pub mod processor;
pub mod command;
// pub mod app_state;
pub mod state_actor;

// Re-export commonly used items for easier access
pub use crate::cli::ChatArgs;

pub use crate::key_package::OpenMlsKeyPackage;

// Include the generated protobuf code
// The build script outputs to src/ directory so rust-analyzer can find it
#[path = "agora_chat.rs"]
pub mod agora_chat;
