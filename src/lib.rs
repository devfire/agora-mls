pub mod app;
pub mod cli;
pub mod config;
pub mod error;
pub mod network;
pub mod processor;
pub mod command;
pub mod openmls_actor;
pub mod state_actor;
pub mod identity_actor;
pub mod safety_number;

// Re-export commonly used items for easier access
pub use crate::cli::ChatArgs;

// Include the generated protobuf code
// The build script outputs to src/ directory so rust-analyzer can find it
#[path = "agora_chat.rs"]
pub mod agora_chat;
