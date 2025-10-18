pub mod app;
pub mod cli;
pub mod config;
pub mod error;
pub mod network;
pub mod processor;
pub mod command;
pub mod crypto_identity_actor;
pub mod state_actor;
pub mod safety_number;
pub mod protobuf_wrapper;

// Re-export commonly used items for easier access
pub use crate::cli::ChatArgs;

// Include the generated protobuf code
// The build script outputs to src/ directory so rust-analyzer can find it
#[path = "agora_chat.rs"]
pub mod agora_chat;
