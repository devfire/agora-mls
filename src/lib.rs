pub mod app;
pub mod cli;
pub mod command;
pub mod config;
pub mod crypto_identity_actor;
pub mod error;
pub mod network;
pub mod processor;
pub mod protobuf_wrapper;
pub mod safety_number;

// Re-export commonly used items for easier access
pub use crate::cli::ChatArgs;

// Include the generated protobuf code
// The build script outputs to src/ directory so rust-analyzer can find it
#[path = "agora_chat.rs"]
pub mod agora_chat;
