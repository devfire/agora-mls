pub mod app;
pub mod cli;
pub mod config;
pub mod identity;
pub mod key_package;

// Re-export commonly used items for easier access
pub use crate::cli::ChatArgs;

pub use crate::key_package::OpenMlsKeyPackage;

// Include the generated protobuf code
pub mod agora_chat {
    include!(concat!(env!("OUT_DIR"), "/agora_chat.rs"));
}
