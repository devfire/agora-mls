use core::convert::Infallible;
use kameo::error::SendError;
use openmls::group::{CreateMessageError, MergeCommitError, ProcessMessageError};
use openmls_rust_crypto::MemoryStorageError;
use prost::DecodeError;
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpenSSHKeyError {
    #[error("Failed to read SSH key file: {ssh_key_file_path}")]
    MissingSshKeyFile { ssh_key_file_path: String },
}

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Network configuration error: {message}")]
    Configuration { message: String },

    #[error(
        "Invalid multicast address: {address}. Multicast addresses must be in the range 224.0.0.0/4"
    )]
    InvalidMulticastAddress { address: SocketAddr },

    #[error(
        "Buffer size {size} bytes is outside allowed range. Must be between 1024 and 1048576 bytes"
    )]
    InvalidBufferSize { size: usize },

    #[error("Invalid port number: {port}. Must be between 1024 and 65535")]
    InvalidPort { port: u16 },

    #[error("Missing required field: {field_name}")]
    MissingRequiredField { field_name: String },

    #[error("IPv6 multicast addresses are not currently supported: {address}")]
    UnsupportedIpv6 { address: SocketAddr },

    #[error("Network interface error: {interface} - {message}")]
    InterfaceError { interface: String, message: String },
}

#[derive(Error, Debug)] // Note: Removed Clone, as some inner errors aren't clonable
pub enum StateActorError {
    #[error("User not found")]
    UserNotFound,

    #[error("Group not found")]
    GroupNotFound,

    #[error("Channel not found")]
    ChannelNotFound,

    #[error("Failed to create group: {0}")]
    GroupCreationFailed(#[from] anyhow::Error),

    #[error("Safety number generation failed")]
    SafetyNumberGenerationFailed,

    #[error("No active group")]
    NoActiveGroup,

    #[error("Actor communication failed: {0}")]
    ActorCommError(String),

    #[error("Failed to create MLS message: {0}")]
    MlsCreateMessageError(#[from] CreateMessageError),

    #[error("Failed to process MLS message: {0}")]
    MlsProcessMessageError(#[from] ProcessMessageError<Infallible>),

    #[error("Failed to merge staged commit: {0}")]
    MlsMergeCommitError(#[from] MergeCommitError<Infallible>),

    #[error("Failed to store: {0}")]
    MlsMergeStorageError(#[from] MergeCommitError<MemoryStorageError>),

    #[error("Failed to convert to/from Protobuf: {0}")]
    ProtobufConversionError(#[from] ProtobufWrapperError),

    #[error("Invalid message received from network")]
    InvalidReceivedMessage,

    #[error("Failed to decode message as UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("Feature not implemented")]
    NotImplemented,

    #[error("Missing verifying key in identity actor")]
    MissingVerifyingKey,

    #[error("Invalid credential or missing required extension")]
    InvalidCredential,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Failed to serialize MLS message to bytes")]
    MlsMessageError(#[from] openmls::framing::errors::MlsMessageError),

    #[error("Failed to deserialize MLS packet")]
    MlsDeserializeError(#[from] openmls::prelude::Error),

    #[error("Failed to store MLS")]
    MlsProcessStorageError(#[from] ProcessMessageError<MemoryStorageError>),

    #[error("Failed to validate KeyPackage")]
    KeyPackageValidationFailed,

    #[error("Invalid composite key format (expected username@fingerprint)")]
    InvalidCompositeKey,
}

#[derive(Error, Debug)]
pub enum SafetyNumberError {
    #[error("Public key is empty.")]
    EmptyPublicKey,
    #[error("Failed to generate safety number.")]
    QrCodeGenerationFailed,
}

#[derive(Error, Debug)]
pub enum ProtobufWrapperError {
    #[error("Failed to serialize MLS message")]
    SerializationFailed(#[from] openmls::prelude::Error),

    #[error("Failed to decode Protobuf message")]
    ProtobufDecode(#[from] DecodeError),

    #[error("MLS message body is empty or invalid")]
    MlsMessageBodyInvalid,

    #[error("OpenMLS failed to process the message")]
    MlsMessageInvalid(#[from] openmls::framing::errors::MlsMessageError),
}

// Add this implementation at the bottom of the file
// Replace the previous `impl From<KameoError>` with this generic one
impl<M> From<SendError<M>> for StateActorError {
    fn from(err: SendError<M>) -> Self {
        let err_msg = match err {
            SendError::ActorNotRunning(_) => "Actor not running".to_string(),
            SendError::ActorStopped => "Actor stopped before a reply could be received".to_string(),
            SendError::MailboxFull(_) => "Actor's mailbox is full".to_string(),
            SendError::HandlerError(_) => {
                "An error occurred within the actor's handler".to_string()
            }
            SendError::Timeout(_) => "Timed out waiting for a reply".to_string(),
        };
        StateActorError::ActorCommError(err_msg)
    }
}
