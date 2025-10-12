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

// Define errors
#[derive(Error, Debug, Clone)]
pub enum StateActorError {
    #[error("User not found")]
    UserNotFound,

    #[error("Group not found")]
    GroupNotFound,

    #[error("Channel not found")]
    ChannelNotFound,

    #[error("Channel creation failed")]
    ChannelCreationFailed,

    #[error("Safety number generation failed")]
    SafetyNumberGenerationFailed,

    #[error("No active group")]
    NoActiveGroup,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Group state error")]
    GroupStateError,
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
