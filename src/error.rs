
use openmls::{group::NewGroupError, prelude::InvalidExtensionError};
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
pub enum CommandError {
    #[error("Nick parsing failed, are you missing the @ sign?")]
    NickParsingFailed(#[from] CryptoIdentityActorError),

    #[error("Not a crypto command")]
    NotACryptoCommand,
}

#[derive(Error, Debug)]
pub enum CryptoIdentityActorError {
    #[error("Group not found")]
    GroupNotFound,

    #[error("User {0} not found")]
    UserNotFound(String),

    #[error("Failed to set extensions {0}")]
    ExtensionError(InvalidExtensionError),

    #[error("Failed to create new group")]
    GroupCreationFailed(#[from] NewGroupError<MemoryStorageError>),

    #[error("Failed to store new group")]
    GroupStorageFailed,

    #[error("Failed to export group")]
    GroupExportFailed(#[from] openmls::group::ExportGroupInfoError),

    #[error("Failed to tls serialize group")]
    GroupTlsSerializationFailed(#[from] openmls::prelude::Error),

    #[error("Failed to HPKE seal")]
    HpkeSealFailed(#[from] openmls::prelude::CryptoError),

    #[error("Failed to create message")]
    MessageCreationFailed(#[from] openmls::group::CreateMessageError),

    #[error("Protocol message conversion failure")]
    ProtocolMessageConversionFailed(#[from] openmls::framing::errors::ProtocolMessageError),

    #[error("Message processing failed")]
    MessageProcessingFailed(#[from] openmls::group::ProcessMessageError<MemoryStorageError>),

    #[error("UTF8 encoding failed")]
    UtfEncodingFailed(#[from] std::string::FromUtf8Error),

    #[error("Failed to merge staged commit")]
    MergingStagedCommitFailed(#[from] openmls::group::MergeCommitError<MemoryStorageError>),

    #[error("Unsupported message content type")]
    UnsupportedMessageContentType,

    #[error("Failed to validate key package")]
    KeyPackageValidationFailed(#[from] openmls::prelude::KeyPackageVerifyError),

    #[error("GroupInfo missing from MlsMessageIn")]
    MlsMessageInMissingGroupInfo,

    #[error("External commit build failed")]
    ExternalCommitBuildFailed(
        #[from] openmls::group::ExternalCommitBuilderError<MemoryStorageError>,
    ),

    #[error("Commit creation failed")]
    CommitCreationFailed(#[from] openmls::group::CreateCommitError),

    #[error("Unable to finalize commit")]
    ExternalCommitFinalizedFailed(
        #[from] openmls::group::ExternalCommitBuilderFinalizeError<MemoryStorageError>,
    ),

    #[error("Failed to generate safety number")]
    SafetyNumberGenerationFailed(#[from] SafetyNumberError),

    #[error("Unable to merge pending commit")]
    MergePendingCommitFailed(#[from] openmls::group::MergePendingCommitError<MemoryStorageError>),

    #[error("Unable to store signature keypair")]
    SignatureKeypairStorageFailed(#[from] MemoryStorageError),

    #[error("Unable to build key package bundle")]
    KeyPackageBundleBuildFaile(#[from] openmls::prelude::KeyPackageNewError),

    #[error("Unable to locate key file")]
    KeyFileNotFound,

    #[error("Unable to load key from file")]
    KeyLoadFailed(#[from] std::io::Error),

    #[error("Unable to extract private key")]
    PrivateKeyExtractionFailed(#[from] ssh_key::Error),

    #[error("Private key decryption failed")]
    PrivateKeyDecryptionFailed,

    #[error("Incorrect username format")]
    IncorrectUsernameFormat,
}

#[derive(Error, Debug)]
pub enum SafetyNumberError {
    #[error("Public key is empty.")]
    EmptyPublicKey,
    #[error("Failed to generate safety number.")]
    QrCodeGenerationFailed,
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
