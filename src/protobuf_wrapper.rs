use crate::agora_chat; // Your generated protobuf module
use crate::error::ProtobufWrapperError;
use openmls::prelude::{MlsMessageBodyOut, MlsMessageIn, MlsMessageOut, tls_codec::Deserialize};
use prost::Message;
use std::ops::Deref;

// Assuming your newtype is defined as:
pub struct ProtoMlsMessageOut(pub agora_chat::AgoraPacket);

/// Converts an OpenMLS [`MlsMessageOut`] into a protobuf [`ProtoMlsMessageOut`] wrapper.
///
/// This implementation serializes the MLS message to bytes and wraps it in the appropriate
/// protobuf message structure based on the message body type. It handles all standard MLS
/// message types:
/// - PublicMessage: Application messages visible to all group members
/// - PrivateMessage: Encrypted messages for specific recipients
/// - GroupInfo: Information about group state and configuration
/// - KeyPackage: Public keys used for handshake operations
///
/// The resulting protobuf message includes the MLS 1.0 protocol version and the serialized
/// message bytes wrapped in the appropriate message body variant.
///
/// # Errors
/// Returns [`ProtobufWrapperError::SerializationFailed`] if the MLS message cannot be
/// serialized using the TLS codec.
impl TryFrom<MlsMessageOut> for ProtoMlsMessageOut {
    type Error = ProtobufWrapperError;

    fn try_from(mls_message: MlsMessageOut) -> Result<Self, Self::Error> {
        let mls_message_bytes = mls_message.to_bytes()?;

        let agora_chat_body = match mls_message.body() {
            MlsMessageBodyOut::PublicMessage(_) => {
                let inner = agora_chat::PublicMessage {
                    tls_serialized_public_message: mls_message_bytes,
                };
                agora_chat::agora_packet::Body::PublicMessage(inner)
            }
            MlsMessageBodyOut::PrivateMessage(_) => {
                let inner = agora_chat::PrivateMessage {
                    tls_serialized_private_message: mls_message_bytes,
                };
                agora_chat::agora_packet::Body::PrivateMessage(inner)
            }
            MlsMessageBodyOut::GroupInfo(_) => {
                let inner = agora_chat::GroupInfo {
                    tls_serialized_group_info: mls_message_bytes,
                };
                agora_chat::agora_packet::Body::GroupInfo(inner)
            }
            MlsMessageBodyOut::KeyPackage(_) => {
                // This shouldn't happen in normal flow - KeyPackages are wrapped in UserAnnouncement
                panic!("Bare KeyPackage should not be sent - use UserAnnouncement instead")
            }
            MlsMessageBodyOut::Welcome(_welcome) => {
                unimplemented!(
                    "Welcome messages are not implemented in this wrapper. \n
                This implementation uses the modern external commit pattern with GroupInfo instead.
"
                )
            }
        };

        let agora_chat_message_out = agora_chat::AgoraPacket {
            version: agora_chat::ProtocolVersion::Mls10 as i32,
            body: Some(agora_chat_body),
        };

        Ok(Self(agora_chat_message_out))
    }
}

impl Deref for ProtoMlsMessageOut {
    type Target = agora_chat::AgoraPacket;

    fn deref(&self) -> &Self::Target {
        // Return a reference to the inner data.
        &self.0
    }
}

// This newtype wraps the same generated struct, but its name
// clarifies its role as an incoming message.
#[derive(Debug)]
pub struct ProtoMlsMessageIn(pub agora_chat::AgoraPacket);

impl ProtoMlsMessageIn {
    /// Deserializes a byte slice into our Protobuf wrapper.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtobufWrapperError> {
        let proto_message = agora_chat::AgoraPacket::decode(bytes)?;
        Ok(Self(proto_message))
    }
}

impl TryFrom<ProtoMlsMessageIn> for MlsMessageIn {
    type Error = ProtobufWrapperError;

    fn try_from(wrapper: ProtoMlsMessageIn) -> Result<Self, Self::Error> {
        // The inner proto message from our newtype.
        let proto_message = wrapper.0;

        // Match on the `oneof` body to get the raw MLS message bytes.
        let mls_bytes = match proto_message.body {
            Some(body) => match body {
                agora_chat::agora_packet::Body::PublicMessage(m) => m.tls_serialized_public_message,
                agora_chat::agora_packet::Body::PrivateMessage(m) => {
                    m.tls_serialized_private_message
                }
                agora_chat::agora_packet::Body::GroupInfo(m) => m.tls_serialized_group_info,
                agora_chat::agora_packet::Body::UserAnnouncement(m) => {
                    // UserAnnouncement contains both username and key package
                    // Extract the KeyPackage bytes for MLS processing
                    m.tls_serialized_key_package
                }
                agora_chat::agora_packet::Body::EncryptedGroupInfo(m) => {
                    // EncryptedGroupInfo contains HPKE-encrypted GroupInfo with separate KEM output and ciphertext
                    // Concatenate them for MLS processing (KEM output + ciphertext)
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&m.kem_output);
                    combined.extend_from_slice(&m.ciphertext);
                    combined
                }
            },
            // If the `body` is `None`, the message is invalid.
            None => return Err(ProtobufWrapperError::MlsMessageBodyInvalid),
        };

        // Finally, use the extracted bytes to create an MlsMessageIn.
        // The `?` will convert an MlsMessageError into our ProtoMessageError.
        let mls_message_in = MlsMessageIn::tls_deserialize(&mut &mls_bytes[..])?;

        Ok(mls_message_in)
    }
}
