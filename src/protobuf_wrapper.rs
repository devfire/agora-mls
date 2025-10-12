use crate::agora_chat; // Your generated protobuf module
use openmls::prelude::{MlsMessageBodyOut, MlsMessageOut};
use std::ops::Deref;

// Assuming your newtype is defined as:
pub struct ProtoMlsMessageOut(pub agora_chat::MlsMessageOut);

/// Converts an OpenMLS [`MlsMessageOut`] into a protobuf [`ProtoMlsMessageOut`] wrapper.
///
/// This implementation serializes the MLS message to bytes and wraps it in the appropriate
/// protobuf message structure based on the message body type. It handles all standard MLS
/// message types:
/// - PublicMessage: Application messages visible to all group members
/// - PrivateMessage: Encrypted messages for specific recipients
/// - Welcome: Messages used to add new members to a group
/// - GroupInfo: Information about group state and configuration
/// - KeyPackage: Public keys used for handshake operations
///
/// The resulting protobuf message includes the MLS 1.0 protocol version and the serialized
/// message bytes wrapped in the appropriate message body variant.
///
/// # Panics
/// Panics if the MLS message cannot be serialized using the TLS codec.
impl From<MlsMessageOut> for ProtoMlsMessageOut {
    fn from(mls_message: MlsMessageOut) -> Self {
        let mls_message_bytes = mls_message
            .to_bytes()
            .expect("Failed to serialize MLS message using tls_codec");

        let agora_chat_body = match mls_message.body() {
            MlsMessageBodyOut::PublicMessage(_) => {
                let inner = agora_chat::PublicMessage {
                    tls_serialized_public_message: mls_message_bytes,
                };
                agora_chat::mls_message_out::Body::PublicMessage(inner)
            }
            MlsMessageBodyOut::PrivateMessage(_) => {
                let inner = agora_chat::PrivateMessage {
                    tls_serialized_private_message: mls_message_bytes,
                };
                agora_chat::mls_message_out::Body::PrivateMessage(inner)
            }
            MlsMessageBodyOut::Welcome(_) => {
                let inner = agora_chat::Welcome {
                    tls_serialized_welcome_message: mls_message_bytes,
                };
                agora_chat::mls_message_out::Body::Welcome(inner)
            }
            MlsMessageBodyOut::GroupInfo(_) => {
                let inner = agora_chat::GroupInfo {
                    tls_serialized_group_info: mls_message_bytes,
                };
                agora_chat::mls_message_out::Body::GroupInfo(inner)
            }
            MlsMessageBodyOut::KeyPackage(_) => {
                let inner = agora_chat::KeyPackage {
                    tls_serialized_key_package: mls_message_bytes,
                };
                agora_chat::mls_message_out::Body::KeyPackage(inner)
            }
        };

        let agora_chat_message_out = agora_chat::MlsMessageOut {
            version: agora_chat::ProtocolVersion::Mls10 as i32,
            body: Some(agora_chat_body),
        };

        Self(agora_chat_message_out)
    }
}

impl Deref for ProtoMlsMessageOut {
    type Target = agora_chat::MlsMessageOut;

    fn deref(&self) -> &Self::Target {
        // Return a reference to the inner data.
        &self.0
    }
}
