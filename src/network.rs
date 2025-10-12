use crate::protobuf_wrapper::ProtoMlsMessageIn;
use crate::{agora_chat::MlsMessageOut, protobuf_wrapper::ProtoMlsMessageOut};
use crate::error::NetworkError;

use prost::Message;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use tracing::{debug, warn};

use tokio::net::UdpSocket;

use anyhow::{Context, Result};

/// Configuration for network operations
///
/// This struct holds the configuration needed for UDP multicast communication
/// in the Agora chat system. All validation is performed during construction
/// via the NetworkConfigBuilder.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// The multicast address to join (must be in 224.0.0.0/4 range)
    pub multicast_address: SocketAddr,
    /// Optional network interface to bind to (defaults to INADDR_ANY)
    pub interface: Option<String>,
    /// Socket buffer size in bytes (between 1KB and 1MB)
    pub buffer_size: usize,
}

/// Builder for creating NetworkConfig instances with validation
///
/// Provides a fluent API for constructing NetworkConfig with comprehensive
/// validation of all parameters. Use this instead of constructing NetworkConfig
/// directly to ensure all network parameters are valid.
///
/// # Example
/// ```rust,ignore
/// let config = NetworkConfigBuilder::new()
///     .multicast_address("239.0.0.1:8080".parse().unwrap())
///     .interface("192.168.1.1".to_string())
///     .buffer_size(65536)
///     .build()
///     .expect("Invalid network configuration");
/// ```
#[derive(Debug)]
pub struct NetworkConfigBuilder {
    multicast_address: Option<SocketAddr>,
    interface: Option<String>,
    buffer_size: Option<usize>,
}

impl NetworkConfigBuilder {
    /// Create a new NetworkConfigBuilder with no defaults set
    pub fn new() -> Self {
        Self {
            multicast_address: None,
            interface: None,
            buffer_size: None,
        }
    }

    /// Create a new NetworkConfigBuilder (alias for new() for backward compatibility)
    pub fn builder() -> Self {
        Self::new()
    }

    /// Set the multicast address (required)
    /// Validates that the address is a valid multicast address in the 224.0.0.0/4 range
    pub fn multicast_address(mut self, address: SocketAddr) -> Self {
        // Basic validation during construction
        if let Err(e) = Self::validate_multicast_address(&address) {
            warn!("Invalid multicast address provided: {}", e);
        }
        self.multicast_address = Some(address);
        self
    }

    /// Set the network interface (optional)
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Set the buffer size with validation
    /// Must be between 1KB and 1MB to prevent memory issues
    pub fn buffer_size(mut self, size: usize) -> Self {
        if let Err(e) = Self::validate_buffer_size(size) {
            warn!("Invalid buffer size provided: {}", e);
        }
        self.buffer_size = Some(size);
        self
    }

    /// Build the NetworkConfig with comprehensive validation
    pub fn build(self) -> Result<NetworkConfig> {
        // Extract and validate multicast address
        let multicast_address = self.multicast_address
            .ok_or_else(|| NetworkError::MissingRequiredField {
                field_name: "multicast_address".to_string()
            })?;

        // Comprehensive multicast address validation
        Self::validate_multicast_address(&multicast_address)
            .map_err(|_| NetworkError::InvalidMulticastAddress {
                address: multicast_address
            })?;

        // Validate port number
        Self::validate_port(multicast_address.port())?;

        // Validate and set buffer size
        let buffer_size = self.buffer_size.unwrap_or(65536); // Default to 64KB
        Self::validate_buffer_size(buffer_size)
            .map_err(|_| NetworkError::InvalidBufferSize { size: buffer_size })?;

        Ok(NetworkConfig {
            multicast_address,
            interface: self.interface,
            buffer_size,
        })
    }

    /// Validate that an address is a proper multicast address
    fn validate_multicast_address(address: &SocketAddr) -> std::result::Result<(), NetworkError> {
        match address {
            SocketAddr::V4(v4_addr) => {
                if !v4_addr.ip().is_multicast() {
                    return Err(NetworkError::InvalidMulticastAddress {
                        address: *address
                    });
                }

                // Additional validation for multicast range
                let octets = v4_addr.ip().octets();
                if octets[0] < 224 || octets[0] > 239 {
                    return Err(NetworkError::InvalidMulticastAddress {
                        address: *address
                    });
                }

                Ok(())
            },
            SocketAddr::V6(_) => Err(NetworkError::UnsupportedIpv6 {
                address: *address
            }),
        }
    }

    /// Validate buffer size is within acceptable limits
    fn validate_buffer_size(size: usize) -> std::result::Result<(), NetworkError> {
        const MIN_BUFFER_SIZE: usize = 1024;   // 1KB minimum
        const MAX_BUFFER_SIZE: usize = 1048576; // 1MB maximum

        if size < MIN_BUFFER_SIZE || size > MAX_BUFFER_SIZE {
            return Err(NetworkError::InvalidBufferSize { size });
        }

        Ok(())
    }

    /// Validate port number is in valid range
    fn validate_port(port: u16) -> std::result::Result<(), NetworkError> {
        // Use ports above the well-known range to avoid conflicts
        if port < 1024 {
            return Err(NetworkError::InvalidPort { port });
        }

        Ok(())
    }
}

impl Default for NetworkConfigBuilder {
    fn default() -> Self {
        Self::builder()
    }
}

/// Manages UDP multicast networking for communicating with other chat clients
pub struct NetworkManager {
    socket: UdpSocket,
    multicast_addr: SocketAddr,
    config: NetworkConfig,
}

impl NetworkManager {
    /// Create a new NetworkManager with the specified configuration
    /// Note: NetworkConfig validation is handled during NetworkConfig creation
    pub async fn new(config: NetworkConfig) -> Result<Self> {
        debug!(
            "Creating NetworkManager for multicast address {}:{}",
            config.multicast_address.ip(),
            config.multicast_address.port()
        );

        // Create the UDP socket using socket2 for advanced configuration
        let socket = Self::create_multicast_socket(&config)
            .context("Failed to create multicast socket - check network configuration and permissions")?;

        // Convert to tokio UdpSocket
        let tokio_socket = UdpSocket::from_std(socket)
            .context("Failed to convert to tokio UDP socket - check if another process is using the port")?;

        let manager = Self {
            socket: tokio_socket,
            multicast_addr: config.multicast_address,
            config,
        };

        debug!("NetworkManager successfully created and configured");
        Ok(manager)
    }

    /// Create and configure a UDP socket for multicast operations
    fn create_multicast_socket(config: &NetworkConfig) -> Result<std::net::UdpSocket> {
        // Create socket with socket2 for advanced configuration
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .context("Failed to create UDP socket")?;
        debug!("Multicast socket created successfully.");

        // Enable SO_REUSEADDR to allow multiple agents on the same machine
        socket.set_reuse_address(true)
            .context("Failed to set SO_REUSEADDR")?;

        // On Unix systems, also set SO_REUSEPORT if available for better performance
        #[cfg(unix)]
        {
            if let Err(e) = socket.set_reuse_port(true) {
                warn!("Failed to set SO_REUSEPORT (continuing anyway): {}", e);
            }
        }

        // Bind to INADDR_ANY with the specified port for better multicast handling
        let bind_addr = SocketAddr::new(
            Ipv4Addr::UNSPECIFIED.into(),
            config.multicast_address.port(),
        );
        socket.bind(&bind_addr.into())
            .context(format!("Failed to bind to port {}", config.multicast_address.port()))?;

        // Join the multicast group
        if let SocketAddr::V4(multicast_v4) = config.multicast_address {
            let multicast_ip = *multicast_v4.ip();

            // Determine the interface to use - default to INADDR_ANY for better compatibility
            let interface_ip = if let Some(ref interface_str) = config.interface {
                interface_str.parse::<Ipv4Addr>().unwrap_or_else(|_| {
                    warn!("Invalid interface IP '{}', using INADDR_ANY", interface_str);
                    Ipv4Addr::UNSPECIFIED
                })
            } else {
                Ipv4Addr::UNSPECIFIED
            };

            socket.join_multicast_v4(&multicast_ip, &interface_ip)
                .context(format!("Failed to join multicast group {}", multicast_ip))?;

            debug!(
                "Successfully joined multicast group {}:{} on interface {}",
                multicast_ip,
                multicast_v4.port(),
                interface_ip
            );
        } else {
            return Err(NetworkError::UnsupportedIpv6 {
                address: config.multicast_address
            }.into());
        }

        // Set socket to non-blocking mode for tokio compatibility
        socket.set_nonblocking(true)
            .context("Failed to set non-blocking mode")?;

        // Convert to std::net::UdpSocket
        Ok(socket.into())
    }

    /// Send a message to the multicast group
    ///
    /// Serializes the packet and sends it to the configured multicast address.
    /// Uses efficient encoding for better performance with large packets.
    pub async fn send_message(&self, packet: ProtoMlsMessageOut) -> Result<()> {
        // Pre-allocate buffer with reasonable initial capacity for better performance
        let mut packet_bytes = Vec::with_capacity(4096);

        // Use the Message trait's encode method which is more efficient
        packet.encode(&mut packet_bytes)
            .context("Failed to encode packet for sending")?;

        self.socket
            .send_to(&packet_bytes, self.multicast_addr)
            .await
            .context(format!("Failed to send packet to multicast address {}", self.multicast_addr))?;

        debug!("Successfully sent {} bytes to multicast group", packet_bytes.len());
        Ok(())
    }

    /// Receive a single message from the multicast group
    ///
    /// Uses a pre-allocated buffer for better performance. The buffer size
    /// is configured during NetworkManager creation.
    pub async fn receive_message(&self) -> Result<ProtoMlsMessageIn> {
        // Pre-allocate buffer with configured size for optimal performance
        let mut buffer = vec![0u8; self.config.buffer_size];

        let (len, remote_addr) = self.socket
            .recv_from(&mut buffer)
            .await
            .context("Failed to receive data from socket")?;

        // Only decode the actual received bytes to avoid processing padding
        let packet = ProtoMlsMessageIn::decode(&buffer[..len])
            .context(format!("Failed to decode packet from {}", remote_addr))?;

        debug!("Received {} bytes from {} (decoded to packet: {:?})", len, remote_addr, packet);

        Ok(packet)
    }
}
