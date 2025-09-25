use crate::agora_chat::ChatPacket;

use prost::Message;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;

use anyhow::{Result, bail};

/// Configuration for network operations
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub multicast_address: SocketAddr,
    pub interface: Option<String>,
    pub buffer_size: usize,
}

/// Builder for creating NetworkConfig instances
#[derive(Debug)]
pub struct NetworkConfigBuilder {
    multicast_address: Option<SocketAddr>,
    interface: Option<String>,
    buffer_size: Option<usize>,
}

impl NetworkConfigBuilder {
    /// Create a new NetworkConfigBuilder with no defaults set
    pub fn builder() -> Self {
        Self {
            multicast_address: None,
            interface: None,
            buffer_size: None,
        }
    }

    /// Set the multicast address (required)
    pub fn multicast_address(mut self, address: SocketAddr) -> Self {
        self.multicast_address = Some(address);
        self
    }

    /// Set the network interface (optional)
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Set the buffer size
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = Some(size);
        self
    }

    /// Build the NetworkConfig, validating required fields
    pub fn build(self) -> Result<NetworkConfig> {
        let multicast_address = self.multicast_address
            .ok_or_else(|| anyhow::anyhow!("multicast_address is required"))?;

        // Validate that the address is a multicast address
        if !multicast_address.ip().is_multicast() {
            bail!(
                "Address {} is not a valid multicast address",
                multicast_address.ip()
            );
        }

        Ok(NetworkConfig {
            multicast_address,
            interface: self.interface,
            buffer_size: self.buffer_size.unwrap_or(65536), // Default to 64KB
        })
    }
}

impl Default for NetworkConfigBuilder {
    fn default() -> Self {
        Self::builder()
    }
}

// impl Default for NetworkConfig {
//     fn default() -> Self {
//         Self {
//             multicast_address: "239.255.255.250:8080".parse().unwrap(), // unwrap ok because this will never fail
//             interface: None,
//             buffer_size: 65536, // 64KB buffer
//         }
//     }
// }

/// Manages UDP multicast networking for communicating with other chat clients
pub struct NetworkManager {
    socket: UdpSocket,
    multicast_addr: SocketAddr,
    config: NetworkConfig,
}

impl NetworkManager {
    /// Create a new NetworkManager with the specified configuration
    pub async fn new(config: NetworkConfig) -> Result<Self> {
        // Validate multicast address
        if !config.multicast_address.ip().is_multicast() {
            bail!(
                "Address {} is not a valid multicast address",
                config.multicast_address.ip()
            );
        }

        // Create the UDP socket using socket2 for advanced configuration
        let socket = Self::create_multicast_socket(&config)?;

        // Convert to tokio UdpSocket
        let tokio_socket = UdpSocket::from_std(socket)?;

        let manager = Self {
            socket: tokio_socket,
            multicast_addr: config.multicast_address,
            config,
        };

        Ok(manager)
    }

    /// Create and configure a UDP socket for multicast operations
    fn create_multicast_socket(config: &NetworkConfig) -> Result<std::net::UdpSocket> {
        // Create socket with socket2 for advanced configuration
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        // Enable SO_REUSEADDR to allow multiple agents on the same machine
        socket.set_reuse_address(true)?;

        // Disable loopback so we don't receive our own messages
        // socket.set_multicast_loop_v4(false)?;

        // On Unix systems, also set SO_REUSEPORT if available
        #[cfg(unix)]
        {
            if let Err(e) = socket.set_reuse_port(true) {
                tracing::warn!("Failed to set SO_REUSEPORT: {}", e);
            }
        }

        // Bind to the multicast address
        let bind_addr = SocketAddr::new(
            std::net::Ipv4Addr::UNSPECIFIED.into(),
            config.multicast_address.port(),
        );
        socket.bind(&bind_addr.into())?;

        // Join the multicast group
        if let SocketAddr::V4(multicast_v4) = config.multicast_address {
            let multicast_ip = *multicast_v4.ip();

            // Determine the interface to use
            let interface_ip = if let Some(ref interface_str) = config.interface {
                // Try to parse as IP address first
                interface_str
                    .parse::<Ipv4Addr>()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED)
            } else {
                Ipv4Addr::UNSPECIFIED
            };

            socket.join_multicast_v4(&multicast_ip, &interface_ip)?;

            tracing::debug!(
                "Joined multicast group {}:{} on interface {}",
                multicast_ip,
                multicast_v4.port(),
                interface_ip
            );
        } else {
            bail!("IPv6 multicast not currently supported".to_string(),);
        }

        // Set socket to non-blocking mode for tokio compatibility
        socket.set_nonblocking(true)?;

        // Convert to std::net::UdpSocket
        Ok(socket.into())
    }

    /// Send a message to the multicast group
    pub async fn send_message(&self, packet: ChatPacket) -> Result<()> {
        let packet_bytes = packet.encode_to_vec();

        self.socket
            .send_to(&packet_bytes, self.multicast_addr)
            .await?;
        Ok(())
    }

    /// Receive a single message from the multicast group
    pub async fn receive_message(&self) -> Result<ChatPacket> {
        let mut buffer = vec![0u8; self.config.buffer_size];

        let (len, _) = self.socket.recv_from(&mut buffer).await?;
        // Deserialize the received bytes into a ChatPacket
        let packet = ChatPacket::decode(&buffer[..len])?;

        Ok(packet)
    }
}
