# Agora MLS

![Rust Version](https://img.shields.io/badge/rust-2024%20edition-orange.svg)

**A secure, distributed chat application using Messaging Layer Security (MLS) over UDP multicast**

Agora MLS is a distributed chat application that leverages the MLS protocol to provide end-to-end encrypted group messaging over UDP multicast. 

---

## Overview

Agora MLS combines the security guarantees of the Messaging Layer Security (MLS) protocol with the simplicity of UDP multicast networking to create a serverless chat system. 

Each participant maintains their own identity (loaded from a local SSH key) and cryptographic state, enabling secure group conversations.

### Why Agora MLS?

**Problem:** Traditional chat applications rely on centralized servers that become single points of failure and control. Peer-to-peer solutions often lack proper security or are difficult to set up.

**Solution:** Agora MLS provides:
- **End-to-End Encryption** via the OpenMLS protocol (IETF RFC 9420)
- **Decentralized Architecture** with no central server required
- **Zero-Configuration Networking** using UDP multicast
- **Actor-Based Concurrency** using [kameo](https://docs.page/tqwewe/kameo) for scalable performance (and because actors are cool, duh)
- **Identity Verification** through safety numbers (similar to Signal)

---

## Quick Start

### Prerequisites

**Option 1: Using Docker** (Recommended for quick setup)
- Docker installed on your system

**Option 2: Building from Source**
- Rust 2024 edition or later
- An Ed25519 SSH key pair (NOTE: this the only SSH type that will work!)
- Protocol Buffers compiler (protoc) - installed automatically by cargo, so you shouldn't have to worry about it.

### Installation

#### Using Docker

```bash
# Clone the repository
git clone https://github.com/devfire/agora-mls
cd agora-mls

# Build the Docker image
docker build -t agora-mls .

# Run the application
docker run --rm --network host agora-mls
```
**Important**: Use `--network host` to enable UDP multicast communication on Linux. On macOS and Windows, Docker networking may require additional configuration for multicast support.

#### From Source

```bash
# Clone the repository
git clone https://github.com/devfire/agora-mls
cd agora-mls

# Build the project (protobuf compilation happens automatically)
cargo build --release

# Run the application
cargo run --release

# Or install globally for easier access
cargo install --path .
```

---

## Usage

### Basic Usage

Start a chat session with default settings:

```bash
agora-mls
```

This will:
- Use your default SSH key (`~/.ssh/id_ed25519`)
- Generate a random chat ID
- Join the default multicast group (`239.255.255.250:8080`)

### Advanced Usage

```bash
# Specify a custom chat ID and multicast address
agora-mls --chat-id my-secure-chat --multicast-address 239.1.2.3:9000

# Use a specific SSH key and network interface
agora-mls --key-file ~/.ssh/custom_key --interface eth0

# Enable debug logging
agora-mls --log-level debug
```

### Command-Line Options

```
Options:
  -c, --chat-id <ID>                    Unique identifier for this chat [default: random UUID]
  -l, --log-level <LEVEL>              Set the log level [default: info]
                                         [possible values: error, warn, info, debug, trace]
  -m, --multicast-address <ADDR:PORT>  UDP multicast address [default: 239.255.255.250:8080]
  -i, --interface <INTERFACE>          Network interface to bind to (e.g., 'eth0', '192.168.1.100')
  -k, --key-file <PATH>                Private key file path [default: ~/.ssh/id_ed25519]
  -h, --help                           Print help
  -V, --version                        Print version
```

---

## Configuration

### SSH Key Setup

If you don't have an Ed25519 SSH key:

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

Then specify it with:

```bash
agora-mls --key-file ~/.ssh/id_ed25519
```

---

## Security Considerations

**Important Security Notes**:

1. **Network Isolation**: Multicast traffic is visible to all devices on the local network segment (but that's OK because everything is encrypted!)
2. **Key Management**: Protect your private key file with appropriate filesystem permissions
3. **Safety Numbers**: Always verify safety numbers when adding new participants
4. **Development Status**: This is a prototype/research project - use with appropriate caution (OBVIOUSLY)

### Threat Model

**Protected Against**:
- Eavesdropping (end-to-end encryption)
- Message tampering (authenticated encryption)
- Impersonation (cryptographic signatures)
- Forward/backward secrecy (key rotation)

**Not Protected Against**:
- Network-level traffic analysis (although you can't really tell who is who, exactly!)
- Local network attackers with physical access (can cause mischief but addressing malicious actors is WIP)

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
Copyright (c) 2025 Agora MLS Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## Acknowledgments

This project builds upon excellent work from the Rust community:

- **[OpenMLS](https://github.com/openmls/openmls)**: MLS protocol implementation
- **[Kameo](https://github.com/tqwewe/kameo)**: Actor framework
- **[Tokio](https://tokio.rs/)**: Async runtime
- **[Clap](https://github.com/clap-rs/clap)**: CLI parsing
- **[Dalek Cryptography](https://github.com/dalek-cryptography)**: Ed25519 and X25519 implementations

### Related Projects

- [OpenMLS](https://github.com/openmls/openmls) - Rust implementation of MLS
- [Signal Protocol](https://signal.org/docs/) - Inspiration for safety numbers
- [Matrix](https://matrix.org/) - Decentralized communication protocol

---

## Roadmap

- [ ] **Group Management**: Add/remove participants dynamically
- [ ] **Persistent Storage**: Save conversation history and state
- [ ] **NAT Traversal**: Support for cross-network communication
- [ ] **GUI Client**: Desktop application with graphical interface
- [ ] **Mobile Support**: iOS and Android clients
- [ ] **File Transfer**: Secure file sharing capabilities
- [ ] **Voice/Video**: Real-time audio/video communication

---

## FAQ

### Q: Why UDP multicast instead of a server?

**A**: Multicast eliminates the need for server infrastructure, reducing complexity and central points of failure. It works well for local network communication and serves as a foundation for understanding decentralized protocols. This is like.. ZEROCONF and everything. :)

### Q: Can I use this over the internet?

**A**: UDP multicast is typically limited to local networks. For internet usage, you'd need to implement NAT traversal or use a relay server (defeating the serverless design). So.. no?

### Q: Is this production-ready?

**A**: No. This is a research/prototype project demonstrating MLS and actor-based architecture. Use established solutions like Signal or Matrix for production needs.

### Q: How do I verify someone's identity?

**A**: Use the `/safety` command to display the safety number, then verify it out-of-band (in person, phone call, etc.) with the other participant.

### Q: What happens if someone's key is compromised?

**A**: MLS provides forward secrecy and post-compromise security. Remove the compromised participant and re-add them with a new key to restore security.

---

**Made with Rust by the Rust community**

---

For more information, questions, or to contribute, visit the [GitHub repository](https://github.com/devfire/agora-mls).
