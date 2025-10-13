# Agora MLS

![Rust Version](https://img.shields.io/badge/rust-2024%20edition-orange.svg)

**A secure, distributed chat application using Messaging Layer Security (MLS) over UDP multicast**

Agora MLS is a distributed chat application that leverages the OpenMLS protocol to provide end-to-end encrypted group messaging over UDP multicast. Built with modern Rust async patterns and an actor-based architecture, it offers a secure foundation for decentralized communication without relying on centralized servers.

---

## Overview

Agora MLS combines the security guarantees of the Messaging Layer Security (MLS) protocol with the simplicity of UDP multicast networking to create a serverless chat system. Each participant maintains their own identity and cryptographic state, enabling secure group conversations that resist eavesdropping and tampering.

### Why Agora MLS?

**Problem:** Traditional chat applications rely on centralized servers that become single points of failure and control. Peer-to-peer solutions often lack proper security or are difficult to set up.

**Solution:** Agora MLS provides:
- ✨ **End-to-End Encryption** via the MLS protocol (IETF RFC 9420)
- 🔒 **Decentralized Architecture** with no central server required
- 🚀 **Zero-Configuration Networking** using UDP multicast
- ⚡ **Actor-Based Concurrency** for responsive, scalable performance
- 🔐 **Identity Verification** through safety numbers (similar to Signal)

### Key Differentiators

- **True Decentralization**: No server infrastructure needed - participants communicate directly via multicast
- **Standards-Based Security**: Uses OpenMLS, an implementation of the IETF MLS protocol
- **Modern Rust Architecture**: Built on tokio async runtime with kameo actor framework
- **SSH Key Integration**: Leverages existing Ed25519 SSH keys for identity

---

## Features

- 🔐 **MLS Protocol Integration**: Implements the Messaging Layer Security protocol for group encryption
- 🌐 **UDP Multicast Communication**: Serverless networking using UDP multicast groups
- 🎭 **Identity Management**: Ed25519-based cryptographic identities with SSH key support
- 🔄 **Actor-Based Architecture**: Concurrent message processing using the kameo actor framework
- 💬 **Interactive CLI**: Full-featured command-line interface with rustyline support and command parsing
- 🔢 **Safety Numbers**: Generate identity verification fingerprints for security
- 📦 **Protocol Buffers**: Efficient message serialization with prost and protobuf definitions
- 🛡️ **End-to-End Encryption**: Secure group messaging with forward secrecy
- 🔍 **Structured Logging**: Comprehensive tracing with configurable verbosity levels
- ⚙️ **Flexible Configuration**: Multiple network interfaces and custom multicast addresses
- 👥 **Group Management**: Create and manage multiple chat groups
- 💬 **Private Messaging**: Send direct messages between users
- 🔐 **SSH Key Integration**: Use existing SSH keys for identity management

---

## Quick Start

### Prerequisites

- Rust 2024 edition or later
- An Ed25519 SSH key pair (or the tool will guide you to create one)

### Installation

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

### Basic Usage Examples

Start a chat session with default settings:

```bash
# Use your default SSH key and join with a random chat ID
cargo run --release

# Or use the binary directly if installed
agora-mls
```

This will:
- Use your default SSH key (`~/.ssh/id_ed25519`)
- Generate a random chat ID
- Join the default multicast group (`239.255.255.250:8080`)

### Interactive Commands

Once running, use these commands in the chat interface:

- `/invite <nick> [password]` - Invite a user to join a channel
- `/leave [channel]` - Leave current or specified channel
- `/msg <user> <message>` - Send a private message
- `/create <name>` - Create a new group
- `/users` - List users in current channel
- `/groups` - List available groups
- `/group [name]` - Display or set active group
- `/nick [nickname]` - Display or set your nickname
- `/safety` - Generate safety number for identity verification
- `/quit` or `/q` - Exit the application
- Simply type a message and press Enter to send it to the group

---

## Installation

### From Source

```bash
git clone https://github.com/<username>/agora-mls
cd agora-mls
cargo build --release
./target/release/agora-mls
```

### Development Build

```bash
# Build in debug mode (automatically compiles protobuf files)
cargo build

# Run with debug logging
cargo run -- --log-level debug

# Run with trace logging for detailed diagnostics
cargo run -- --log-level trace
```

### Platform-Specific Notes

**Linux**: Requires multicast support in your network stack (enabled by default in most distributions)

**macOS**: Multicast should work out of the box on most networks

**Windows**: May require firewall configuration to allow UDP multicast traffic

---

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────┐
│                    App                          │
│  (Main coordinator and initialization)          │
└────────────┬────────────────────────────────────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
┌─────────┐     ┌──────────┐
│Identity │     │ Network  │
│ Actor   │     │ Manager  │
└────┬────┘     └────┬─────┘
     │               │
     ▼               ▼
┌──────────┐   ┌───────────┐
│OpenMLS   │   │Processor  │
│Actor     │   │           │
└────┬─────┘   └─────┬─────┘
     │               │
     └───────┬───────┘
             ▼
      ┌────────────┐
      │   State    │
      │   Actor    │
      └────────────┘
```

### Actor System

Agora MLS uses the **kameo** actor framework for concurrent message processing:

- **IdentityActor**: Manages cryptographic identity and SSH key operations
- **OpenMlsActor**: Handles MLS protocol state, encryption, and decryption operations
- **StateActor**: Coordinates overall application state and group management
- **Processor**: Routes messages between network, CLI, and state actors
- **NetworkManager**: Handles UDP multicast communication

### Security Model

1. **Identity**: Each participant has an Ed25519 keypair
2. **Key Packages**: MLS key packages are exchanged during group joins
3. **Group State**: Encrypted group state synchronized via multicast
4. **Safety Numbers**: Identity verification through numeric fingerprints

---

## Documentation

- [OpenMLS Documentation](https://docs.rs/openmls)
- [Kameo Actor Framework](https://docs.rs/kameo)
- [MLS Protocol (RFC 9420)](https://datatracker.ietf.org/doc/html/rfc9420)

For detailed API documentation:

```bash
cargo doc --open
```

---

## Configuration

### Environment Variables

```bash
# Set default log level
export RUST_LOG=agora_mls=debug

# Configure tokio runtime
export TOKIO_WORKER_THREADS=4
```

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

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/<username>/agora-mls
cd agora-mls

# Build
cargo build

# Run tests
cargo test

# Run with development logging
cargo run -- --log-level trace
```

### Project Structure

```
agora-mls/
├── src/
│   ├── main.rs              # Application entry point
│   ├── lib.rs               # Library exports and module definitions
│   ├── app.rs               # Main application coordinator
│   ├── cli.rs               # Command-line argument parsing
│   ├── config.rs            # Configuration management
│   ├── command.rs           # Interactive command definitions
│   ├── processor.rs         # Message processing and task coordination
│   ├── network.rs           # UDP multicast networking
│   ├── identity_actor.rs    # Cryptographic identity management
│   ├── openmls_actor.rs     # MLS protocol handler
│   ├── state_actor.rs       # Application state coordination
│   ├── safety_number.rs     # Identity verification
│   ├── error.rs             # Error types
│   ├── protobuf_wrapper.rs  # Protocol buffer message handling
│   └── agora_chat.rs        # Generated protobuf code
├── proto/
│   └── chat.proto           # Protocol buffer definitions
├── build.rs                 # Build script for protobuf compilation
├── Cargo.toml               # Dependencies and metadata
└── Cargo.lock               # Dependency version locks
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with logging
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Code Style

This project uses:
- `rustfmt` for code formatting
- `clippy` for linting

```bash
cargo fmt
cargo clippy -- -D warnings
```

### Reporting Issues

Please use GitHub Issues to report bugs or suggest features. Include:
- Rust version (`rustc --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior

---

## Performance Considerations

- **Multicast Efficiency**: UDP multicast reduces bandwidth compared to unicast
- **Actor Parallelism**: Concurrent message processing via tokio async runtime
- **Zero-Copy**: Protocol buffers with minimal serialization overhead
- **Buffer Sizing**: Configurable network buffer size (default 64KB)

### Benchmarks

Performance depends on:
- Network latency and bandwidth
- Number of group participants
- Message frequency and size
- CPU capabilities for cryptographic operations

---

## Security Considerations

⚠️ **Important Security Notes**:

1. **Network Isolation**: Multicast traffic is visible to all devices on the local network segment
2. **Key Management**: Protect your private key file with appropriate filesystem permissions
3. **Safety Numbers**: Always verify safety numbers when adding new participants
4. **Development Status**: This is a prototype/research project - use with appropriate caution

### Threat Model

**Protected Against**:
- Eavesdropping (end-to-end encryption)
- Message tampering (authenticated encryption)
- Impersonation (cryptographic signatures)
- Forward/backward secrecy (key rotation)

**Not Protected Against**:
- Network-level traffic analysis
- Local network attackers with physical access
- Compromised endpoints

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

**A**: Multicast eliminates the need for server infrastructure, reducing complexity and central points of failure. It works well for local network communication and serves as a foundation for understanding decentralized protocols.

### Q: Can I use this over the internet?

**A**: UDP multicast is typically limited to local networks. For internet usage, you'd need to implement NAT traversal or use a relay server (defeating the serverless design).

### Q: Is this production-ready?

**A**: No. This is a research/prototype project demonstrating MLS and actor-based architecture. Use established solutions like Signal or Matrix for production needs.

### Q: How do I verify someone's identity?

**A**: Use the `/safety` command to display the safety number, then verify it out-of-band (in person, phone call, etc.) with the other participant.

### Q: What happens if someone's key is compromised?

**A**: MLS provides forward secrecy and post-compromise security. Remove the compromised participant and re-add them with a new key to restore security.

---

**Made with 🦀 and ❤️ by the Rust community**

---

For more information, questions, or to contribute, visit the [GitHub repository](https://github.com/devfire/agora-mls).