# Agora MLS

![Rust Version](https://img.shields.io/badge/rust-2024%20edition-orange.svg)

**A secure, distributed chat application using Messaging Layer Security (MLS) over UDP multicast**

Agora MLS is a distributed chat application that leverages the OpenMLS protocol to provide end-to-end encrypted group messaging over UDP multicast. 

---

## Overview

Agora MLS combines the security guarantees of the Messaging Layer Security (MLS) protocol with the simplicity of UDP multicast networking to create a serverless chat system. Each participant maintains their own identity and cryptographic state, enabling secure group conversations that resist eavesdropping and tampering.

### Why Agora MLS?

**Problem:** Traditional chat applications rely on centralized servers that become single points of failure and control. Peer-to-peer solutions often lack proper security or are difficult to set up.

**Solution:** Agora MLS provides:
- **End-to-End Encryption** via the OpenMLS protocol (IETF RFC 9420)
- **Decentralized Architecture** with no central server required
- **Zero-Configuration Networking** using UDP multicast
- **Actor-Based Concurrency** using [kameo](https://docs.page/tqwewe/kameo) for responsive, scalable performance
- **Identity Verification** through safety numbers (similar to Signal)

---

## Quick Start

### Prerequisites

**Option 1: Using Docker** (Recommended for quick setup)
- Docker installed on your system

**Option 2: Building from Source**
- Rust 2024 edition or later
- An Ed25519 SSH key pair (this the only SSH type that will work!)
- Protocol Buffers compiler (protoc) - installed automatically by cargo

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

### Using Docker

```bash
# Clone and build
git clone https://github.com/devfire/agora-mls
cd agora-mls
docker build -t agora-mls .

# Run
docker run --rm --network host agora-mls
```

See the [Docker Deployment](#docker-deployment) section for detailed usage.

### From Source

```bash
git clone https://github.com/devfire/agora-mls
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

### Docker Deployment

Agora MLS can be deployed using Docker for consistent, isolated execution across different environments.

#### Building the Docker Image

```bash
# Build the image
docker build -t agora-mls .

# Build with a specific tag
docker build -t agora-mls:latest .
```

The Dockerfile uses a multi-stage build process:
- **Build stage**: Compiles the Rust application with all dependencies
- **Runtime stage**: Creates a minimal image (~100MB) with only the binary and runtime dependencies

#### Running with Docker

Basic usage:
```bash
# Display help
docker run --rm agora-mls

# Run with default settings
docker run --rm --network host agora-mls
```

**Important**: Use `--network host` to enable UDP multicast communication on Linux. On macOS and Windows, Docker networking may require additional configuration for multicast support.

Advanced usage with custom options:
```bash
# Run with custom chat ID and multicast address
docker run --rm --network host agora-mls \
  --chat-id my-secure-chat \
  --multicast-address 239.1.2.3:9000

# Run with persistent storage for SSH keys
docker run --rm --network host \
  -v ~/.ssh:/home/agora/.ssh:ro \
  agora-mls --key-file /home/agora/.ssh/id_ed25519

# Run interactively with mounted data directory
docker run -it --rm --network host \
  -v $(pwd)/data:/home/agora/.agora-mls \
  agora-mls

# Enable debug logging
docker run --rm --network host agora-mls --log-level debug
```

#### Docker Compose Example

Create a `docker-compose.yml` file:

```yaml
services:
  agora-mls:
    build: .
    network_mode: host
    volumes:
      - ~/.ssh:/home/agora/.ssh:ro
      - ./data:/home/agora/.agora-mls
    command: >
      --chat-id my-chat
      --log-level info
    stdin_open: true
    tty: true
```

Run with:
```bash
docker-compose up
```

#### Docker Networking Notes

- **Linux**: Use `--network host` for UDP multicast to work properly
- **macOS/Windows**: Docker Desktop may require additional network configuration for multicast
- The default multicast address `239.255.255.250:8080` works on most local networks
- Firewall rules may need adjustment to allow UDP multicast traffic

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
│   ├── main.rs                   # Application entry point
│   ├── lib.rs                    # Library exports and module definitions
│   ├── app.rs                    # Main application coordinator
│   ├── cli.rs                    # Command-line argument parsing
│   ├── config.rs                 # Configuration management
│   ├── command.rs                # Interactive command definitions
│   ├── processor.rs              # Message processing and task coordination
│   ├── network.rs                # UDP multicast networking
│   ├── crypto_identity_actor.rs  # Cryptographic identity management
│   ├── safety_number.rs          # Identity verification
│   ├── error.rs                  # Error types
│   ├── protobuf_wrapper.rs       # Protocol buffer message handling
│   └── agora_chat.rs             # Generated protobuf code
├── proto/
│   └── chat.proto                # Protocol buffer definitions
├── build.rs                      # Build script for protobuf compilation
├── Dockerfile                    # Docker container definition
├── .dockerignore                 # Docker build exclusions
├── Cargo.toml                    # Dependencies and metadata
└── Cargo.lock                    # Dependency version locks
```

### Running Tests

HA, kidding: there are no tests yet.

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
- Network-level traffic analysis (although you can't really tell who is who, exactly!)
- Replay attacks, that's WIP!
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

**Made with Rust by the Rust community**

---

For more information, questions, or to contribute, visit the [GitHub repository](https://github.com/devfire/agora-mls).
