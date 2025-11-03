# Build stage
FROM rust:1.91-bookworm AS builder

# Install protobuf compiler
RUN apt-get update && \
    apt-get install -y protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/agora-mls

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy proto files (needed for build.rs)
COPY proto ./proto

# Copy build script
COPY build.rs ./

# Copy source code
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies (OpenSSL, CA certificates)
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 agora && \
    mkdir -p /home/agora/.agora-mls && \
    chown -R agora:agora /home/agora

# Copy the binary from builder
COPY --from=builder /usr/src/agora-mls/target/release/agora-mls /usr/local/bin/agora-mls

# Set the user
USER agora
WORKDIR /home/agora

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/agora-mls"]

# Default command (can be overridden)
CMD ["--help"]