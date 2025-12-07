# Build the chatroom example in a Rust toolchain image
FROM rust:1.74 AS builder
WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
COPY tests ./tests
RUN cargo build --release --example chatroom

# Runtime stage contains only the compiled binary and minimal deps
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/examples/chatroom /usr/local/bin/chatroom

EXPOSE 4433
ENTRYPOINT ["/usr/local/bin/chatroom"]
