//! High-level peer connectivity with automatic NAT traversal.
//!
//! This module is internal to the crate. Types are exposed externally only via
//! the `tests` feature module in `lib.rs`.
//!
//! Provides [`PeerNetwork`] and its [`smart_connect`][PeerNetwork::smart_connect]
//! method, which is the **primary API for connecting to peers**. Consumers should use
//! `smart_connect` exclusively—it abstracts away all transport complexity including:
//!
//! - Direct QUIC connections when network conditions allow
//! - Automatic relay fallback when behind Symmetric NAT (CGNAT)
//! - NAT type detection and connection strategy selection
//!
//! # Module Structure
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`transport`] | `PeerNetwork` implementation, smart_connect, DhtNetwork trait impl |
//! | [`tls`] | TLS configuration, Ed25519 certificates, SNI identity pinning |
//! | [`connection`] | Connection cache (LRU, 1000 max), health monitoring, rate limiting |
//! | [`smartsock`] | Unified transport socket with seamless relay↔direct path switching |
//! | [`relay`] | UDP relay forwarder for CRLY-framed packet forwarding |
//!
//! # Security Architecture
//!
//! The network module implements defense-in-depth across all subsystems:
//!
//! ## Identity & Authentication (Zero-Hash Model)
//!
//! - **Identity = Ed25519 public key**: No intermediate hashing, eliminates collision concerns
//! - **SNI-based identity pinning**: Certificate's SPKI public key must match SNI-encoded identity
//! - **Mutual TLS**: Both client and server present certificates for bidirectional verification
//! - **TLS signature verification**: Cryptographic proof of private key possession
//!
//! ## Connection Security
//!
//! | Protection | Limit | Description |
//! |------------|-------|-------------|
//! | Global rate limit | 100/s | Token bucket for all incoming connections |
//! | Per-IP rate limit | 20/s | Token bucket per source IP |
//! | IP tracking | 1,000 | LRU cache bounds memory for IP tracking |
//! | Connection cache | 1,000 | LRU eviction prevents unbounded growth |
//! | Idle timeout | 60s | Stale connections trigger passive health check |
//! | Response size | 1 MB | `MAX_RESPONSE_SIZE` prevents memory exhaustion |
//!
//! ## Relay Security
//!
//! | Protection | Limit | Description |
//! |------------|-------|-------------|
//! | Session count | 10,000 | `MAX_SESSIONS` bounds relay state |
//! | Session timeout | 5 min | Inactive sessions expire automatically |
//! | Session ID | 128-bit | Cryptographically random via `getrandom` |
//! | Frame size | 1,500 | MTU-safe, prevents amplification |
//! | E2E encryption | QUIC | Relay cannot decrypt forwarded packets |
//!
//! ## Path Probing Security
//!
//! | Protection | Description |
//! |------------|-------------|
//! | Random TX IDs | Probe transaction IDs start with random seed |
//! | Timeout expiry | Pending probes expire after 2× probe interval |
//! | Failure limit | 3 consecutive failures mark path as failed |
//! | RTT advantage | Relay must be 50ms+ faster to beat direct path |

pub(crate) mod connection;
pub(crate) mod relay;
pub(crate) mod smartsock;
pub(crate) mod tls;
pub(crate) mod transport;

// Re-export types for internal use
pub(crate) use transport::{
    PeerNetwork,
    generate_ed25519_cert,
    create_server_config,
    create_client_config,
    extract_public_key_from_cert,
};
pub(crate) use relay::{UdpRelayForwarder, CryptoError, MAX_SESSIONS};
pub(crate) use smartsock::SmartSock;
pub(crate) use connection::ConnectionRateLimiter;

