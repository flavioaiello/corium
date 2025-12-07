//! High-level peer connectivity with automatic NAT traversal.
//!
//! This module provides [`PeerNetwork`] and its [`smart_connect`][PeerNetwork::smart_connect]
//! method, which is the **primary API for connecting to peers**. Consumers should use
//! `smart_connect` exclusively—it abstracts away all transport complexity including:
//!
//! - Direct QUIC connections when network conditions allow
//! - Automatic relay fallback when behind Symmetric NAT (CGNAT)
//! - NAT type detection and connection strategy selection
//! - Connection upgrade probing (relay → direct via new connection when conditions improve)
//!
//! # Module Structure
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`transport`] | `PeerNetwork` implementation, smart_connect, DhtNetwork trait impl |
//! | [`tls`] | TLS configuration, Ed25519 certificates, SNI identity pinning |
//! | [`connection`] | Connection cache (LRU, 1000 max), health monitoring, rate limiting |
//! | [`smartsock`] | Unified transport socket with seamless relay↔direct path switching |
//! | [`holepunch`] | NAT hole punching coordination, rendezvous registry (5000 pending max) |
//! | [`relay`] | UDP relay forwarder for CRLY-framed packet forwarding |
//!
//! # Re-exports
//!
//! Key types are re-exported for convenience:
//! - [`PeerNetwork`]: Main network interface
//! - [`SmartConnection`]: Transport-agnostic connection handle
//! - [`UdpRelayForwarder`]: Relay packet forwarder for NAT traversal
//! - [`ALPN`]: Protocol identifier (`corium`)
//! - TLS utilities: `generate_ed25519_cert`, `create_server_config`, `create_client_config`

pub mod connection;
pub mod holepunch;
pub mod relay;
pub mod smartsock;
pub mod tls;
pub mod transport;

// Re-export types used by other internal modules and lib.rs
pub use transport::{
    PeerNetwork,
    ALPN,
    generate_ed25519_cert,
    create_server_config,
    create_client_config,
    extract_public_key_from_cert,
    verify_peer_identity,
};

pub use connection::SmartConnection;
pub use relay::{
    UdpRelayForwarder, RelayInfo, NatType, NatReport, CryptoError,
    detect_nat_type, generate_session_id, DIRECT_CONNECT_TIMEOUT,
};
