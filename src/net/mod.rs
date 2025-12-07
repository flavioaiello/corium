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

mod connection;
mod relay;
mod smartsock;
mod tls;
mod transport;

// Re-export types for tests feature (pub) or internal use (pub(crate))
#[cfg(feature = "tests")]
pub use transport::{
    PeerNetwork,
    ALPN,
    generate_ed25519_cert,
    create_server_config,
    create_client_config,
    extract_public_key_from_cert,
    verify_peer_identity,
};
#[cfg(feature = "tests")]
pub use connection::SmartConnection;
#[cfg(feature = "tests")]
pub use relay::{
    UdpRelayForwarder, RelayInfo, NatType, NatReport, CryptoError,
    detect_nat_type, generate_session_id, DIRECT_CONNECT_TIMEOUT,
};

#[cfg(not(feature = "tests"))]
pub(crate) use transport::{
    PeerNetwork,
    ALPN,
    generate_ed25519_cert,
    create_server_config,
    create_client_config,
    extract_public_key_from_cert,
    verify_peer_identity,
};
#[cfg(not(feature = "tests"))]
pub(crate) use connection::SmartConnection;
#[cfg(not(feature = "tests"))]
pub(crate) use relay::{
    UdpRelayForwarder, RelayInfo, NatType, NatReport, CryptoError,
    detect_nat_type, generate_session_id, DIRECT_CONNECT_TIMEOUT,
};

// Crate-internal re-exports (used by node.rs, server.rs) - always pub(crate)
pub(crate) use smartsock::SmartSock;
pub(crate) use connection::{ConnectionRateLimiter, MAX_CONNECTIONS_PER_IP_PER_SECOND};
pub(crate) use relay::MAX_SESSIONS;
