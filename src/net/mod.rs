//! High-level peer connectivity with automatic NAT traversal.
//!
//! This module provides [`PeerNetwork`] and its [`smart_connect`][PeerNetwork::smart_connect]
//! method, which is the **primary API for connecting to peers**. Consumers should use
//! `smart_connect` exclusively—it abstracts away all transport complexity including:
//!
//! - Direct QUIC connections when network conditions allow
//! - Automatic relay fallback when behind Symmetric NAT (CGNAT)
//! - NAT type detection and connection strategy selection
//! - Connection upgrade probing (relay → direct when conditions improve)
//!
//! # Module Structure
//!
//! - [`transport`]: Core `PeerNetwork` implementation, smart_connect, RPC handling
//! - [`tls`]: TLS/certificate handling, Ed25519 cert generation, SNI identity pinning
//! - [`connection`]: Connection caching, health monitoring, `SmartConnection`
//! - [`path`]: Path probing, candidate discovery, connection management
//! - [`holepunch`]: NAT hole punching coordination and registry

pub mod connection;
pub mod holepunch;
pub mod path;
pub mod tls;
pub mod transport;

// Re-export primary types from transport (main API surface)
pub use transport::{
    PeerNetwork,
    ALPN,
    UPGRADE_PROBE_INTERVAL,
    generate_ed25519_cert,
    create_server_config,
    create_client_config,
    extract_public_key_from_cert,
    verify_peer_identity,
};

// Re-export connection types
pub use connection::{
    CachedConnection,
    ConnectionHealthStats,
    ConnectionHealthStatus,
    ConnectionHealthSummary,
    ConnectionRateLimiter,
    SmartConnection,
    CONNECTION_HEALTH_CHECK_INTERVAL,
    MAX_CACHED_CONNECTIONS,
    MAX_CONNECTIONS_PER_IP_PER_SECOND,
    MAX_GLOBAL_CONNECTIONS_PER_SECOND,
    MAX_TRACKED_IPS,
};

// Re-export path types
pub use path::{
    ConnectionManager,
    ConnectionStats,
    PathCandidate,
    PathMessage,
    PathProbe,
    PathProber,
    PathReply,
    PathState,
    PathStats,
    ReachMe,
    MAX_PATH_PROBERS,
    MAX_PROBE_FAILURES,
    PATH_PROBE_INTERVAL,
    PATH_STALE_TIMEOUT,
    PROBE_TIMEOUT,
};

// Re-export hole punch types
pub use holepunch::{
    HolePunchRegistry,
    HolePunchResult,
    HolePunchState,
    HolePuncher,
    HOLE_PUNCH_CLOCK_SKEW_TOLERANCE_MS,
    HOLE_PUNCH_REGISTRY_TIMEOUT,
    HOLE_PUNCH_RENDEZVOUS_TIMEOUT,
    HOLE_PUNCH_STAGGER,
    HOLE_PUNCH_TIMEOUT,
    MAX_BY_PEERS_ENTRIES,
    MAX_HOLE_PUNCH_PER_IDENTITY,
    MAX_PENDING_HOLE_PUNCHES,
    MAX_READY_HOLE_PUNCHES,
};
