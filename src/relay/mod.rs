//! Relay and NAT traversal functionality.
//!
//! This module implements:
//! - ICE (Interactive Connectivity Establishment) for NAT traversal
//! - STUN/TURN-like relay protocol
//! - Relay server and client implementations
//! - Connection registry for relay sessions

pub mod protocol;
pub mod ice;
pub mod registry;
pub mod server;
pub mod client;

// Re-export common types
pub use protocol::{
    RelayInfo, RelayCapabilities, RelayRequest, RelayResponse, RelayPacket,
    NatType, NatReport, TransportProtocol, CryptoError,
    MAX_RELAY_SESSIONS, RELAY_SESSION_TIMEOUT, MAX_RELAY_PACKET_SIZE, DIRECT_CONNECT_TIMEOUT,
    STUN_TIMEOUT, ICE_CHECK_INTERVAL, ICE_KEEPALIVE_INTERVAL, TURN_ALLOCATION_LIFETIME,
};
pub use ice::{
    IceAgent, IceCandidate, IceRole, IceState, CandidateType, CandidatePair, CheckState, TurnAllocation,
    gather_host_candidates, detect_nat_type, ice_connection_strategy,
};
pub use registry::RelayConnectionRegistry;
pub use server::{RelayServer, ForwarderRegistry};
pub use client::{RelayClient, IncomingRelayData, ConnectionStrategy, choose_connection_strategy};
