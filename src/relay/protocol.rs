use std::net::SocketAddr;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::identity::Identity;

// ============================================================================
// Configuration & Constants
// ============================================================================

/// Maximum number of relay sessions a node will host.
pub const MAX_RELAY_SESSIONS: usize = 100;

/// How long a relay session can be idle before expiration.
pub const RELAY_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum packet size for relayed data.
pub const MAX_RELAY_PACKET_SIZE: usize = 1500;

/// Timeout for direct connection attempts before falling back to relay.
pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// STUN binding request timeout.
pub const STUN_TIMEOUT: Duration = Duration::from_secs(3);

/// ICE connectivity check interval.
pub const ICE_CHECK_INTERVAL: Duration = Duration::from_millis(50);

/// ICE keepalive interval for nominated pairs.
pub const ICE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// TURN allocation lifetime (must refresh before expiry).
pub const TURN_ALLOCATION_LIFETIME: Duration = Duration::from_secs(600);

// ============================================================================
// Error Types
// ============================================================================

/// Error indicating failure to obtain cryptographic random bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError {
    /// The underlying getrandom error code, if available.
    pub code: Option<u32>,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(
                f,
                "CSPRNG unavailable (error code {}). \
                 Cryptographic random number generator required for secure operation.",
                code
            ),
            None => write!(
                f,
                "CSPRNG unavailable. \
                 Cryptographic random number generator required for secure operation."
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<getrandom::Error> for CryptoError {
    fn from(err: getrandom::Error) -> Self {
        Self {
            code: Some(err.code().get()),
        }
    }
}

// ============================================================================
// Transport & NAT Types
// ============================================================================

/// Transport protocol for ICE candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    /// UDP transport (standard for QUIC).
    Udp,
    /// TCP transport (fallback).
    Tcp,
}

/// NAT type classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT - we have a public IP.
    None,
    /// Full cone NAT - any external host can send to the mapped address.
    FullCone,
    /// Restricted cone NAT - only hosts we've sent to can reply.
    RestrictedCone,
    /// Port restricted cone NAT - only (host, port) we've sent to can reply.
    PortRestrictedCone,
    /// Symmetric NAT - different mapping for each destination.
    Symmetric,
    /// Unknown - couldn't determine type.
    Unknown,
}

/// Result of STUN-based NAT type detection.
#[derive(Clone, Debug)]
pub struct NatReport {
    /// Detected NAT type.
    pub nat_type: NatType,
    /// Our public address as seen by STUN server 1.
    pub mapped_addr_1: Option<SocketAddr>,
    /// Our public address as seen by STUN server 2 (for symmetric detection).
    pub mapped_addr_2: Option<SocketAddr>,
    /// Whether we appear to have a public IP.
    pub has_public_ip: bool,
    /// Whether UDP is blocked.
    pub udp_blocked: bool,
    /// Whether we're behind a firewall.
    pub behind_firewall: bool,
    /// Detected RTT to STUN server (ms).
    pub stun_rtt_ms: Option<f32>,
}

impl Default for NatReport {
    fn default() -> Self {
        Self {
            nat_type: NatType::Unknown,
            mapped_addr_1: None,
            mapped_addr_2: None,
            has_public_ip: false,
            udp_blocked: false,
            behind_firewall: false,
            stun_rtt_ms: None,
        }
    }
}

// ============================================================================
// Relay Protocol Messages
// ============================================================================

/// Request to establish a relay session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayRequest {
    /// The peer we want to reach through the relay.
    pub target_peer: Identity,
    /// Our own peer ID for the relay to match connections.
    pub from_peer: Identity,
    /// Session ID to correlate the two halves of the relay.
    pub session_id: [u8; 16],
}

/// Response to a relay request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelayResponse {
    /// Relay accepted, waiting for peer to connect.
    Accepted {
        /// Session ID confirmed.
        session_id: [u8; 16],
    },
    /// Relay session established (both peers connected).
    Connected {
        /// Session ID.
        session_id: [u8; 16],
    },
    /// Relay rejected (at capacity or peer not found).
    Rejected {
        /// Reason for rejection.
        reason: String,
    },
}

/// A packet being relayed between peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayPacket {
    /// The sender's identity.
    pub from: Identity,
    /// Session ID for routing.
    pub session_id: [u8; 16],
    /// Encrypted payload (QUIC packet, opaque to relay).
    pub payload: Vec<u8>,
}

/// Notification of relay session state changes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelayNotification {
    /// Peer connected to the relay session.
    PeerConnected { session_id: [u8; 16] },
    /// Session closed (peer disconnected or timeout).
    SessionClosed { session_id: [u8; 16], reason: String },
}

// ============================================================================
// Relay Info for DHT Publishing
// ============================================================================

/// Information about a node's relay capabilities published to DHT.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayInfo {
    /// The relay node's peer ID.
    pub relay_peer: Identity,
    /// Addresses where the relay can be reached.
    pub relay_addrs: Vec<String>,
    /// Current load (0.0 - 1.0).
    pub load: f32,
    /// Whether this relay is currently accepting new sessions.
    pub accepting: bool,
    /// Observed RTT to this relay in milliseconds (from DHT tiering).
    /// None if we haven't measured RTT yet.
    #[serde(default)]
    pub rtt_ms: Option<f32>,
    /// Tiering level (0 = fastest tier).
    /// Used for latency-aware relay selection.
    #[serde(default)]
    pub tier: Option<u8>,
    /// Capabilities supported by this relay.
    #[serde(default)]
    pub capabilities: RelayCapabilities,
}

/// Capabilities supported by a relay server.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelayCapabilities {
    /// Supports STUN binding requests (WhatIsMyAddr).
    #[serde(default)]
    pub stun: bool,
    /// Supports TURN allocation (relay forwarding).
    #[serde(default)]
    pub turn: bool,
    /// Supports ICE-lite (connectivity checks).
    #[serde(default)]
    pub ice_lite: bool,
    /// Maximum bandwidth in Kbps (0 = unlimited).
    #[serde(default)]
    pub max_bandwidth_kbps: u32,
    /// Geographic region hint.
    #[serde(default)]
    pub region: Option<String>,
}

impl RelayInfo {
    /// Calculate a score for relay selection (lower is better).
    ///
    /// This combines:
    /// - RTT latency (weighted heavily - we want fast relays)
    /// - Load (prefer less loaded relays)
    /// - Tier level (prefer nodes in faster tiers)
    ///
    /// The formula prioritizes latency over load since relay overhead
    /// adds to every packet's round trip.
    pub fn selection_score(&self) -> f32 {
        // Base score from RTT (if known)
        let rtt_score = self.rtt_ms.unwrap_or(200.0); // Default to 200ms if unknown
        
        // Load penalty (0-100ms equivalent)
        let load_penalty = self.load * 100.0;
        
        // Tier penalty (20ms per tier level)
        let tier_penalty = self.tier.map(|t| t as f32 * 20.0).unwrap_or(40.0);
        
        rtt_score + load_penalty + tier_penalty
    }

    /// Check if this relay has known latency metrics.
    pub fn has_latency_info(&self) -> bool {
        self.rtt_ms.is_some() || self.tier.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_selection_score() {
        // Fast relay: low RTT, low load, tier 0
        let fast_relay = RelayInfo {
            relay_peer: Identity::from_bytes([1u8; 32]),
            relay_addrs: vec!["relay-1:4433".to_string()],
            load: 0.1,
            accepting: true,
            rtt_ms: Some(20.0),
            tier: Some(0),
            capabilities: Default::default(),
        };
        
        // Slow relay: high RTT, high load, tier 2
        let slow_relay = RelayInfo {
            relay_peer: Identity::from_bytes([2u8; 32]),
            relay_addrs: vec!["relay-2:4433".to_string()],
            load: 0.8,
            accepting: true,
            rtt_ms: Some(150.0),
            tier: Some(2),
            capabilities: Default::default(),
        };
        
        // Fast relay should have lower (better) score
        assert!(fast_relay.selection_score() < slow_relay.selection_score());
    }

    #[test]
    fn test_relay_selection_prefers_measured() {
        // Relay with measurements
        let measured = RelayInfo {
            relay_peer: Identity::from_bytes([1u8; 32]),
            relay_addrs: vec!["relay-1:4433".to_string()],
            load: 0.5,
            accepting: true,
            rtt_ms: Some(30.0),
            tier: Some(0),
            capabilities: Default::default(),
        };
        
        // Relay without measurements (uses defaults: 200ms RTT, tier penalty 40ms)
        let unmeasured = RelayInfo {
            relay_peer: Identity::from_bytes([2u8; 32]),
            relay_addrs: vec!["relay-2:4433".to_string()],
            load: 0.2,
            accepting: true,
            rtt_ms: None,
            tier: None,
            capabilities: Default::default(),
        };
        
        // Measured relay should be preferred (lower score)
        assert!(measured.selection_score() < unmeasured.selection_score());
        assert!(measured.has_latency_info());
        assert!(!unmeasured.has_latency_info());
    }
}
