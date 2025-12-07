//! QUIC-based NAT hole punching with server-side rendezvous coordination.
//!
//! This module provides:
//!
//! - [`HolePuncher`]: Client-side hole punch orchestration
//! - [`HolePunchRegistry`]: Server-side rendezvous for coordinating simultaneous open
//!
//! # Protocol Overview
//!
//! 1. **Discovery**: Both peers query STUN-like servers to learn public addresses
//! 2. **Registration**: Each peer registers with a rendezvous server (punch_id, target_peer, public_addr)
//! 3. **Coordination**: When both peers register, server returns start_time for synchronized punch
//! 4. **Simultaneous Open**: Both peers initiate QUIC connections at start_time
//! 5. **Race**: First successful connection wins; others are dropped
//!
//! # Timing Parameters
//!
//! - **Punch timeout**: 5 seconds ([`HOLE_PUNCH_TIMEOUT`])
//! - **Rendezvous timeout**: 10 seconds waiting for peer ([`HOLE_PUNCH_RENDEZVOUS_TIMEOUT`])
//! - **Stagger**: 50ms between connection attempts for NAT slot diversity
//! - **Clock skew tolerance**: 2,000ms for real-world NTP drift
//! - **Registry timeout**: 30 seconds before pending registrations expire
//!
//! # Rate Limiting
//!
//! Server-side bounds prevent abuse:
//! - **Per-identity**: Max 5 pending registrations per peer
//! - **Global pending**: Max 5,000 pending registrations
//! - **Ready results**: Max 1,000 cached results

use std::net::SocketAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use futures::future::select_all;
use getrandom::getrandom;
use quinn::{ClientConfig, Connection, Endpoint};
use tokio::time::sleep;
use tracing::{debug, info};

use crate::dht::Contact;
use crate::identity::Identity;
use crate::messages::{DhtRequest, DhtResponse};

use super::tls::identity_to_sni;
use super::transport::PeerNetwork;

pub const HOLE_PUNCH_TIMEOUT: Duration = Duration::from_secs(5);
pub const HOLE_PUNCH_RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(10);
pub const HOLE_PUNCH_STAGGER: Duration = Duration::from_millis(50);
/// Clock skew tolerance for hole punch timing.
/// 2000ms handles typical NTP drift and asymmetric network delays.
/// This is more robust than 500ms for real-world deployments where peers
/// may have significant clock differences.
pub const HOLE_PUNCH_CLOCK_SKEW_TOLERANCE_MS: u64 = 2000;
const HOLE_PUNCH_MIN_WAIT_MS: u64 = 100;
const HOLE_PUNCH_MAX_WAIT_MS: u64 = 10_000;

/// Timeout for hole punch rendezvous (waiting for peer to register) on the server side.
pub const HOLE_PUNCH_REGISTRY_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of ready hole punch results to keep.
pub const MAX_READY_HOLE_PUNCHES: usize = 1000;

/// Maximum pending hole punch registrations (waiting for peer).
pub const MAX_PENDING_HOLE_PUNCHES: usize = 5000;

/// Maximum entries in the by_peers lookup map.
pub const MAX_BY_PEERS_ENTRIES: usize = MAX_PENDING_HOLE_PUNCHES;

/// Maximum pending hole punch registrations per identity.
pub const MAX_HOLE_PUNCH_PER_IDENTITY: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolePunchState {
    DiscoveringAddress,
    WaitingForPeer,
    Punching,
    Success,
    Failed(String),
}

#[derive(Debug)]
pub struct HolePunchResult {
    pub state: HolePunchState,
    pub connection: Option<Connection>,
    pub our_public_addr: Option<SocketAddr>,
    pub peer_public_addr: Option<SocketAddr>,
    pub duration: Duration,
}

/// Client-side hole punch coordinator.
///
/// Orchestrates the hole punch workflow:
///
/// 1. [`discover_public_addr`][Self::discover_public_addr]: Query STUN servers for NAT-mapped address
/// 2. [`punch_with_rendezvous`][Self::punch_with_rendezvous]: Full workflow with server coordination
/// 3. [`punch`][Self::punch]: Direct simultaneous open attempt
///
/// # Connection Racing
///
/// Makes 3 staggered connection attempts (50ms apart) and races them.
/// First successful QUIC handshake wins; losers are dropped.
/// Identity verification happens via SNI during TLS handshake.
#[derive(Debug)]
pub struct HolePuncher {
    endpoint: Endpoint,
    client_config: ClientConfig,
    our_peer_id: Identity,
    state: HolePunchState,
    our_public_addr: Option<SocketAddr>,
}

impl HolePuncher {
    pub fn new(endpoint: Endpoint, client_config: ClientConfig, our_peer_id: Identity) -> Self {
        Self {
            endpoint,
            client_config,
            our_peer_id,
            state: HolePunchState::DiscoveringAddress,
            our_public_addr: None,
        }
    }

    pub async fn discover_public_addr(
        &mut self,
        stun_contacts: &[Contact],
        network: &PeerNetwork,
    ) -> Result<SocketAddr> {
        self.state = HolePunchState::DiscoveringAddress;

        let (consistent, all_addrs) = network.discover_public_addr(stun_contacts, 3).await;

        if let Some(addr) = consistent {
            self.our_public_addr = Some(addr);
            debug!(addr = %addr, "discovered public address (consistent)");
            Ok(addr)
        } else if let Some(addr) = all_addrs.first() {
            self.our_public_addr = Some(*addr);
            debug!(addr = %addr, all = ?all_addrs, "discovered public address (inconsistent - possible symmetric NAT)");
            Ok(*addr)
        } else {
            anyhow::bail!("failed to discover public address - no STUN responses")
        }
    }

    pub async fn punch(&mut self, peer_public_addr: SocketAddr, peer_id: &Identity) -> Result<Connection> {
        self.state = HolePunchState::Punching;
        let start = Instant::now();

        info!(
            peer = ?peer_id,
            peer_addr = %peer_public_addr,
            our_addr = ?self.our_public_addr,
            "attempting QUIC hole punch"
        );

        let mut attempts = Vec::new();
        for i in 0..3 {
            let sni = identity_to_sni(peer_id);
            let connecting = self
                .endpoint
                .connect_with(self.client_config.clone(), peer_public_addr, &sni);

            match connecting {
                Ok(connecting) => attempts.push(connecting),
                Err(e) => {
                    debug!(attempt = i, error = %e, "hole punch attempt failed to initiate");
                }
            }

            if i < 2 {
                sleep(HOLE_PUNCH_STAGGER).await;
            }
        }

        if attempts.is_empty() {
            self.state = HolePunchState::Failed("failed to initiate any connection attempts".into());
            anyhow::bail!("hole punch failed: no connection attempts initiated");
        }

        let timeout = sleep(HOLE_PUNCH_TIMEOUT);
        tokio::pin!(timeout);

        let result = tokio::select! {
            _ = &mut timeout => Err(anyhow::anyhow!("hole punch timed out")),
            result = Self::race_connections(attempts) => result,
        };

        match result {
            Ok(conn) => {
                let duration = start.elapsed();
                self.state = HolePunchState::Success;
                info!(
                    peer = ?peer_id,
                    duration_ms = duration.as_millis(),
                    "hole punch succeeded (identity verified via SNI)"
                );
                Ok(conn)
            }
            Err(e) => {
                self.state = HolePunchState::Failed(e.to_string());
                debug!(peer = ?peer_id, error = %e, "hole punch failed");
                Err(e)
            }
        }
    }

    async fn race_connections(attempts: Vec<quinn::Connecting>) -> Result<Connection> {
        let futures: Vec<_> = attempts.into_iter().map(Box::pin).collect();

        if futures.is_empty() {
            anyhow::bail!("no connection attempts");
        }

        let mut remaining = futures;

        while !remaining.is_empty() {
            let (result, _index, rest) = select_all(remaining).await;
            match result {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    debug!(error = %e, "connection attempt failed");
                    remaining = rest;
                }
            }
        }

        anyhow::bail!("all hole punch attempts failed")
    }

    pub async fn punch_with_rendezvous(
        &mut self,
        target_peer: &Identity,
        rendezvous_contact: &Contact,
        network: &PeerNetwork,
    ) -> Result<HolePunchResult> {
        let start = Instant::now();

        if self.our_public_addr.is_none() {
            self
                .discover_public_addr(std::slice::from_ref(rendezvous_contact), network)
                .await?;
        }
        let our_addr = self
            .our_public_addr
            .ok_or_else(|| anyhow::anyhow!("failed to discover public address"))?;

        let mut punch_id = [0u8; 16];
        if getrandom(&mut punch_id).is_err() {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            punch_id[..8].copy_from_slice(&(ts as u64).to_le_bytes());
            punch_id[8..].copy_from_slice(&(ts.wrapping_mul(31337) as u64).to_le_bytes());
        }

        self.state = HolePunchState::WaitingForPeer;
        debug!(
            target = ?target_peer,
            rendezvous = %rendezvous_contact.addr,
            "registering for hole punch"
        );

        let register_request = DhtRequest::HolePunchRegister {
            from_peer: self.our_peer_id,
            target_peer: *target_peer,
            our_public_addr: our_addr.to_string(),
            punch_id,
        };

        let response = network.rpc(rendezvous_contact, register_request).await?;

        let peer_addr: SocketAddr = match response {
            DhtResponse::HolePunchReady { peer_addr, start_time_ms, .. } => {
                let now_ms = crate::now_ms();

                let raw_wait_ms = if start_time_ms > now_ms { start_time_ms - now_ms } else { 0 };

                let wait_ms = raw_wait_ms
                    .max(HOLE_PUNCH_MIN_WAIT_MS)
                    .min(HOLE_PUNCH_MAX_WAIT_MS);

                if wait_ms != raw_wait_ms {
                    debug!(
                        raw_wait_ms = raw_wait_ms,
                        adjusted_wait_ms = wait_ms,
                        "adjusted hole punch wait time for clock skew tolerance"
                    );
                }

                let wait = Duration::from_millis(wait_ms);
                debug!(wait_ms = wait.as_millis(), "waiting for synchronized punch start");
                sleep(wait).await;

                peer_addr.parse().context("invalid peer address from rendezvous")?
            }
            DhtResponse::HolePunchWaiting { .. } => {
                debug!("waiting for peer to register...");

                let deadline = Instant::now() + HOLE_PUNCH_RENDEZVOUS_TIMEOUT;
                loop {
                    if Instant::now() >= deadline {
                        return Ok(HolePunchResult {
                            state: HolePunchState::Failed("peer did not register in time".into()),
                            connection: None,
                            our_public_addr: Some(our_addr),
                            peer_public_addr: None,
                            duration: start.elapsed(),
                        });
                    }

                    sleep(Duration::from_millis(500)).await;

                    let poll = DhtRequest::HolePunchStart { punch_id };
                    if let Ok(DhtResponse::HolePunchReady { peer_addr, .. }) =
                        network.rpc(rendezvous_contact, poll).await
                    {
                        break peer_addr.parse().context("invalid peer address from rendezvous")?;
                    }
                }
            }
            DhtResponse::HolePunchFailed { reason } => {
                return Ok(HolePunchResult {
                    state: HolePunchState::Failed(reason),
                    connection: None,
                    our_public_addr: Some(our_addr),
                    peer_public_addr: None,
                    duration: start.elapsed(),
                });
            }
            other => {
                return Ok(HolePunchResult {
                    state: HolePunchState::Failed(format!("unexpected response: {:?}", other)),
                    connection: None,
                    our_public_addr: Some(our_addr),
                    peer_public_addr: None,
                    duration: start.elapsed(),
                });
            }
        };

        match self.punch(peer_addr, target_peer).await {
            Ok(conn) => Ok(HolePunchResult {
                state: HolePunchState::Success,
                connection: Some(conn),
                our_public_addr: Some(our_addr),
                peer_public_addr: Some(peer_addr),
                duration: start.elapsed(),
            }),
            Err(e) => Ok(HolePunchResult {
                state: HolePunchState::Failed(e.to_string()),
                connection: None,
                our_public_addr: Some(our_addr),
                peer_public_addr: Some(peer_addr),
                duration: start.elapsed(),
            }),
        }
    }

    pub fn state(&self) -> &HolePunchState {
        &self.state
    }

    pub fn public_addr(&self) -> Option<SocketAddr> {
        self.our_public_addr
    }
}

// ============================================================================
// Server-Side Rendezvous Registry
// ============================================================================

/// A pending hole punch waiting for the second peer.
#[derive(Debug)]
struct PendingHolePunch {
    /// First peer's ID.
    initiator: Identity,
    /// Target peer's ID.
    target: Identity,
    /// Initiator's public address.
    initiator_addr: String,
    /// When this was registered.
    registered_at: Instant,
}

/// Result of a successful hole punch rendezvous.
#[derive(Debug, Clone)]
struct RendezvousResult {
    /// Address of the peer to connect to.
    peer_addr: String,
    /// When to start the simultaneous open.
    start_time_ms: u64,
}

/// Internal state protected by a single mutex to prevent race conditions.
#[derive(Debug, Default)]
struct RegistryState {
    /// Pending punches: punch_id -> pending info.
    pending: HashMap<[u8; 16], PendingHolePunch>,
    /// Completed punches ready for pickup: punch_id -> result.
    ready: HashMap<[u8; 16], RendezvousResult>,
    /// Lookup by peer pair: (peer_a, peer_b) sorted -> punch_id.
    by_peers: HashMap<(Identity, Identity), [u8; 16]>,
    /// Count of pending registrations per identity (for rate limiting).
    per_identity_count: HashMap<Identity, usize>,
}

/// Tracks pending hole punch rendezvous requests.
///
/// Coordinates simultaneous UDP hole punch attempts between two peers:
///
/// 1. First peer calls [`register`][Self::register] → stored in `pending`
/// 2. Second peer calls [`register`][Self::register] → matched, both get start_time
/// 3. Both peers initiate QUIC connections at synchronized time
///
/// # State Management
///
/// - `pending`: Waiting for second peer (bounded by [`MAX_PENDING_HOLE_PUNCHES`])
/// - `ready`: Both peers registered, result awaiting pickup (bounded by [`MAX_READY_HOLE_PUNCHES`])
/// - `by_peers`: Sorted peer-pair → punch_id lookup for matching
/// - `per_identity_count`: Per-peer rate limiting (max [`MAX_HOLE_PUNCH_PER_IDENTITY`])
///
/// # Thread Safety
///
/// Uses a single `tokio::sync::Mutex` for atomic state transitions, preventing:
/// - TOCTOU race conditions on rate limit checks
/// - Deadlocks from nested lock acquisition
/// - State corruption from concurrent modifications
#[derive(Debug, Default)]
pub struct HolePunchRegistry {
    /// All state protected by a single mutex for atomic operations.
    state: tokio::sync::Mutex<RegistryState>,
}

impl HolePunchRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hole punch request.
    ///
    /// If the peer is already waiting, returns their info for simultaneous open.
    /// Returns `None` if the peer has exceeded their registration limit.
    ///
    /// This method is atomic - all state checks and modifications happen
    /// under a single lock to prevent race conditions.
    pub async fn register(
        &self,
        punch_id: [u8; 16],
        from_peer: Identity,
        target_peer: Identity,
        from_addr: String,
    ) -> Result<Option<(String, u64)>, &'static str> {
        // Normalize peer pair for lookup
        let peer_pair = if from_peer.as_bytes() < target_peer.as_bytes() {
            (from_peer, target_peer)
        } else {
            (target_peer, from_peer)
        };

        // Single lock protects all state atomically - no TOCTOU race conditions
        let mut state = self.state.lock().await;

        // Check per-identity rate limit (atomic with the rest of the operation)
        if let Some(&count) = state.per_identity_count.get(&from_peer) {
            if count >= MAX_HOLE_PUNCH_PER_IDENTITY {
                return Err("too many pending hole punch registrations");
            }
        }

        // Check if the other peer is already waiting
        if let Some(&existing_id) = state.by_peers.get(&peer_pair) {
            // Check if it's us (retry) or them (match)
            let is_self = if let Some(existing) = state.pending.get(&existing_id) {
                existing.initiator == from_peer
            } else {
                false // Should not happen
            };

            if !is_self {
                if let Some(existing) = state.pending.remove(&existing_id) {
                    state.by_peers.remove(&peer_pair);
                    
                    // Decrement count for the initiator
                    if let Some(count) = state.per_identity_count.get_mut(&existing.initiator) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            state.per_identity_count.remove(&existing.initiator);
                        }
                    }
                    
                    // Both peers ready! Calculate start time
                    // Use 500ms offset to handle clock skew between peers
                    let start_time_ms = crate::now_ms()
                        + HOLE_PUNCH_CLOCK_SKEW_TOLERANCE_MS;
                    
                    // Enforce limit on ready results to prevent memory exhaustion
                    if state.ready.len() >= MAX_READY_HOLE_PUNCHES {
                        // Remove oldest entries (those with earliest start_time_ms)
                        let oldest_key = state.ready
                            .iter()
                            .min_by_key(|(_, r)| r.start_time_ms)
                            .map(|(k, _)| *k);
                        if let Some(key) = oldest_key {
                            state.ready.remove(&key);
                        }
                    }
                    
                    // Store result for the first peer to pick up via check_ready()
                    state.ready.insert(existing_id, RendezvousResult {
                        peer_addr: from_addr.clone(),
                        start_time_ms,
                    });
                    
                    // Return the first peer's address to the second peer
                    return Ok(Some((existing.initiator_addr, start_time_ms)));
                }
            } else {
                // It's us! Remove old registration to allow update (retry)
                state.pending.remove(&existing_id);
                state.by_peers.remove(&peer_pair);
                // Decrement count for the old registration
                if let Some(count) = state.per_identity_count.get_mut(&from_peer) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        state.per_identity_count.remove(&from_peer);
                    }
                }
            }
        }

        // First peer - register and wait
        // Check pending limit to prevent memory exhaustion
        if state.pending.len() >= MAX_PENDING_HOLE_PUNCHES {
            // Remove oldest pending registration
            let oldest = state.pending
                .iter()
                .min_by_key(|(_, p)| p.registered_at)
                .map(|(id, _)| *id);
            if let Some(old_id) = oldest {
                if let Some(old_punch) = state.pending.remove(&old_id) {
                    // Clean up associated state
                    let old_pair = if old_punch.initiator.as_bytes() < old_punch.target.as_bytes() {
                        (old_punch.initiator, old_punch.target)
                    } else {
                        (old_punch.target, old_punch.initiator)
                    };
                    state.by_peers.remove(&old_pair);
                    if let Some(count) = state.per_identity_count.get_mut(&old_punch.initiator) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            state.per_identity_count.remove(&old_punch.initiator);
                        }
                    }
                }
            }
        }
        
        state.pending.insert(punch_id, PendingHolePunch {
            initiator: from_peer,
            target: target_peer,
            initiator_addr: from_addr,
            registered_at: Instant::now(),
        });
        
        // Defensive bounds check for by_peers map.
        // This should never trigger due to the pending limit above, but we check
        // explicitly to prevent unbounded growth if the invariant is broken.
        if state.by_peers.len() >= MAX_BY_PEERS_ENTRIES {
            // Remove an arbitrary entry to make room (should not happen in practice)
            if let Some(key) = state.by_peers.keys().next().copied() {
                state.by_peers.remove(&key);
            }
        }
        state.by_peers.insert(peer_pair, punch_id);
        
        // Increment count for this identity (saturating to prevent overflow)
        *state.per_identity_count.entry(from_peer).or_insert(0) = 
            state.per_identity_count.get(&from_peer).copied().unwrap_or(0).saturating_add(1);

        Ok(None)
    }

    /// Check if a punch is ready (both peers registered).
    /// 
    /// The first peer calls this to poll for the result after registering.
    /// Returns `Some((peer_addr, start_time_ms))` when the second peer has registered.
    pub async fn check_ready(&self, punch_id: &[u8; 16]) -> Option<(String, u64)> {
        // Single lock for atomic access
        let mut state = self.state.lock().await;
        
        // Check if result is ready (second peer has registered)
        if let Some(result) = state.ready.remove(punch_id) {
            return Some((result.peer_addr, result.start_time_ms));
        }
        
        // Still waiting for the other peer
        None
    }

    /// Clean up expired pending punches and stale ready results.
    ///
    /// This method is atomic - all cleanup happens under a single lock.
    pub async fn cleanup_expired(&self) {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        
        // Get current time in milliseconds for ready result expiration
        let now_ms = crate::now_ms();

        // Collect expired punch IDs first to avoid borrow issues
        let expired_ids: Vec<[u8; 16]> = state.pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.registered_at) >= HOLE_PUNCH_REGISTRY_TIMEOUT)
            .map(|(id, _)| *id)
            .collect();

        for id in expired_ids {
            if let Some(p) = state.pending.remove(&id) {
                // Also remove from by_peers lookup
                let peer_pair = if p.initiator.as_bytes() < p.target.as_bytes() {
                    (p.initiator, p.target)
                } else {
                    (p.target, p.initiator)
                };
                state.by_peers.remove(&peer_pair);
                
                // Decrement count for the initiator
                if let Some(count) = state.per_identity_count.get_mut(&p.initiator) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        state.per_identity_count.remove(&p.initiator);
                    }
                }
                
                debug!(punch_id = hex::encode(id), "hole punch rendezvous expired");
            }
        }
        
        // Clean up stale ready results (not picked up within 30 seconds)
        state.ready.retain(|_id, result| {
            now_ms < result.start_time_ms + 30_000
        });
    }
}
