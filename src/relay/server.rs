use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, trace, warn};
use anyhow::Result;

use crate::identity::Identity;
use crate::relay::protocol::{
    RelayRequest, RelayResponse, RelayPacket, RelayInfo, RelayCapabilities,
    CryptoError, MAX_RELAY_SESSIONS, RELAY_SESSION_TIMEOUT, MAX_RELAY_PACKET_SIZE,
};

// ============================================================================
// Relay Session State
// ============================================================================

/// A pending relay session waiting for the second peer.
#[derive(Debug)]
pub struct PendingSession {
    /// The first peer that connected.
    pub initiator: Identity,
    /// The target peer we're waiting for.
    pub target: Identity,
    /// When this session was created.
    pub created_at: Instant,
    /// Channel to send packets to the initiator.
    pub initiator_tx: tokio::sync::mpsc::Sender<RelayPacket>,
}

/// An active relay session between two peers.
#[derive(Debug)]
pub struct ActiveSession {
    /// First peer (initiator).
    pub peer_a: Identity,
    /// Second peer (responder).
    pub peer_b: Identity,
    /// Channel to send packets to peer A.
    pub peer_a_tx: tokio::sync::mpsc::Sender<RelayPacket>,
    /// Channel to send packets to peer B.
    pub peer_b_tx: tokio::sync::mpsc::Sender<RelayPacket>,
    /// When this session was established.
    pub established_at: Instant,
    /// Last activity timestamp.
    pub last_activity: Instant,
}

// ============================================================================
// Forwarder Task Registry
// ============================================================================

/// Maximum number of concurrent forwarder tasks.
const MAX_FORWARDER_TASKS: usize = 200;

/// Tracks and limits relay forwarder task handles.
pub struct ForwarderRegistry {
    /// Task handles by session ID.
    handles: RwLock<HashMap<[u8; 16], tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for ForwarderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwarderRegistry")
            .field("handles_count", &"<async>")
            .finish()
    }
}

impl Default for ForwarderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwarderRegistry {
    pub fn new() -> Self {
        Self {
            handles: RwLock::new(HashMap::new()),
        }
    }

    pub async fn can_accept(&self) -> bool {
        let handles = self.handles.read().await;
        handles.len() < MAX_FORWARDER_TASKS
    }

    pub async fn active_count(&self) -> usize {
        let handles = self.handles.read().await;
        handles.len()
    }

    pub async fn register(&self, session_id: [u8; 16], handle: tokio::task::JoinHandle<()>) -> bool {
        let mut handles = self.handles.write().await;
        
        if handles.len() >= MAX_FORWARDER_TASKS {
            handle.abort();
            return false;
        }
        
        if let Some(old_handle) = handles.remove(&session_id) {
            old_handle.abort();
        }
        
        handles.insert(session_id, handle);
        true
    }

    pub async fn abort(&self, session_id: &[u8; 16]) {
        let mut handles = self.handles.write().await;
        if let Some(handle) = handles.remove(session_id) {
            handle.abort();
            trace!(
                session = hex::encode(session_id),
                "aborted forwarder task for closed session"
            );
        }
    }

    pub async fn cleanup_completed(&self) {
        let mut handles = self.handles.write().await;
        let before = handles.len();
        
        handles.retain(|session_id, handle| {
            if handle.is_finished() {
                trace!(
                    session = hex::encode(session_id),
                    "cleaning up completed forwarder task"
                );
                false
            } else {
                true
            }
        });
        
        let removed = before - handles.len();
        if removed > 0 {
            debug!(
                removed = removed,
                remaining = handles.len(),
                "cleaned up completed forwarder tasks"
            );
        }
    }

    pub async fn abort_all(&self) {
        let mut handles = self.handles.write().await;
        let count = handles.len();
        
        for (session_id, handle) in handles.drain() {
            handle.abort();
            trace!(
                session = hex::encode(session_id),
                "aborted forwarder task during shutdown"
            );
        }
        
        if count > 0 {
            info!(count = count, "aborted all forwarder tasks");
        }
    }
}

// ============================================================================
// Relay Server State
// ============================================================================

#[derive(Debug, Default)]
struct RelayMetrics {
    total_sessions: u64,
    total_bytes_relayed: u64,
    active_count: usize,
}

/// Manages relay sessions for this node.
#[derive(Debug)]
pub struct RelayServer {
    /// Pending sessions (waiting for second peer).
    pending: RwLock<HashMap<[u8; 16], PendingSession>>,
    /// Active sessions (both peers connected).
    active: RwLock<HashMap<[u8; 16], ActiveSession>>,
    /// Session IDs that were actually issued by this server.
    issued_sessions: RwLock<HashSet<[u8; 16]>>,
    /// Server secret for computing session authentication tokens (HMAC).
    server_secret: [u8; 32],
    /// Maximum concurrent sessions.
    max_sessions: usize,
    /// Metrics for load calculation.
    metrics: Mutex<RelayMetrics>,
    /// Registry of forwarder task handles.
    forwarder_registry: ForwarderRegistry,
}

impl RelayServer {
    pub fn new() -> Result<Self, CryptoError> {
        Self::with_capacity(MAX_RELAY_SESSIONS)
    }

    pub fn with_capacity(max_sessions: usize) -> Result<Self, CryptoError> {
        let mut server_secret = [0u8; 32];
        getrandom::getrandom(&mut server_secret)?;
        
        Ok(Self {
            pending: RwLock::new(HashMap::new()),
            active: RwLock::new(HashMap::new()),
            issued_sessions: RwLock::new(HashSet::new()),
            server_secret,
            max_sessions,
            metrics: Mutex::new(RelayMetrics::default()),
            forwarder_registry: ForwarderRegistry::new(),
        })
    }

    pub async fn is_session_issued(&self, session_id: &[u8; 16]) -> bool {
        let issued = self.issued_sessions.read().await;
        issued.contains(session_id)
    }

    pub fn compute_session_token(
        &self,
        session_id: &[u8; 16],
        initiator: &Identity,
        target: &Identity,
    ) -> [u8; 32] {
        use blake3::Hasher;
        
        let mut hasher = Hasher::new_keyed(&self.server_secret);
        hasher.update(session_id);
        hasher.update(initiator.as_bytes());
        hasher.update(target.as_bytes());
        *hasher.finalize().as_bytes()
    }

    pub fn verify_session_token(
        &self,
        session_id: &[u8; 16],
        initiator: &Identity,
        target: &Identity,
        token: &[u8; 32],
    ) -> bool {
        let expected = self.compute_session_token(session_id, initiator, target);
        let mut diff: u8 = 0;
        for (a, b) in expected.iter().zip(token.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    pub fn forwarder_registry(&self) -> &ForwarderRegistry {
        &self.forwarder_registry
    }

    pub async fn load(&self) -> f32 {
        let active = self.active.read().await.len();
        let pending = self.pending.read().await.len();
        let total = active + pending;
        total as f32 / self.max_sessions as f32
    }

    pub async fn is_accepting(&self) -> bool {
        self.load().await < 0.9
    }

    pub async fn handle_request(
        &self,
        request: RelayRequest,
        sender_tx: tokio::sync::mpsc::Sender<RelayPacket>,
    ) -> RelayResponse {
        if !self.is_accepting().await {
            return RelayResponse::Rejected {
                reason: "relay at capacity".to_string(),
            };
        }

        let session_id = request.session_id;

        {
            let mut pending = self.pending.write().await;
            if let Some(pending_session) = pending.remove(&session_id) {
                if pending_session.target != request.from_peer {
                    pending.insert(session_id, pending_session);
                    return RelayResponse::Rejected {
                        reason: "relay request failed".to_string(),
                    };
                }

                let active_session = ActiveSession {
                    peer_a: pending_session.initiator,
                    peer_b: request.from_peer,
                    peer_a_tx: pending_session.initiator_tx,
                    peer_b_tx: sender_tx,
                    established_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                let mut active = self.active.write().await;
                active.insert(session_id, active_session);

                debug!(
                    session_id = hex::encode(session_id),
                    "relay session established"
                );

                let mut metrics = self.metrics.lock().await;
                metrics.total_sessions = metrics.total_sessions.saturating_add(1);
                metrics.active_count = active.len();

                return RelayResponse::Connected { session_id };
            }
        }

        let pending_session = PendingSession {
            initiator: request.from_peer,
            target: request.target_peer,
            created_at: Instant::now(),
            initiator_tx: sender_tx,
        };

        let mut pending = self.pending.write().await;
        
        let now = Instant::now();
        let mut expired_ids: Vec<[u8; 16]> = Vec::new();
        pending.retain(|id, s| {
            let expired = now.duration_since(s.created_at) >= RELAY_SESSION_TIMEOUT;
            if expired {
                expired_ids.push(*id);
            }
            !expired
        });
        
        if pending.len() >= self.max_sessions {
            debug!(
                session_id = hex::encode(session_id),
                pending_count = pending.len(),
                "rejecting relay request: pending session limit reached"
            );
            if !expired_ids.is_empty() {
                let mut issued = self.issued_sessions.write().await;
                for id in &expired_ids {
                    issued.remove(id);
                }
            }
            return RelayResponse::Rejected {
                reason: "relay request failed".to_string(),
            };
        }
        
        {
            let mut issued = self.issued_sessions.write().await;
            for id in &expired_ids {
                issued.remove(id);
            }
            issued.insert(session_id);
        }
        
        pending.insert(session_id, pending_session);

        debug!(
            session_id = hex::encode(session_id),
            "relay session pending, waiting for peer"
        );

        RelayResponse::Accepted { session_id }
    }

    pub async fn forward_packet(
        &self,
        from_peer: &Identity,
        packet: RelayPacket,
    ) -> Result<(), String> {
        if packet.payload.len() > MAX_RELAY_PACKET_SIZE {
            return Err("relay request failed".to_string());
        }

        if !self.is_session_issued(&packet.session_id).await {
            debug!(
                session_id = hex::encode(packet.session_id),
                from = ?hex::encode(&from_peer.as_bytes()[..8]),
                "rejecting forward: session ID was not issued by this server"
            );
            return Err("relay request failed".to_string());
        }

        let mut active = self.active.write().await;
        let session = active
            .get_mut(&packet.session_id)
            .ok_or_else(|| "relay request failed".to_string())?;

        session.last_activity = Instant::now();

        let target_tx = if &session.peer_a == from_peer {
            &session.peer_b_tx
        } else if &session.peer_b == from_peer {
            &session.peer_a_tx
        } else {
            return Err("relay request failed".to_string());
        };

        {
            let mut metrics = self.metrics.lock().await;
            metrics.total_bytes_relayed = metrics.total_bytes_relayed.saturating_add(packet.payload.len() as u64);
        }

        target_tx
            .send(packet)
            .await
            .map_err(|_| "peer disconnected".to_string())
    }

    pub async fn close_session(&self, session_id: &[u8; 16], from_peer: &Identity, reason: &str) {
        let mut active = self.active.write().await;
        if let Some(session) = active.get(session_id) {
            if &session.peer_a != from_peer && &session.peer_b != from_peer {
                warn!(
                    session_id = hex::encode(session_id),
                    from = ?hex::encode(&from_peer.as_bytes()[..8]),
                    "rejecting RELAY_CLOSE: requester is not a session participant"
                );
                return;
            }
            
            active.remove(session_id);
            
            {
                let mut issued = self.issued_sessions.write().await;
                issued.remove(session_id);
            }
            
            self.forwarder_registry.abort(session_id).await;
            
            debug!(
                session_id = hex::encode(session_id),
                reason = reason,
                "relay session closed"
            );
            
            let mut metrics = self.metrics.lock().await;
            metrics.active_count = active.len();
            return;
        }
        drop(active);

        let mut pending = self.pending.write().await;
        if let Some(session) = pending.get(session_id) {
            if &session.initiator != from_peer && &session.target != from_peer {
                warn!(
                    session_id = hex::encode(session_id),
                    from = ?hex::encode(&from_peer.as_bytes()[..8]),
                    "rejecting RELAY_CLOSE: requester is not a session participant"
                );
                return;
            }
            
            pending.remove(session_id);
            
            {
                let mut issued = self.issued_sessions.write().await;
                issued.remove(session_id);
            }
            
            self.forwarder_registry.abort(session_id).await;
            
            debug!(
                session_id = hex::encode(session_id),
                reason = reason,
                "pending relay session closed"
            );
        }
    }

    pub async fn cleanup_expired(&self) {
        let now = Instant::now();

        let expired_pending_ids: Vec<[u8; 16]> = {
            let mut pending = self.pending.write().await;
            let mut expired_ids = Vec::new();
            
            pending.retain(|id, s| {
                let expired = now.duration_since(s.created_at) >= RELAY_SESSION_TIMEOUT;
                if expired {
                    trace!(session_id = hex::encode(id), "pending session expired");
                    expired_ids.push(*id);
                }
                !expired
            });
            
            expired_ids
        };

        let expired_session_ids: Vec<[u8; 16]> = {
            let mut active = self.active.write().await;
            let mut expired_ids = Vec::new();
            
            active.retain(|id, s| {
                let expired = now.duration_since(s.last_activity) >= RELAY_SESSION_TIMEOUT;
                if expired {
                    debug!(session_id = hex::encode(id), "active session expired");
                    expired_ids.push(*id);
                }
                !expired
            });

            let mut metrics = self.metrics.lock().await;
            metrics.active_count = active.len();
            
            expired_ids
        };
        
        {
            let mut issued = self.issued_sessions.write().await;
            for session_id in &expired_pending_ids {
                issued.remove(session_id);
            }
            for session_id in &expired_session_ids {
                issued.remove(session_id);
            }
        }
        
        for session_id in &expired_session_ids {
            self.forwarder_registry.abort(session_id).await;
        }
        
        self.forwarder_registry.cleanup_completed().await;
    }

    pub async fn get_relay_info(&self, our_peer: Identity, our_addrs: Vec<String>) -> RelayInfo {
        RelayInfo {
            relay_peer: our_peer,
            relay_addrs: our_addrs,
            load: self.load().await,
            accepting: self.is_accepting().await,
            rtt_ms: None,
            tier: None,
            capabilities: RelayCapabilities {
                stun: true,
                turn: true,
                ice_lite: true,
                max_bandwidth_kbps: 0,
                region: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_relay_server_capacity() {
        let server = RelayServer::with_capacity(10).unwrap();
        assert!(server.is_accepting().await);
        assert!(server.load().await < 0.1);
    }
}
