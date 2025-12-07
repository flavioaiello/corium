use std::collections::{HashMap, HashSet};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, warn};
use anyhow::Result;

use crate::identity::Identity;
use crate::relay::protocol::{RelayInfo, CryptoError};

// ============================================================================
// Relay Client State
// ============================================================================

/// Maximum pending relay data packets per session.
const MAX_PENDING_RELAY_DATA: usize = 64;

/// Incoming relay data packet ready for processing.
#[derive(Debug, Clone)]
pub struct IncomingRelayData {
    /// The session this data belongs to.
    pub session_id: [u8; 16],
    /// The peer who sent this data (the other end of the relay session).
    pub from_peer: Identity,
    /// The E2E encrypted payload (QUIC packet data).
    pub payload: Vec<u8>,
    /// When this data was received.
    pub received_at: std::time::Instant,
}

/// Client-side state for using relays.
#[derive(Debug)]
pub struct RelayClient {
    /// Known relays and their info (including RTT metrics).
    known_relays: RwLock<Vec<RelayInfo>>,
    /// Active sessions through relays (session_id -> relay_peer).
    active_sessions: RwLock<HashMap<[u8; 16], Identity>>,
    /// Channel sender for incoming relay data.
    data_tx: tokio::sync::mpsc::Sender<IncomingRelayData>,
    /// Channel receiver for incoming relay data (taken by consumer).
    data_rx: Mutex<Option<tokio::sync::mpsc::Receiver<IncomingRelayData>>>,
}

impl Default for RelayClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayClient {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(MAX_PENDING_RELAY_DATA);
        Self {
            known_relays: RwLock::new(Vec::new()),
            active_sessions: RwLock::new(HashMap::new()),
            data_tx: tx,
            data_rx: Mutex::new(Some(rx)),
        }
    }

    pub async fn take_data_receiver(&self) -> Option<tokio::sync::mpsc::Receiver<IncomingRelayData>> {
        self.data_rx.lock().await.take()
    }

    pub async fn queue_incoming_data(
        &self,
        session_id: [u8; 16],
        from_peer: Identity,
        payload: Vec<u8>,
    ) -> Result<(), &'static str> {
        let data = IncomingRelayData {
            session_id,
            from_peer,
            payload,
            received_at: std::time::Instant::now(),
        };

        self.data_tx
            .try_send(data)
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    "relay data queue full"
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    "relay data receiver closed"
                }
            })
    }

    pub async fn update_relays(&self, relays: Vec<RelayInfo>) {
        let mut known = self.known_relays.write().await;
        *known = relays;
        known.sort_by(|a, b| {
            a.selection_score()
                .partial_cmp(&b.selection_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    pub async fn update_relay_rtt(&self, relay_peer: &Identity, rtt_ms: f32, tier: u8) {
        let mut known = self.known_relays.write().await;
        for relay in known.iter_mut() {
            if &relay.relay_peer == relay_peer {
                relay.rtt_ms = Some(rtt_ms);
                relay.tier = Some(tier);
            }
        }
        known.sort_by(|a, b| {
            a.selection_score()
                .partial_cmp(&b.selection_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    pub async fn get_relays(&self, count: usize) -> Vec<RelayInfo> {
        let known = self.known_relays.read().await;
        known
            .iter()
            .filter(|r| r.accepting)
            .take(count)
            .cloned()
            .collect()
    }

    pub async fn get_relay_info(&self, identity: &Identity) -> Option<RelayInfo> {
        let known = self.known_relays.read().await;
        known.iter().find(|r| &r.relay_peer == identity).cloned()
    }

    pub async fn is_known_relay(&self, identity: &Identity) -> bool {
        let known = self.known_relays.read().await;
        known.iter().any(|r| &r.relay_peer == identity)
    }

    pub async fn get_measured_relays(&self, count: usize) -> Vec<RelayInfo> {
        let known = self.known_relays.read().await;
        known
            .iter()
            .filter(|r| r.accepting && r.has_latency_info())
            .take(count)
            .cloned()
            .collect()
    }

    pub fn generate_session_id() -> Result<[u8; 16], CryptoError> {
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id)?;
        Ok(id)
    }
    
    pub fn generate_unique_session_id(
        existing: &HashSet<[u8; 16]>,
    ) -> Result<Option<[u8; 16]>, CryptoError> {
        const MAX_RETRIES: usize = 10;
        
        for attempt in 0..MAX_RETRIES {
            let id = Self::generate_session_id()?;
            if !existing.contains(&id) {
                if attempt > 0 {
                    debug!(
                        attempts = attempt + 1,
                        "session ID collision avoided after retries"
                    );
                }
                return Ok(Some(id));
            }
            warn!(
                attempt = attempt + 1,
                "session ID collision detected, retrying"
            );
        }
        
        error!(
            "failed to generate unique session ID after {} attempts - possible RNG failure",
            MAX_RETRIES
        );
        Ok(None)
    }

    pub async fn register_session(&self, session_id: [u8; 16], relay: Identity) {
        let mut sessions = self.active_sessions.write().await;
        sessions.insert(session_id, relay);
    }

    pub async fn remove_session(&self, session_id: &[u8; 16]) -> Option<Identity> {
        let mut sessions = self.active_sessions.write().await;
        sessions.remove(session_id)
    }

    pub async fn verify_session(&self, session_id: &[u8; 16], relay_identity: &Identity) -> bool {
        let sessions = self.active_sessions.read().await;
        sessions.get(session_id).map(|r| r == relay_identity).unwrap_or(false)
    }

    pub async fn has_session(&self, session_id: &[u8; 16]) -> bool {
        let sessions = self.active_sessions.read().await;
        sessions.contains_key(session_id)
    }

    pub async fn get_session_relay(&self, session_id: &[u8; 16]) -> Option<Identity> {
        let sessions = self.active_sessions.read().await;
        sessions.get(session_id).cloned()
    }
}

// ============================================================================
// Connection Strategy
// ============================================================================

/// Strategy for connecting to a peer.
#[derive(Clone, Debug)]
pub enum ConnectionStrategy {
    /// Direct connection to known addresses.
    Direct {
        /// Addresses to try.
        addrs: Vec<String>,
    },
    /// Connection via a relay.
    Relayed {
        /// Relay to use.
        relay: RelayInfo,
        /// Session ID for this relay connection.
        session_id: [u8; 16],
    },
}

/// Determines the best connection strategy for reaching a peer.
pub fn choose_connection_strategy(
    direct_addrs: &[String],
    known_relays: &[RelayInfo],
    peer_relays: &[RelayInfo],
    direct_failed: bool,
) -> Result<ConnectionStrategy, CryptoError> {
    if !direct_addrs.is_empty() && !direct_failed {
        return Ok(ConnectionStrategy::Direct {
            addrs: direct_addrs.to_vec(),
        });
    }

    let best_mutual = find_best_mutual_relay(known_relays, peer_relays);
    if let Some(relay) = best_mutual {
        return Ok(ConnectionStrategy::Relayed {
            relay,
            session_id: RelayClient::generate_session_id()?,
        });
    }
    
    let mut peer_sorted: Vec<_> = peer_relays.iter().filter(|r| r.accepting).cloned().collect();
    peer_sorted.sort_by(|a, b| {
        a.selection_score()
            .partial_cmp(&b.selection_score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    
    if let Some(relay) = peer_sorted.into_iter().next() {
        return Ok(ConnectionStrategy::Relayed {
            relay,
            session_id: RelayClient::generate_session_id()?,
        });
    }

    if let Some(relay) = known_relays.iter().find(|r| r.accepting).cloned() {
        return Ok(ConnectionStrategy::Relayed {
            relay,
            session_id: RelayClient::generate_session_id()?,
        });
    }

    Ok(ConnectionStrategy::Direct {
        addrs: direct_addrs.to_vec(),
    })
}

fn find_best_mutual_relay(our_relays: &[RelayInfo], peer_relays: &[RelayInfo]) -> Option<RelayInfo> {
    let mut mutual: Vec<RelayInfo> = Vec::new();
    
    for our in our_relays {
        for peer in peer_relays {
            if our.relay_peer == peer.relay_peer && our.accepting && peer.accepting {
                mutual.push(our.clone());
                break;
            }
        }
    }
    
    mutual.sort_by(|a, b| {
        a.selection_score()
            .partial_cmp(&b.selection_score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    
    mutual.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_relay(id: u8, rtt: Option<f32>, tier: Option<u8>, load: f32) -> RelayInfo {
        RelayInfo {
            relay_peer: Identity::from_bytes([id; 32]),
            relay_addrs: vec![format!("relay-{}:4433", id)],
            load,
            accepting: true,
            rtt_ms: rtt,
            tier,
            capabilities: Default::default(),
        }
    }

    #[test]
    fn test_session_id_generation() {
        let id1 = RelayClient::generate_session_id().unwrap();
        let id2 = RelayClient::generate_session_id().unwrap();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 16);
    }

    #[test]
    fn test_connection_strategy_direct_first() {
        let addrs = vec!["192.168.1.1:4433".to_string()];
        let strategy = choose_connection_strategy(&addrs, &[], &[], false).unwrap();
        
        match strategy {
            ConnectionStrategy::Direct { addrs: a } => {
                assert_eq!(a.len(), 1);
            }
            _ => panic!("expected direct strategy"),
        }
    }

    #[test]
    fn test_connection_strategy_fallback_to_relay() {
        let addrs = vec!["192.168.1.1:4433".to_string()];
        let relay = make_relay(1, Some(50.0), Some(0), 0.5);
        
        let strategy = choose_connection_strategy(&addrs, &[relay], &[], true).unwrap();
        
        match strategy {
            ConnectionStrategy::Relayed { relay: r, .. } => {
                assert_eq!(r.relay_addrs[0], "relay-1:4433");
            }
            _ => panic!("expected relayed strategy"),
        }
    }

    #[test]
    fn test_relay_selection_score() {
        // Fast relay: low RTT, low load, tier 0
        let fast_relay = make_relay(1, Some(20.0), Some(0), 0.1);
        
        // Slow relay: high RTT, high load, tier 2
        let slow_relay = make_relay(2, Some(150.0), Some(2), 0.8);
        
        // Fast relay should have lower (better) score
        assert!(fast_relay.selection_score() < slow_relay.selection_score());
    }

    #[test]
    fn test_relay_selection_prefers_measured() {
        // Relay with measurements
        let measured = make_relay(1, Some(30.0), Some(0), 0.5);
        
        // Relay without measurements (uses defaults: 200ms RTT, tier penalty 40ms)
        let unmeasured = make_relay(2, None, None, 0.2);
        
        // Measured relay should be preferred (lower score)
        assert!(measured.selection_score() < unmeasured.selection_score());
        assert!(measured.has_latency_info());
        assert!(!unmeasured.has_latency_info());
    }

    #[test]
    fn test_mutual_relay_selection() {
        let relay_a = make_relay(1, Some(100.0), Some(1), 0.3);
        let relay_b = make_relay(2, Some(50.0), Some(0), 0.2);  // Better RTT
        
        // Both know about relay_a and relay_b, but with different metrics
        let our_relays = vec![relay_a.clone(), relay_b.clone()];
        let peer_relays = vec![
            make_relay(1, None, None, 0.4),
            make_relay(2, None, None, 0.3),
        ];
        
        let result = find_best_mutual_relay(&our_relays, &peer_relays);
        assert!(result.is_some());
        
        // Should pick relay_b (better score due to lower RTT and tier)
        let selected = result.unwrap();
        assert_eq!(selected.relay_peer, Identity::from_bytes([2u8; 32]));
    }

    #[tokio::test]
    async fn test_relay_client_session_verification() {
        let client = RelayClient::new();
        let session_id = RelayClient::generate_session_id().unwrap();
        let relay_identity = Identity::from_bytes([1u8; 32]);
        let other_relay = Identity::from_bytes([2u8; 32]);
        let unknown_session: [u8; 16] = [0xFF; 16];
        
        // Initially no session registered
        assert!(!client.verify_session(&session_id, &relay_identity).await);
        assert!(!client.has_session(&session_id).await);
        
        // Register session
        client.register_session(session_id, relay_identity).await;
        
        // Session should now verify with correct relay
        assert!(client.verify_session(&session_id, &relay_identity).await);
        assert!(client.has_session(&session_id).await);
        
        // Session should NOT verify with different relay (prevents injection)
        assert!(!client.verify_session(&session_id, &other_relay).await);
        
        // Unknown session should not verify
        assert!(!client.verify_session(&unknown_session, &relay_identity).await);
        
        // Get session relay should return correct identity
        assert_eq!(client.get_session_relay(&session_id).await, Some(relay_identity));
        assert_eq!(client.get_session_relay(&unknown_session).await, None);
        
        // Remove session
        let removed = client.remove_session(&session_id).await;
        assert_eq!(removed, Some(relay_identity));
        
        // Session should no longer verify after removal
        assert!(!client.verify_session(&session_id, &relay_identity).await);
    }
}
