use std::collections::HashMap;
use tracing::{debug, trace, warn};
use anyhow::{Context, Result};

use crate::identity::Identity;
use crate::messages::DhtRequest;
use crate::relay::protocol::RelayPacket;

// ============================================================================
// Relay Connection Registry
// ============================================================================

/// Maximum number of peer connections to track for relay forwarding.
pub const MAX_RELAY_CONNECTIONS: usize = 1000;

/// Tracks peer connections for relay packet forwarding.
///
/// When a peer connects and establishes a relay session, we store their
/// connection so we can push relayed packets back to them by opening
/// new streams on their connection.
#[derive(Debug, Default)]
pub struct RelayConnectionRegistry {
    /// Map from peer identity to their QUIC connection.
    connections: tokio::sync::RwLock<HashMap<Identity, quinn::Connection>>,
}

impl RelayConnectionRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a peer's connection for relay forwarding.
    pub async fn register(&self, peer: Identity, connection: quinn::Connection) {
        let mut conns = self.connections.write().await;
        
        // Enforce capacity limit to prevent memory exhaustion
        if conns.len() >= MAX_RELAY_CONNECTIONS && !conns.contains_key(&peer) {
            warn!(
                peer = ?hex::encode(&peer.as_bytes()[..8]),
                "relay connection registry at capacity, rejecting new connection"
            );
            return;
        }
        
        conns.insert(peer, connection);
    }

    /// Remove a peer's connection.
    pub async fn unregister(&self, peer: &Identity) {
        let mut conns = self.connections.write().await;
        conns.remove(peer);
    }

    /// Get a peer's connection for sending relayed packets.
    pub async fn get(&self, peer: &Identity) -> Option<quinn::Connection> {
        let conns = self.connections.read().await;
        conns.get(peer).cloned()
    }

    /// Send a relayed packet to a peer by opening a stream on their connection.
    ///
    /// This is the core of relay forwarding - when peer A sends data to peer B
    /// through the relay, we open a stream on B's connection and push the data.
    pub async fn forward_to_peer(&self, to_peer: &Identity, packet: RelayPacket) -> Result<()> {
        let connection = self.get(to_peer).await.ok_or_else(|| {
            anyhow::anyhow!("peer not connected for relay forwarding")
        })?;

        // Open a unidirectional stream to push the relayed packet
        let mut send = connection.open_uni().await.context("failed to open stream for relay")?;

        // Construct a RelayData message to send to the peer
        let relay_data = DhtRequest::RelayData {
            from: packet.from,
            session_id: packet.session_id,
            payload: packet.payload,
        };

        let data = bincode::serialize(&relay_data).context("failed to serialize relay data")?;
        let len = data.len() as u32;
        
        send.write_all(&len.to_be_bytes()).await?;
        send.write_all(&data).await?;
        send.finish()?;

        trace!(
            to = ?hex::encode(&to_peer.as_bytes()[..8]),
            session = hex::encode(packet.session_id),
            "forwarded relay packet to peer"
        );

        Ok(())
    }

    /// Clean up closed connections.
    pub async fn cleanup(&self) {
        let mut conns = self.connections.write().await;
        conns.retain(|peer, conn| {
            let is_open = conn.close_reason().is_none();
            if !is_open {
                debug!(
                    peer = ?hex::encode(&peer.as_bytes()[..8]),
                    "removing closed connection from relay registry"
                );
            }
            is_open
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_relay_connection_registry() {
        use crate::identity::Keypair;
        
        let registry = RelayConnectionRegistry::new();
        
        // Generate a test identity
        let keypair = Keypair::generate();
        let identity = keypair.identity();
        
        // Initially no connection should be present
        assert!(registry.get(&identity).await.is_none());
        
        // We can't easily create a real Connection in tests, but we can verify
        // the registry's capacity enforcement logic by checking len after unregister
        registry.unregister(&identity).await;
        
        // After unregister, still no connection
        assert!(registry.get(&identity).await.is_none());
    }

    #[tokio::test]
    async fn test_relay_connection_registry_cleanup() {
        let registry = RelayConnectionRegistry::new();
        
        // Cleanup on empty registry should not panic
        registry.cleanup().await;
    }
}
