use anyhow::Result;
use async_trait::async_trait;

use crate::dht::Contact;
use crate::identity::Identity;

use super::message::PubSubMessage;

/// Network trait for GossipSub message delivery.
/// 
/// This trait provides the capability for GossipSub to send
/// PubSub-specific messages to peers.
#[async_trait]
pub trait GossipSubNetwork: Send + Sync {
    /// Send a PubSub message to a specific peer.
    /// 
    /// This is used for all gossipsub control messages (Subscribe, Unsubscribe,
    /// Graft, Prune, IHave, IWant) and data messages (Publish).
    async fn send_pubsub(&self, to: &Contact, from: Identity, message: PubSubMessage) -> Result<()>;
    
    /// Send multiple PubSub messages to a peer in a single RPC.
    /// 
    /// This is more efficient when there are multiple queued messages
    /// for the same peer.
    async fn send_pubsub_batch(&self, to: &Contact, from: Identity, messages: Vec<PubSubMessage>) -> Result<()> {
        // Default implementation: send one by one
        for msg in messages {
            self.send_pubsub(to, from, msg).await?;
        }
        Ok(())
    }
}
