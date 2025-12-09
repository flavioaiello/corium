//! Relay network trait for relay connection establishment.

use anyhow::Result;
use async_trait::async_trait;

use crate::dht::Contact;
use crate::identity::Identity;

/// Session information for an established relay connection.
#[derive(Clone, Debug)]
pub struct RelaySession {
    /// Unique session identifier.
    pub session_id: [u8; 16],
    /// Address of the relay's data forwarding endpoint.
    pub relay_data_addr: String,
    /// The relay node's identity.
    pub relay_identity: Identity,
}

/// Network trait for relay connection establishment.
/// 
/// This trait provides the capability to establish relay connections
/// through intermediary nodes when direct connectivity is not possible.
#[async_trait]
pub trait RelayNetwork: Send + Sync {
    /// Request a relay connection to a target peer through a relay node.
    /// 
    /// This initiates a relay session. The relay will wait for the target
    /// peer to also connect with the same session ID.
    async fn request_relay(
        &self,
        relay: &Contact,
        target: Identity,
    ) -> Result<RelaySession>;
    
    /// Join an existing relay session initiated by another peer.
    /// 
    /// The session_id must match a pending session on the relay.
    async fn join_relay(
        &self,
        relay: &Contact,
        session_id: [u8; 16],
    ) -> Result<RelaySession>;
}
