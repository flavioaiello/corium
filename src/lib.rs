mod crypto;
mod dht;
mod hyparview;
mod identity;
mod messages;
mod node;
mod plumtree;
mod ratelimit;
mod relay;
mod routing;
mod rpc;
mod smartsock;

#[inline]
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub use messages::Message;
pub use node::Node;
pub use quinn::Connection;

// Re-export types needed for relay integration
pub use identity::{Identity, RelayEndpoint};

