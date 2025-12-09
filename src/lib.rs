mod dht;
mod identity;
mod net;
mod pubsub;
mod node;

#[inline]
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub use node::Node;
pub use node::Message;
pub use quinn::Connection;

// Re-export types needed for relay integration
pub use identity::{Identity, RelayEndpoint};

