mod crypto;
mod dht;
mod hyparview;
mod identity;
mod messages;
mod node;
mod plumtree;
mod ratelimit;
mod routing;
mod rpc;
mod transport;

#[inline]
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// Public API - Node is the facade for all operations
pub use node::Node;

