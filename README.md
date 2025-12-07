# Corium

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/corium.svg)](https://crates.io/crates/corium)
[![Documentation](https://docs.rs/corium/badge.svg)](https://docs.rs/corium)

**Batteries-included adaptive mesh networking**

Corium is a high-performance, secure, and adaptive mesh networking library written in Rust. It provides a robust foundation for building decentralized applications, scale-out fabrics, and distributed services. It features built-in NAT traversal, efficient PubSub, and a secure identity system.

## Why Corium?

- **Zero-Config NAT Traversal**: "Smartsock" technology automatically punches holes through NATs and relays traffic when necessary, ensuring connectivity in difficult network environments.
- **Adaptive & Resilient**: Uses a Kademlia-based DHT with adaptive parameters (`k` and `alpha`) that adjust to network churn.
- **Efficient PubSub**: Implements the PlumTree (Epidemic Broadcast Trees) protocol for highly efficient and scalable message propagation.
- **Secure by Default**: Built on Ed25519 identities ("Zero-Hash Architecture") and QUIC encryption. Every node is cryptographically verifiable.
- **Developer Friendly**: Simple, high-level async API for bootstrapping, messaging, and state management.

## Quick Start

Add `corium` to your `Cargo.toml`:

```toml
[dependencies]
corium = "0.3"
tokio = { version = "1", features = ["full"] }
```

### 1. Create a Node

```rust
use corium::Node;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Bind to a random port
    let node = Node::bind("0.0.0.0:0").await?;
    
    println!("Node started at {}", node.local_addr()?);
    println!("Identity: {}", node.identity());
    
    Ok(())
}
```

### 2. PubSub Messaging

```rust
// Subscribe to a topic
node.subscribe("chat/general").await?;

// Publish a message
node.publish("chat/general", b"Hello, world!").await?;

// Receive messages
let mut messages = node.messages().await?;
while let Some(msg) = messages.recv().await {
    println!("Received on {}: {:?}", msg.topic, String::from_utf8_lossy(&msg.payload));
}
```

### 3. Direct Messaging

```rust
// Send a direct message to a peer (by Identity)
node.send_direct(peer_identity, b"Secret message").await?;

// Receive direct messages
let mut dms = node.direct_messages().await?;
while let Some((from, payload)) = dms.recv().await {
    println!("DM from {}: {:?}", from, String::from_utf8_lossy(&payload));
}
```

## Common Use Cases
- **Chat / Messaging**: Decentralized chat applications with topic-based rooms.
- **File Sync / Scale-out Storage**: Distributed file sharing and synchronization.
- **IoT Device Mesh**: Connecting devices behind NATs without a central server.
- **Distributed Computing**: Job distribution and coordination among peers.

## Features

### Mesh Networking
- **QUIC Transport**: Uses `quinn` for high-performance, encrypted, multiplexed connections.
- **HyParView**: Hybrid Partial View protocol for maintaining a robust overlay network.
- **Latency-Aware Routing**: Prioritizes low-latency paths for better performance.

### PlumTree Publish/Subscribe
- **Epidemic Broadcast Trees**: Combines the robustness of gossip (epidemic) protocols with the efficiency of tree-based multicast.
- **Lazy & Eager Push**: Optimizes bandwidth by pushing full messages to a subset of peers and announcing availability to others.
- **Automatic Repair**: Heals the broadcast tree automatically when nodes fail or disconnect.

### Smartsock NAT Traversal
- **Hole Punching**: Automatically attempts to punch holes through NATs for direct fabric connections.
- **Relay Fallback**: Seamlessly falls back to relaying traffic through other nodes if direct connection fails.
- **Path Probing**: Continuously monitors path quality and switches between direct and relayed paths to optimize latency.
- **Connection Migration**: Leverages QUIC connection migration for seamless path switching.

### Peer Discovery (DHT)
- **Kademlia-based DHT**: Distributed Hash Table for storing and retrieving peer contact information.
- **Adaptive Parameters**: Dynamically adjusts replication factor (`k`) and concurrency (`alpha`) based on network stability.
- **Sloppy Hashing**: Supports "sloppy" storage to handle hot spots and improve availability.

### Identity & Security (Zero-Hash Architecture)
- **Ed25519 Identities**: Node IDs are derived directly from their public keys.
- **Mutual Authentication**: All connections are mutually authenticated using TLS 1.3 (via QUIC).
- **Sybil Protection**: The cryptographic identity system makes Sybil attacks computationally expensive.

## Architecture

### Domain Model
- **Node**: The central entity representing a peer in the network.
- **Identity**: A cryptographic identity (Ed25519 public key).
- **Contact**: A tuple of (Identity, Address) used for connection establishment.
- **SmartSock**: The transport layer abstraction handling NAT traversal and reliability.

## Core Concepts

### Public API Facade
The `Node` struct provides the primary interface. It hides the complexity of the underlying DHT, PubSub, and Transport layers.

### Ed25519 Identity (Zero-Hash Architecture)
Corium uses a "Zero-Hash" approach where the Node ID *is* the public key (or a direct derivation), eliminating the need for a separate hash-based ID space mapping. This simplifies verification and prevents ID spoofing.

### Routing Table
The routing table (K-Buckets) stores contact information for other peers, organized by XOR distance. It is used for DHT lookups and peer discovery.

### Latency Tiering
Peers are prioritized based on round-trip time (RTT). The system prefers low-latency peers for routing and storage operations to improve overall network performance.

## Network Protocol

### ALPN
Corium uses specific ALPN (Application-Layer Protocol Negotiation) tokens to identify its traffic during the TLS handshake, ensuring compatibility and security.

### RPC Messages
Communication between nodes uses a custom RPC protocol defined in `messages.rs`. Messages are serialized efficiently (e.g., using `bincode` or similar) and include:
- `Ping` / `Pong`
- `FindNode` / `Nodes`
- `FindValue` / `Value`
- `Store`
- `Publish` (PlumTree)
- `IHave` / `IWant` / `Graft` / `Prune` (PlumTree Control)

### NAT Traversal

#### How It Works
1.  **STUN-like Discovery**: Nodes discover their public endpoints via `PathProbe` messages.
2.  **Hole Punching**: Nodes attempt to send packets to each other simultaneously to open NAT mappings.
3.  **Relaying**: If hole punching fails, traffic is relayed through a mutual contact (Relay Node).

#### Connection Strategy
The `SmartSock` logic maintains a state machine for each peer connection (`PeerPathState`), tracking:
- Direct candidates
- Relay candidates
- Active path (Direct or Relay)
- RTT measurements

#### Dynamic Relay Selection
Nodes can act as relays for others. The system dynamically selects the best relay based on availability and latency.

#### Automatic Path Switching (SmartSock)
If a direct connection degrades or fails, `SmartSock` automatically switches to a relay path. Conversely, if a direct path becomes available (e.g., after successful hole punching), it upgrades from relay to direct.

## Publish/Subscribe (PlumTree)

### How It Works
PlumTree builds a spanning tree over the mesh for each topic.
- **Eager Push**: Messages are immediately forwarded to a small set of "eager" peers (tree branches).
- **Lazy Push**: Message IDs (IHave) are gossiped to "lazy" peers. If a peer misses a message, it requests it (IWant), potentially triggering a tree repair (Graft).

### Configuration
- `eager_peers`: Number of peers to push full messages to (default: 4).
- `lazy_peers`: Number of peers to gossip metadata to (default: 6).

## Security

### Security Hardening
- **Input Validation**: All incoming messages are strictly validated for size and format.
- **Resource Bounding**: Limits on message sizes, buffer capacities, and concurrent connections prevent DoS attacks.

### Sybil Protection
The cost of generating valid Ed25519 keys provides a baseline protection. Application-level trust mechanisms can be built on top of these stable identities.

### Protocol Security
- **TLS 1.3**: All data in transit is encrypted and authenticated.
- **Replay Protection**: Nonces and timestamps prevent replay attacks.

### Connection Rate Limiting
`ConnectionRateLimiter` enforces limits on:
- Connection attempts per second.
- Total active connections per IP.

### PubSub Message Authentication
Messages are signed by the sender's private key. Recipients verify the signature against the sender's Identity before processing or forwarding.

## Testing

### Test Categories
- **Unit Tests**: Cover individual components (Routing Table, Message Serialization).
- **Integration Tests**: Simulate small networks of nodes to verify discovery and messaging.
- **Simulation**: `spawn_cluster.sh` allows running a local cluster for stress testing.

## Dependencies

- `quinn`: QUIC implementation.
- `tokio`: Async runtime.
- `ed25519-dalek`: Elliptic curve cryptography.
- `blake3`: Cryptographic hashing.
- `serde`: Serialization.

## References

Corium's design is informed by the following research:

### NAT Traversal with QUIC

- **Liang, J., Xu, W., Wang, T., Yang, Q., & Zhang, S.** (2024). *Implementing NAT Hole Punching with QUIC*. VTC2024-Fall Conference. [arXiv:2408.01791](https://arxiv.org/abs/2408.01791)
  
  This paper demonstrates that QUIC-based hole punching effectively reduces hole punching time compared to TCP, with pronounced advantages in weak network environments. It also shows that QUIC connection migration for connection restoration saves 2 RTTs compared to re-punching, which Corium leverages for seamless path switching.

### Distributed Hash Tables

- **Freedman, M. J., Freudenthal, E., & Mazières, D.** (2004). *Democratizing Content Publication with Coral*. NSDI '04. [PDF](https://www.cs.princeton.edu/~mfreed/docs/coral-nsdi04.pdf)

  Coral introduced the concept of a "sloppy" DHT (DSHT) with hierarchical clustering based on latency. Corium adopts similar ideas with its latency-based tiering system, which uses k-means clustering to organize peers by RTT and prioritize fast peers for lookups while offloading storage pressure to slower tiers.
