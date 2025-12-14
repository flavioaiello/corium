# Corium

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/corium.svg)](https://crates.io/crates/corium)
[![Documentation](https://docs.rs/corium/badge.svg)](https://docs.rs/corium)

**Batteries-included adaptive mesh networking**

Corium is a high-performance, secure, and adaptive mesh networking library written in Rust. It provides a robust foundation for building decentralized applications, scale-out fabrics, and distributed services with built-in NAT traversal, efficient PubSub, and a cryptographic identity system.

## Why Corium?

| Feature | Description |
|---------|-------------|
| **Zero-Config NAT Traversal** | SmartSock automatically punches holes through NATs and relays traffic when necessary |
| **Adaptive DHT** | Kademlia-based DHT with adaptive `k` and `α` parameters that adjust to network churn |
| **Efficient PubSub** | PlumTree protocol for scalable message propagation with automatic tree repair |
| **Secure by Default** | Ed25519 identities + QUIC/TLS 1.3 encryption with mutual authentication |
| **Simple API** | High-level async API for bootstrapping, messaging, and peer discovery |

## Quick Start

Add `corium` to your `Cargo.toml`:

```toml
[dependencies]
corium = "0.3"
tokio = { version = "1", features = ["full"] }
```

### Create a Node

```rust
use corium::Node;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let node = Node::bind("0.0.0.0:0").await?;
    
    println!("Listening on {}", node.local_addr()?);
    println!("Identity: {}", node.identity());
    
    // Bootstrap from an existing peer
    node.bootstrap(
        "abc123...",                    // peer identity (64 hex chars)
        "192.168.1.100:4433"            // peer address
    ).await?;
    
    Ok(())
}
```

### PubSub Messaging

```rust
// Subscribe to a topic
node.subscribe("chat/general").await?;

// Publish a message
node.publish("chat/general", b"Hello, world!".to_vec()).await?;

// Receive messages
let mut messages = node.messages().await?;
while let Some(msg) = messages.recv().await {
    println!("[{}] {}: {}", msg.topic, msg.from, String::from_utf8_lossy(&msg.data));
}
```

### Direct Messaging

```rust
// Send a direct message to a peer by identity
node.send_direct("abc123...", b"Secret message".to_vec()).await?;

// Receive direct messages
let mut dms = node.direct_messages().await?;
while let Some((from, data)) = dms.recv().await {
    println!("DM from {}: {}", from, String::from_utf8_lossy(&data));
}
```

### Peer Discovery

```rust
// Connect to a peer by identity (DHT lookup + SmartConnect)
let conn = node.connect_peer("abc123...").await?;

// Find peers close to a target identity
let peers = node.find_peers(target_identity).await?;

// Resolve a peer's endpoint record from DHT
let record = node.resolve_peer(&peer_identity).await?;
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           Node                                   │
│  (Public API: bind, bootstrap, publish, subscribe, connect)     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   PlumTree   │  │  HyParView   │  │       DhtNode        │   │
│  │   (PubSub)   │  │  (Overlay)   │  │   (Peer Discovery)   │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘   │
│         │                 │                      │               │
│         └─────────────────┼──────────────────────┘               │
│                           │                                      │
│                    ┌──────▼───────┐                              │
│                    │   RpcNode    │                              │
│                    │  (RPC Layer) │                              │
│                    └──────┬───────┘                              │
│                           │                                      │
│         ┌─────────────────┼─────────────────┐                    │
│         │                 │                 │                    │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐           │
│  │   SmartSock  │  │    QUIC      │  │  UdpRelay    │           │
│  │ (Path Mgmt)  │  │  (Endpoint)  │  │  Forwarder   │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Module Overview

| Module | Lines | Purpose |
|--------|-------|---------|
| `node.rs` | ~370 | Public API facade, orchestrates all subsystems |
| `transport.rs` | ~2260 | SmartSock, path probing, relay tunneling, virtual addressing |
| `rpc.rs` | ~1190 | Connection caching, RPC dispatch, SmartConnect logic |
| `dht.rs` | ~2560 | Kademlia DHT with adaptive parameters, iterative lookups |
| `plumtree.rs` | ~1570 | Epidemic broadcast trees for PubSub |
| `hyparview.rs` | ~770 | Hybrid partial view membership protocol |
| `routing.rs` | ~610 | K-bucket routing table with rate limiting |
| `identity.rs` | ~880 | Ed25519 keypairs, endpoint records, signatures |
| `messages.rs` | ~630 | RPC message types and serialization |
| `crypto.rs` | ~400 | TLS certificates, Ed25519 verification |

## Core Concepts

### Identity (Zero-Hash Architecture)

Node identities are Ed25519 public keys (32 bytes, displayed as 64 hex characters). This "Zero-Hash" approach means the node ID *is* the public key—no separate hash mapping required.

```rust
let keypair = Keypair::generate();
let identity: Identity = keypair.identity();  // [u8; 32]
println!("{}", identity);  // 64 hex chars
```

### Contact

A `Contact` represents a reachable peer: identity + network addresses.

```rust
pub struct Contact {
    pub identity: Identity,
    pub addr: String,        // Primary address
    pub addrs: Vec<String>,  // Additional addresses
}
```

### SmartAddr (Virtual Addressing)

SmartSock maps identities to virtual IPv6 addresses in the `fd00:c0f1::/48` prefix, enabling identity-based routing through QUIC.

### SmartConnect

When connecting to a peer, Corium uses a multi-stage approach:

1. **Direct Connection**: Try connecting directly to peer's addresses
2. **DHT Path Nodes**: Nodes contacted during DHT lookup become relay candidates
3. **Relay Fallback**: If direct fails, negotiate relay through path nodes
4. **Path Probing**: Continuously probe for better paths after connection

## NAT Traversal

### How SmartSock Works

```
┌────────┐                    ┌────────┐                    ┌────────┐
│ Node A │                    │ Relay  │                    │ Node B │
│ (NAT)  │                    │        │                    │ (NAT)  │
└───┬────┘                    └───┬────┘                    └───┬────┘
    │                             │                             │
    │ 1. Try direct connect       │                             │
    │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
    │                             │                             │
    │ 2. If failed, request relay │                             │
    │────────────────────────────▶│                             │
    │                             │ 3. Notify target            │
    │                             │────────────────────────────▶│
    │                             │                             │
    │                             │◀────────────────────────────│
    │◀────────────────────────────│ 4. Relay established        │
    │                             │                             │
    │ 5. CRLY-framed packets      │                             │
    │════════════════════════════▶│════════════════════════════▶│
    │◀════════════════════════════│◀════════════════════════════│
    │                             │                             │
    │ 6. Path probing (SMPR)      │                             │
    │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
    │                             │                             │
    │ 7. Upgrade to direct if possible                          │
    │──────────────────────────────────────────────────────────▶│
```

### Protocol Headers

| Protocol | Magic | Description |
|----------|-------|-------------|
| Relay Tunnel | `CRLY` | 4-byte magic + 16-byte session ID + payload |
| Path Probe | `SMPR` | Request (0x01) / Response (0x02) with RTT measurement |

### Path Selection

SmartSock maintains a `PeerPathState` for each peer with:
- **Direct candidates**: Known IP addresses
- **Relay candidates**: Available relay tunnels
- **Active path**: Currently selected path
- **RTT measurements**: Exponential moving average (α=0.2)

Direct paths are preferred unless relay is significantly faster (>50ms advantage).

## DHT (Distributed Hash Table)

### Kademlia Implementation

- **XOR Distance Metric**: Peers organized by XOR distance from target
- **K-Buckets**: 256 buckets for 256-bit key space
- **Iterative Lookups**: Parallel queries with configurable α
- **Adaptive Parameters**: `k` and `α` adjust based on churn rate

### Key Operations

```rust
// Store a value
dht.store(key, value).await?;

// Retrieve a value
let value = dht.get(key).await?;

// Find nodes close to a key
let nodes = dht.find_node(target).await?;
```

### Latency Tiering

Peers are clustered by RTT into tiers:
- **Tier 0**: Fastest peers (used for lookups)
- **Tier 1-N**: Progressively slower peers (used for storage offloading)

## PlumTree (PubSub)

### Epidemic Broadcast Trees

PlumTree combines gossip reliability with tree efficiency:

1. **Eager Push**: Forward full messages to `eager_peers` (default: 4)
2. **Lazy Push**: Send `IHave` to `lazy_peers` (default: 6)
3. **IWant**: Request missing messages
4. **Graft/Prune**: Dynamically repair the broadcast tree

### Message Flow

```
Publisher ──▶ Eager Peers ──▶ Their Eager Peers ──▶ ...
     │              │
     └── IHave ────▶ Lazy Peers (request via IWant if needed)
```

### Message Authentication

All PubSub messages are signed with the sender's Ed25519 key:

```rust
pub struct PlumTreeMessage::Publish {
    topic: String,
    msg_id: [u8; 32],
    source: Identity,
    seqno: u64,
    data: Vec<u8>,
    signature: Vec<u8>,  // Ed25519 signature
}
```

## HyParView (Membership)

Maintains a robust overlay network with:
- **Active View**: Small set of direct connections (default: 5)
- **Passive View**: Larger pool of known peers (default: 30)
- **Shuffle Protocol**: Periodically exchanges peers to improve connectivity
- **Forward Join**: New nodes propagate through the network

## Security

### Defense Layers

| Layer | Protection |
|-------|------------|
| **Transport** | TLS 1.3 via QUIC (mutual authentication) |
| **Identity** | Ed25519 key pairs, certificates embed public key |
| **Messages** | Signed PubSub, bounded deserialization |
| **Resources** | Rate limiting, bounded collections, timeouts |

### Security Constants

```rust
const MAX_VALUE_SIZE: usize = 1024 * 1024;           // 1 MB max DHT value
const MAX_MESSAGE_SIZE: usize = 64 * 1024;           // 64 KB max PubSub message
const MAX_CONTACTS_PER_RESPONSE: usize = 100;        // Limit DHT response size
const CONNECTION_STALE_TIMEOUT: Duration = 60s;      // Connection cache TTL
const RPC_STREAM_TIMEOUT: Duration = 30s;            // RPC timeout
```

## CLI Usage

### Running a Node

```bash
# Start a node on a random port
cargo run --release

# Start with specific bind address
cargo run --release -- --bind 0.0.0.0:4433

# Bootstrap from existing peer
cargo run --release -- -B 192.168.1.100:4433/abc123...
```

### Chatroom Example

```bash
# Start first node
cargo run --release --example chatroom -- --name Alice --room general

# Join from another terminal (copy bootstrap string from first node)
cargo run --release --example chatroom -- --name Bob --room general -B <bootstrap_string>
```

Commands in chatroom:
- Type message and press Enter to broadcast
- `/dm <identity> <message>` - Send direct message
- `/peers` - List known peers
- `/quit` - Exit

## Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run specific test
cargo test test_smart_addr

# Run integration tests
cargo test --test node_public_api

# Spawn local cluster
./scripts/spawn_cluster.sh
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `quinn` | QUIC implementation |
| `tokio` | Async runtime |
| `ed25519-dalek` | Ed25519 signatures |
| `blake3` | Fast cryptographic hashing |
| `rustls` | TLS implementation |
| `bincode` | Binary serialization |
| `lru` | LRU caches |
| `tracing` | Structured logging |

## References

### NAT Traversal with QUIC

- **Liang, J., et al.** (2024). *Implementing NAT Hole Punching with QUIC*. VTC2024-Fall. [arXiv:2408.01791](https://arxiv.org/abs/2408.01791)
  
  Demonstrates QUIC hole punching advantages and connection migration saving 2 RTTs.

### Distributed Hash Tables

- **Freedman, M. J., et al.** (2004). *Democratizing Content Publication with Coral*. NSDI '04. [PDF](https://www.cs.princeton.edu/~mfreed/docs/coral-nsdi04.pdf)

  Introduced "sloppy" DHT with latency-based clustering—inspiration for Corium's tiering system.

### PlumTree

- **Leitão, J., Pereira, J., & Rodrigues, L.** (2007). *Epidemic Broadcast Trees*. SRDS '07.

  The original PlumTree paper combining gossip reliability with tree efficiency.

### HyParView

- **Leitão, J., Pereira, J., & Rodrigues, L.** (2007). *HyParView: A Membership Protocol for Reliable Gossip-Based Broadcast*. DSN '07.

  Hybrid partial view membership protocol for robust overlay maintenance.

## License

MIT License - see [LICENSE](LICENSE) for details.
