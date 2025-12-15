# Corium

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/corium.svg)](https://crates.io/crates/corium)
[![Documentation](https://docs.rs/corium/badge.svg)](https://docs.rs/corium)

**Batteries-included adaptive mesh networking**

Corium is a high-performance, secure, and adaptive mesh networking library written in Rust. It provides a robust foundation for building decentralized applications, scale-out fabrics, and distributed services with built-in NAT traversal, efficient PubSub, and a cryptographic identity system.

## Why Corium?

- **Zero Configuration** — Self-organizing mesh with automatic peer discovery
- **NAT Traversal** — Built-in relay infrastructure and path probing via SmartSock
- **Secure by Default** — Ed25519 identities with mutual TLS on every connection
- **Adaptive Performance** — Latency-tiered DHT with automatic path optimization
- **Complete Stack** — DHT storage, PubSub messaging, direct messaging, and membership management

## Quick Start

Add Corium to your `Cargo.toml`:

```toml
[dependencies]
corium = "0.3"
tokio = { version = "1", features = ["full"] }
```

### Create a Node

```rust
use corium::Node;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Bind to any available port
    let node = Node::bind("0.0.0.0:0").await?;
    
    println!("Node identity: {}", node.identity());
    println!("Listening on: {}", node.local_addr()?);
    
    // Bootstrap from an existing peer
    node.bootstrap("peer_identity_hex", "192.168.1.100:4433").await?;
    
    Ok(())
}
```

### PubSub Messaging

```rust
// Subscribe to a topic
node.subscribe("events/alerts").await?;

// Publish messages (signed with your identity)
node.publish("events/alerts", b"System update available".to_vec()).await?;

// Receive messages
let mut rx = node.messages().await?;
while let Some(msg) = rx.recv().await {
    println!("[{}] from {}: {:?}", msg.topic, &msg.from[..16], msg.data);
}
```

### Direct Messaging

```rust
// Send direct message to a peer (resolved via DHT)
node.send_direct("peer_identity_hex", b"Hello!".to_vec()).await?;

// Receive direct messages
let mut dm_rx = node.direct_messages().await?;
while let Some((from, data)) = dm_rx.recv().await {
    println!("DM from {}: {:?}", &from[..16], data);
}
```

### DHT Storage

```rust
// Store content-addressed data (key = blake3 hash)
let key = node.put(b"my data".to_vec()).await?;

// Store at a specific key
node.put_at(key, b"updated data".to_vec()).await?;

// Retrieve data
if let Some(data) = node.get(&key).await? {
    println!("Retrieved: {:?}", data);
}
```

### NAT Traversal

```rust
// Automatic NAT configuration (helper is a known peer identity in the DHT)
let helper_identity = "abc123..."; // hex-encoded peer identity
let (is_public, relay, incoming_rx) = node.configure_nat(helper_identity, addresses).await?;

if is_public {
    println!("Publicly reachable - can serve as relay");
} else {
    println!("Behind NAT - using relay: {:?}", relay);
    
    // Handle incoming relay connections
    if let Some(mut rx) = incoming_rx {
        while let Some(incoming) = rx.recv().await {
            node.accept_incoming(&incoming).await?;
        }
    }
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                              Node                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │   PlumTree  │  │  HyParView  │  │     DHT     │  │   Relay    │ │
│  │   (PubSub)  │  │ (Membership)│  │  (Storage)  │  │  (Client)  │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘ │
│         │                │                │                │        │
│  ┌──────┴────────────────┴────────────────┴────────────────┴──────┐ │
│  │                          RpcNode                               │ │
│  │            (Connection pooling, request routing)               │ │
│  └────────────────────────────┬───────────────────────────────────┘ │
│  ┌────────────────────────────┴───────────────────────────────────┐ │
│  │                         SmartSock                              │ │
│  │  (Path probing, relay tunnels, virtual addressing, QUIC mux)   │ │
│  └────────────────────────────┬───────────────────────────────────┘ │
│  ┌────────────────────────────┴───────────────────────────────────┐ │
│  │                       QUIC (Quinn)                             │ │
│  └────────────────────────────┬───────────────────────────────────┘ │
│  ┌────────────────────────────┴───────────────────────────────────┐ │
│  │                   UDP Socket + Relay Server                    │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### Module Overview

| Module | Description |
|--------|-------------|
| `node` | High-level facade exposing the complete public API |
| `transport` | SmartSock with path probing, relay tunnels, and virtual addresses |
| `rpc` | Connection pooling, RPC dispatch, and actor-based state management |
| `dht` | Kademlia-style DHT with latency tiering and adaptive parameters |
| `plumtree` | Epidemic broadcast trees for efficient PubSub |
| `hyparview` | Hybrid partial view membership protocol |
| `relay` | UDP relay server and client for NAT traversal |
| `crypto` | Ed25519 certificates, identity verification, custom TLS |
| `identity` | Keypairs, endpoint records, and signed address publication |
| `storage` | LRU storage with per-peer quotas and pressure-based eviction |
| `routing` | Kademlia routing table with bucket refresh |
| `messages` | Protocol message types and bounded serialization |

## Core Concepts

### Identity (Ed25519 Public Keys)

Every node has a cryptographic identity derived from an Ed25519 keypair:

```rust
let node = Node::bind("0.0.0.0:0").await?;
let identity: String = node.identity();  // 64 hex characters (32 bytes)
let keypair = node.keypair();            // Access for signing
```

Identities are:
- **Self-certifying** — The identity IS the public key
- **Collision-resistant** — 256-bit space makes collisions infeasible
- **Verifiable** — Every connection verifies peer identity via mTLS

### Contact

A `Contact` represents a reachable peer:

```rust
pub struct Contact {
    pub identity: Identity,   // Ed25519 public key
    pub addrs: Vec<String>,   // List of addresses (IP:port)
}
```

### SmartAddr (Virtual Addressing)

SmartSock maps identities to virtual IPv6 addresses in the `fd00:c0f1::/32` range:

```
Identity (32 bytes) → blake3 hash → fd00:c0f1:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
```

This enables:
- **Transparent path switching** — QUIC sees stable addresses while SmartSock handles path changes
- **Relay abstraction** — Applications use identity-based addressing regardless of NAT status

### SmartConnect

Automatic connection establishment with fallback:

1. **Try direct connection** to published addresses
2. **If direct fails**, use peer's designated relays
3. **Configure relay tunnel** and establish QUIC connection through relay

```rust
// SmartConnect handles all complexity internally
let conn = node.connect("target_identity_hex").await?;
```

## NAT Traversal

### How SmartSock Works

SmartSock implements transparent NAT traversal:

1. **Path Probing** — Periodic probes measure RTT to all known paths
2. **Path Selection** — Best path chosen (direct preferred, relay as fallback)
3. **Relay Tunnels** — UDP packets wrapped in CRLY frames through relay
4. **Automatic Upgrade** — Switch from relay to direct when hole-punch succeeds

### Protocol Headers

**Path Probe (SMPR)**
```
┌──────────┬──────────┬──────────┬──────────────┐
│  Magic   │   Type   │  Tx ID   │  Timestamp   │
│  4 bytes │  1 byte  │  8 bytes │   8 bytes    │
└──────────┴──────────┴──────────┴──────────────┘
```

**Relay Frame (CRLY)**
```
┌──────────┬──────────────┬──────────────────────┐
│  Magic   │  Session ID  │    QUIC Payload      │
│  4 bytes │   16 bytes   │     (variable)       │
└──────────┴──────────────┴──────────────────────┘
```

### Path Selection Algorithm

```
if direct_path.rtt + 10ms < current_path.rtt:
    switch to direct_path
elif relay_path.rtt + 50ms < direct_path.rtt:
    switch to relay_path (relay gets 50ms handicap)
```

## DHT (Distributed Hash Table)

### Kademlia Implementation

- **256 k-buckets** with configurable k (default: 20, adaptive: 10-30)
- **Iterative lookups** with configurable α (default: 3, adaptive: 2-5)
- **Content-addressed storage** using blake3 hashing

### Key Operations

```rust
// Store and retrieve
let key = node.put(data).await?;
let value = node.get(&key).await?;

// Find peers near a target
let peers = node.find_peers(target_identity).await?;

// Resolve peer's published endpoint record
let record = node.resolve_peer(&peer_id).await?;
```

### Latency Tiering

The DHT implements Coral-inspired latency tiering:

- **RTT samples** collected per /16 IP prefix (IPv4) or /32 prefix (IPv6)
- **K-means clustering** groups prefixes into 1-7 latency tiers
- **Tiered lookups** prefer faster prefixes for lower latency
- **LRU-bounded** — tracks up to 10,000 active prefixes (~1MB memory)

## Scalability (10M+ Nodes)

Corium is designed to scale to millions of concurrent peers. Key design decisions enable efficient operation at scale:

### Memory Efficiency

| Component | At 10M Peers | Design |
|-----------|--------------|--------|
| **Routing table** | ~640 KB | 256 buckets × 20 contacts |
| **RTT tiering** | ~1 MB | /16 prefix-based (not per-peer) |
| **Passive view** | ~13 KB | 100 recovery candidates |
| **Connection cache** | ~200 KB | 1,000 LRU connections |
| **Message dedup** | ~2 MB | 10K source sequence windows |
| **Total** | **~4 MB** | Bounded, independent of network size |

### DHT Performance

| Metric | Value | Notes |
|--------|-------|-------|
| **Lookup hops** | O(log₂ N) ≈ 23 | Standard Kademlia complexity |
| **Parallel queries (α)** | 2-5 adaptive | Reduces under congestion |
| **Bucket size (k)** | 10-30 adaptive | Increases with churn |
| **Routing contacts** | ~5,120 max | 256 buckets × 20 |

### Corium vs Standard Kademlia

| Feature | Standard Kademlia | Corium | Benefit |
|---------|------------------|--------|---------|
| **Bucket size** | Fixed k=20 | Adaptive 10-30 | Handles churn spikes |
| **Concurrency** | Fixed α=3 | Adaptive 2-5 | Load shedding |
| **RTT optimization** | ❌ None | /16 prefix tiering | Lower latency paths |
| **Sybil protection** | ❌ Basic | Per-peer insertion limits | Eclipse resistant |
| **Gossip layer** | ❌ None | HyParView + PlumTree | Fast broadcast, recovery |
| **NAT traversal** | ❌ None | SmartSock + relays | Works behind NAT |
| **Identity** | SHA-1 node IDs | Ed25519 public keys | Self-certifying |

### Scaling Boundaries

| Parameter | Limit | Bottleneck |
|-----------|-------|------------|
| **Peers tracked** | Unlimited | Routing table is O(log N) |
| **DHT storage** | 100K entries | Memory-bounded LRU |
| **PubSub topics** | 10,000 | Per-node limit |
| **Peers per topic** | 1,000 | Gossip efficiency |
| **Relay sessions** | 10,000 | Per-relay server |

### Key Design Decisions

1. **Prefix-based RTT** — Tracking RTT per /16 IP prefix instead of per-peer reduces memory from O(N) to O(65K) while maintaining routing quality through statistical sampling.

2. **Adaptive parameters** — k and α automatically adjust based on observed churn rate, preventing cascade failures during network instability.

3. **Bounded data structures** — All caches use LRU eviction with fixed caps, ensuring memory stays constant regardless of network size.

4. **Hybrid membership** — HyParView's active/passive split provides strong connectivity (5 active peers) with good recovery (100 passive candidates) at minimal cost.

## PlumTree (PubSub)

### Epidemic Broadcast Trees

PlumTree combines:
- **Eager push** — Fast tree-based delivery to connected peers
- **Lazy push** — IHave/IWant recovery via gossip mesh
- **Automatic repair** — Tree rebuilds on peer failure

### Message Flow

```
Publisher → Eager Push (tree) → Subscribers
              ↓
         Lazy Push (IHave)
              ↓
         IWant requests
              ↓
         Message recovery
```

### Message Authentication

All published messages include Ed25519 signatures:

```rust
// Messages are signed with publisher's keypair
node.publish("topic", data).await?;

// Signatures verified on receipt (invalid messages rejected)
let msg = rx.recv().await?;  // msg.from is verified sender
```

### Rate Limiting

| Limit | Value |
|-------|-------|
| Publish rate | 100/sec |
| Per-peer receive rate | 50/sec |
| Max message size | 64 KB |
| Max topics | 10,000 |
| Max peers per topic | 1,000 |

## HyParView (Membership)

Hybrid Partial View membership protocol:

- **Active view** (5 peers) — Fully connected TCP/QUIC links
- **Passive view** (100 peers) — Known but not connected
- **Shuffle protocol** — Periodic peer exchange
- **Failure detection** — Automatic promotion from passive view

```
┌─────────────────┐     ┌─────────────────┐
│   Active View   │────▶│  Passive View   │
│   (connected)   │◀────│   (standby)     │
└─────────────────┘     └─────────────────┘
        │                       │
        └───────Shuffle─────────┘
```

## Security

### Defense Layers

| Layer | Protection |
|-------|------------|
| **Identity** | Ed25519 keypairs, identity = public key |
| **Transport** | Mutual TLS on all QUIC connections |
| **RPC** | Identity verification on every request |
| **Storage** | Per-peer quotas, rate limiting, content validation |
| **Routing** | Rate-limited insertions, ping verification |
| **PubSub** | Message signatures, replay protection |

### Security Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_VALUE_SIZE` | 1 MB | DHT value limit |
| `MAX_RESPONSE_SIZE` | 1 MB | RPC response limit |
| `MAX_SESSIONS` | 10,000 | Relay session limit |
| `MAX_SESSIONS_PER_IP` | 50 | Per-IP relay rate limit |
| `PER_PEER_STORAGE_QUOTA` | 1 MB | DHT storage per peer |
| `PER_PEER_ENTRY_LIMIT` | 100 | DHT entries per peer |
| `MAX_CONCURRENT_STREAMS` | 64 | QUIC streams per connection |

## CLI Usage

### Running a Node

```bash
# Start a node on a random port
cargo run

# Start with specific bind address
cargo run -- --bind 0.0.0.0:4433

# Bootstrap from existing peer
cargo run -- --bootstrap 192.168.1.100:4433/abc123...def456

# With debug logging
RUST_LOG=debug cargo run
```

### Chatroom Example

```bash
# Terminal 1: Start first node
cargo run --example chatroom -- --name Alice --room dev

# Terminal 2: Join with bootstrap (copy the bootstrap string from Terminal 1)
cargo run --example chatroom -- --name Bob --room dev --bootstrap <bootstrap_string>
```

The chatroom demonstrates:
- PubSub messaging (`/room` messages)
- Direct messaging (`/dm <identity> <message>`)
- Peer discovery (`/peers`)

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

# Run relay tests
cargo test --test relay_infrastructure

# Spawn local cluster (7 nodes)
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
| `rcgen` | X.509 certificate generation |
| `x509-parser` | Certificate parsing |

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
