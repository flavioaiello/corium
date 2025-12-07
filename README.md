# Corium

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/corium.svg)](https://crates.io/crates/corium)
[![Documentation](https://docs.rs/corium/badge.svg)](https://docs.rs/corium)

**Mesh networking library with automatic NAT traversal.**

Connect to peers with a single method call—Corium handles NAT detection, hole punching, and relay fallback automatically. No need to manage QUIC connections directly.

```rust
// Connect to any peer—works behind any NAT!
let conn = network.smart_connect(&peer_record).await?;
```

---

## Why Corium?

| Challenge | Corium Solution |
|-----------|-----------------|
| "Peer is behind CGNAT" | Automatic relay fallback with E2E encryption |
| "Which transport to use?" | `smart_connect` abstracts QUIC/relay/hole-punch |
| "How to find peers?" | Built-in Kademlia DHT with signed endpoint records |
| "NAT type varies" | Runtime detection, strategy per-connection |
| "Connection drops" | QUIC migration, path probing, auto-upgrade |

---

## Quick Start

### 1. Create a Node

```rust
use corium::{Node, Keypair};

// Generate identity
let keypair = Keypair::generate();

// Start the node (binds to random port)
let node = Node::bind("0.0.0.0:0", keypair).await?;

println!("Node listening on {}", node.local_addr()?);
println!("Identity: {}", hex::encode(node.identity().as_bytes()));
```

### 2. Store and Retrieve Data

```rust
// Store data (content-addressed)
let key = node.put(b"hello world".to_vec()).await?;

// Retrieve data
if let Some(data) = node.get(&key).await? {
    println!("Retrieved: {:?}", data);
}
```

### 3. Connect to Peers

```rust
use corium::SmartConnection;

// Resolve peer's endpoint record from DHT
let peer_record = node.resolve_peer(&peer_identity).await?.unwrap();

// Connect—NAT traversal is automatic!
let conn = node.connect(&peer_record).await?;

// Check connection type
match &conn {
    SmartConnection::Direct(c) => println!("Direct to {}", c.remote_address()),
    SmartConnection::Relayed { .. } => println!("Via relay (E2E encrypted)"),
    _ => {}
}
```

**That's it.** You don't need to:
- Detect NAT type manually
- Handle QUIC connection errors
- Implement relay logic
- Manage hole punching

### 4. PubSub Messaging

```rust
use corium::{Node, Keypair};

let keypair = Keypair::generate();
let node = Node::bind_with_pubsub("0.0.0.0:0", keypair).await?;

// Subscribe to a topic
node.subscribe("my-topic").await?;

// Receive messages
let mut rx = node.take_message_receiver().await?;
tokio::spawn(async move {
    while let Some(msg) = rx.recv().await {
        println!("[{}] {}", msg.topic, String::from_utf8_lossy(&msg.data));
    }
});

// Publish messages
node.publish("my-topic", b"Hello everyone!".to_vec()).await?;
```

---

## Common Use Cases

### Chat / Messaging
```rust
// 1. Each user publishes their endpoint
node.publish_address(vec![my_addr.to_string()]).await?;

// 2. To message someone, resolve their identity and connect
let peer_record = node.resolve_peer(&recipient).await?.unwrap();
let conn = node.connect(&peer_record).await?;

// 3. Send message over the connection
let (mut send, _) = conn.connection().open_bi().await?;
send.write_all(message_bytes).await?;
```

### File Sync / P2P Storage
```rust
// Store content-addressed data in the DHT
let key = node.put(file_bytes).await?;

// Retrieve from any peer that has it
if let Some(data) = node.get(&key).await? {
    // data retrieved
}
```

---

## How NAT Traversal Works

You don't need to understand this—`node.connect()` handles it. But if you're curious:

```
┌─────────────────────────────────────────────────────────────┐
│  Your Code: network.smart_connect(&peer_record)             │
├─────────────────────────────────────────────────────────────┤
│  1. Try Direct Connection (UDP/QUIC)                        │
│     ├─ Success? → Return SmartConnection::Direct            │
│     └─ Failed/Timeout? → Continue to step 2                 │
├─────────────────────────────────────────────────────────────┤
│  2. Check NAT Type                                          │
│     ├─ Symmetric (CGNAT)? → Skip hole punch, go to relay    │
│     └─ Cone NAT? → Try hole punch coordination              │
├─────────────────────────────────────────────────────────────┤
│  3. Relay Fallback                                          │
│     ├─ Connect to relay node (outbound, traverses NAT)      │
│     ├─ Peer connects to same relay                          │
│     └─ Return SmartConnection::Relayed (E2E encrypted)      │
├─────────────────────────────────────────────────────────────┤
│  4. Background Upgrade                                      │
│     └─ Periodically probe for direct path, migrate if found │
└─────────────────────────────────────────────────────────────┘
```

### NAT Types Handled

| NAT Type | What Happens |
|----------|--------------|
| None (public IP) | Direct connection |
| Full Cone | Direct connection |
| Restricted Cone | Direct with hole punch |
| Port Restricted | Direct with hole punch |
| Symmetric (CGNAT) | Automatic relay |

---

## Features

### Mesh Networking
- **QUIC transport** via quinn with Ed25519 TLS certificates
- **Connection management** with parallel path probing and automatic path selection
- **Smart connections** that seamlessly switch between direct and relayed paths
- **QUIC connection migration** for seamless path switching without reconnection (saves 1-2 RTTs)

### Publish/Subscribe (GossipSub)
- **Topic-based messaging** with mesh-structured networks
- **Epidemic broadcast** achieving O(log n) hop delivery
- **Deduplication** via LRU message cache with configurable TTL
- **Mesh maintenance** with automatic graft/prune for optimal connectivity
- **Lazy push gossip** via IHave/IWant for reliable delivery

### NAT Traversal
- **ICE-lite implementation** with candidate gathering and connectivity checks
- **STUN-like address discovery** via `WhatIsMyAddr` protocol
- **TURN-style relay** with session management for symmetric NAT/CGNAT
- **Hole punching coordination** with synchronized connection attempts
- **NAT type detection** (None, FullCone, RestrictedCone, PortRestrictedCone, Symmetric)

### Peer Discovery (Kademlia DHT)
- **Kademlia-style routing** with 256 buckets and XOR distance metric
- **Adaptive k parameter** (10-30) that adjusts based on network churn
- **Adaptive α parameter** (2-5) that adjusts based on lookup success rate
- **Parallel lookups** querying α nodes concurrently per round
- **Endpoint record publishing** for address resolution via DHT

### Identity & Security (Zero-Hash Architecture)
- **Ed25519 identity** where Identity = public key directly (no hashing)
- **Sybil protection** via Identity-to-TLS certificate binding
- **Signed endpoint records** for verifiable address announcements
- **Storage exhaustion protection** with quotas and rate limiting

### Performance & Reliability
- **Latency-based tiering** using k-means clustering for prioritization
- **Backpressure controls** with O(1) LRU eviction and pressure monitoring
- **TTL expiration** with 24-hour data lifetime (per Kademlia spec)
- **Content-addressed storage** using BLAKE3 hashing
- **Telemetry snapshots** for monitoring and debugging

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
corium = "0.2"
```

---

## Architecture

Corium is organized as a layered networking stack. **Most applications only interact with the Node facade**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│    ← YOUR CODE: node.connect(), node.put(), node.publish()  │
├─────────────────────────────────────────────────────────────┤
│                       Node Facade                           │
│    ← Node (primary API with DHT + PubSub)                   │
├─────────────────────────────────────────────────────────────┤
│                   Connection Layer (automatic)              │
│       SmartConnection, SmartSock (seamless path switching)  │
├─────────────────────────────────────────────────────────────┤
│                   NAT Traversal Layer (automatic)           │
│        Path Probing, Relay Tunnels, Direct UDP              │
├─────────────────────────────────────────────────────────────┤
│                    Transport Layer (automatic)              │
│                  QUIC (quinn), Ed25519 TLS                  │
├─────────────────────────────────────────────────────────────┤
│                    Identity Layer                           │
│    ← Keypair, Identity, EndpointRecord (tests feature)      │
└─────────────────────────────────────────────────────────────┘
```

**Layers marked "automatic" are handled by `node.connect()`**—you don't interact with them directly.

### Public API

The public API is deliberately minimal:

```rust
// Just 3 types in the public API
pub use node::{Node, Message};  // The mesh node and pubsub messages
pub use quinn::Connection;      // QUIC connection to a peer
```

### Internal Access (Tests Feature)

For testing or advanced use cases, enable the `tests` feature:

```toml
[dependencies]
corium = { version = "0.2", features = ["tests"] }
```

Then access internal types:

```rust
use corium::tests::{
    // Identity
    Keypair, Identity, EndpointRecord, verify_identity,
    
    // DHT
    DhtNode, DhtNetwork, Contact, Key, hash_content,
    
    // Network
    PeerNetwork, SmartConnection, UdpRelayForwarder,
    
    // PubSub
    GossipSub, GossipConfig, PubSubMessage,
    
    // TLS utilities
    generate_ed25519_cert, create_client_config, create_server_config,
};
```

---

## Ed25519 Identity (Zero-Hash Architecture)

Corium uses a **zero-hash architecture** where Identity = Ed25519 public key directly:

```rust
// Using the tests feature for internal access
use corium::tests::{Keypair, Identity, verify_identity};

// Generate a new keypair
let keypair = Keypair::generate();

// The Identity IS the public key (no hashing)
let identity = keypair.identity();
let public_key = keypair.public_key_bytes();

// Zero-hash property: Identity bytes == public key bytes
assert_eq!(identity.as_bytes(), &public_key);

// Keypairs can be restored from the secret key
let secret = keypair.secret_key_bytes();
let restored = Keypair::from_secret_key_bytes(&secret);
assert_eq!(keypair.identity(), restored.identity());
```

### Peer Verification

Peer identity is verified automatically during TLS handshake:

```rust
use corium::tests::{verify_peer_identity, extract_public_key_from_cert, Identity};

// After receiving a peer's certificate
let cert_der: &[u8] = /* from TLS handshake */;
let claimed_identity: Identity = /* from Contact */;

// Verify the peer owns their claimed Identity
if verify_peer_identity(cert_der, &claimed_identity) {
    // Peer verified - their certificate's public key matches claimed Identity
}
```

---

## Core Concepts

### Identity and Key (Zero-Hash Architecture)

The DHT uses 256-bit identifiers:

```rust
type Identity = [u8; 32];  // Node identifier = Ed25519 public key (no hash)
type Key = [u8; 32];       // Content key = BLAKE3 hash of value
```

Unlike traditional Kademlia implementations, Corium uses the Ed25519 public key
directly as the node Identity—no intermediate hashing step. This simplifies
identity verification and eliminates hash collision concerns.

### Routing Table

Kademlia-style routing with:
- **256 buckets** for 256-bit XOR distance space
- **Adaptive k** (10-30 contacts per bucket) based on churn rate
- **LRU-like eviction** preferring long-lived nodes
- **Ping-before-evict** rule for bucket maintenance

### Latency Tiering

Contacts are dynamically assigned to latency tiers:
- **K-means clustering** on RTT samples (1-7 tiers, dynamically determined)
- **Periodic recomputation** every 5 minutes
- **Tier-aware lookups** prioritizing fast peers
- **Spill offloading** to slower tiers under pressure
- **Stale data cleanup** removing nodes not seen in 24 hours

### Backpressure & Storage

- **LRU cache** with O(1) operations (get, put, eviction)
- **TTL expiration** - entries expire after 24 hours (per Kademlia spec)
- **Pressure monitoring** based on memory, disk, and request rate
- **Automatic eviction** when pressure exceeds threshold (0.75)
- **Content verification** using BLAKE3 hash

### Adaptive Parameters

| Parameter | Range | Adaptation |
|-----------|-------|------------|
| k (bucket size) | 10-30 | Increases with churn rate |
| α (parallelism) | 2-5 | Adjusts based on lookup success |

---

## Configuration Constants

The following constants are defined internally. Default values for `k` and `alpha` 
are configured automatically based on network conditions.

### DHT Core Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MIN_LATENCY_TIERS` | 1 | Minimum number of latency tiers |
| `MAX_LATENCY_TIERS` | 7 | Maximum number of latency tiers |
| `TIERING_RECOMPUTE_INTERVAL` | 5m | Tier recomputation frequency |
| `TIERING_STALE_THRESHOLD` | 24h | When to remove stale tiering data |
| `PRESSURE_THRESHOLD` | 0.75 | Eviction trigger threshold |
| `LOCAL_STORE_MAX_ENTRIES` | 100,000 | Maximum LRU cache entries |
| `DEFAULT_TTL` | 24h | Data expiration time (per Kademlia spec) |
| `EXPIRATION_CHECK_INTERVAL` | 60s | How often expired entries are cleaned up |
| `MAX_VALUE_SIZE` | 64 KB | Maximum size per stored value |
| `PER_PEER_STORAGE_QUOTA` | 1 MB | Maximum storage per remote peer |
| `PER_PEER_ENTRY_LIMIT` | 100 | Maximum entries per remote peer |
| `PER_PEER_RATE_LIMIT` | 20/min | Maximum store requests per peer per minute |

### Network Constants (Public)

| Constant | Value | Description |
|----------|-------|-------------|
| `ALPN` | `b"corium"` | ALPN protocol identifier |
| `PATH_PROBE_INTERVAL` | 5s | How often to probe paths |
| `PATH_STALE_TIMEOUT` | 30s | When a path is considered stale |
| `PROBE_TIMEOUT` | 3s | Individual probe timeout |
| `UPGRADE_PROBE_INTERVAL` | 30s | Relay→direct upgrade attempts |
| `DIRECT_CONNECT_TIMEOUT` | 5s | Direct connection timeout |
| `STUN_TIMEOUT` | 3s | STUN binding request timeout |

### Relay Constants (Public)

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_RELAY_SESSIONS` | 100 | Max concurrent relay sessions |
| `RELAY_SESSION_TIMEOUT` | 5m | Idle session expiration |
| `ICE_CHECK_INTERVAL` | 50ms | ICE connectivity check interval |
| `ICE_KEEPALIVE_INTERVAL` | 15s | ICE keepalive interval |
| `TURN_ALLOCATION_LIFETIME` | 10m | TURN allocation lifetime |

### PubSub Constants (Public)

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_MESH_DEGREE` | 6 | Target peers per topic |
| `DEFAULT_GOSSIP_INTERVAL` | 1s | IHave gossip interval |
| `DEFAULT_HEARTBEAT_INTERVAL` | 1s | Mesh maintenance interval |

---

## Network Protocol

### ALPN

```rust
pub const ALPN: &[u8] = b"corium";
```

### RPC Messages

**DHT Operations:**

| Request | Response | Description |
|---------|----------|-------------|
| `FindNode` | `Nodes` | Find k closest nodes to target |
| `FindValue` | `Value` | Get value or closer nodes |
| `Store` | `Ack` | Store key-value pair |
| `Ping` | `Ack` | Check node responsiveness |

**NAT Traversal:**

| Request | Response | Description |
|---------|----------|-------------|
| `WhatIsMyAddr` | `YourAddr` | STUN-like address discovery |
| `RelayConnect` | `RelayAccepted/Connected/Rejected` | Establish relay session |
| `RelayForward` | `RelayForwarded` | Forward encrypted packet |
| `RelayClose` | `RelayClosed` | Close relay session |
| `HolePunchRegister` | `HolePunchWaiting/Ready` | Coordinate hole punch |
| `HolePunchStart` | `HolePunchReady/Failed` | Trigger hole punch |

**Publish/Subscribe (GossipSub):**

| Message Type | Description |
|--------------|-------------|
| `Subscribe` | Join a topic mesh |
| `Unsubscribe` | Leave a topic mesh |
| `Graft` | Request to join peer's mesh for a topic |
| `Prune` | Leave peer's mesh, optionally suggest alternatives |
| `Publish` | Broadcast message to topic |
| `IHave` | Gossip: announce available messages |
| `IWant` | Request specific messages by ID |

---

## NAT Traversal

Corium implements comprehensive NAT traversal using ICE-like techniques with QUIC-native transport:

### How It Works

```
┌──────────┐                    ┌──────────┐
│  Peer A  │                    │  Peer B  │
│ (NAT'd)  │                    │ (NAT'd)  │
└────┬─────┘                    └────┬─────┘
     │                               │
     │ 1. WhatIsMyAddr (STUN-like)   │
     ├──────────────────────────────►│
     │◄──────────────────────────────┤
     │   YourAddr: 203.0.113.5:4433  │
     │                               │
     │ 2. Publish EndpointRecord     │
     ├───────────► DHT ◄─────────────┤
     │                               │
     │ 3. Resolve peer addresses     │
     ├───────────► DHT ◄─────────────┤
     │                               │
     │ 4. Parallel path probing      │
     │◄─────── PathProbe ───────────►│
     │◄─────── PathReply ───────────►│
     │                               │
     │ 5a. Direct connection (if NAT allows)
     │◄═════════════════════════════►│
     │   OR                          │
     │ 5b. Relay through TURN node   │
     │◄────► Relay ◄────────────────►│
     │                               │
     │ 6. Upgrade: relay → direct    │
     │   (when NAT conditions allow) │
└────┴───────────────────────────────┴────┘
```

### Connection Strategy

1. **Direct first**: Always attempt direct UDP connection with timeout (5s)
2. **NAT detection**: Query multiple STUN-like endpoints to classify NAT type
3. **Relay fallback**: When blocked by symmetric NAT/CGNAT, connect via relay
4. **Parallel probing**: Continuously probe all paths to find the best route
5. **Path selection**: Prefer direct over relay unless relay is >50ms faster
6. **QUIC migration**: Seamlessly switch paths without reconnecting (saves 1-2 RTTs)

### Dynamic Relay Selection

When relay is needed, Corium dynamically selects the best relay node using a scoring algorithm that combines:

| Factor | Weight | Description |
|--------|--------|-------------|
| RTT latency | High | Measured round-trip time to relay (default: 200ms if unknown) |
| Load | Medium | Relay's current session load (0-100ms penalty) |
| Tier level | Low | DHT tiering level (20ms penalty per tier) |

```rust
use corium::{RelayClient, RelayInfo, Identity};

// Relay selection score (lower is better)
// score = rtt_ms + (load * 100) + (tier * 20)

let client = RelayClient::new();

// Update known relays - automatically sorted by score
client.update_relays(discovered_relays).await;

// Update relay metrics from DHT tiering system
client.update_relay_rtt(&relay_identity, rtt_ms, tier_level).await;

// Get best relays for connection (sorted by score)
let best_relays = client.get_relays(3).await;
if let Some(best) = best_relays.first() {
    println!("Best relay: {} (score: {:.1})", 
        best.relay_addrs[0], 
        best.selection_score());
}

// Get only relays with measured latency
let measured = client.get_measured_relays(3).await;
```

Relay nodes publish their capabilities to the DHT:

```rust
pub struct RelayInfo {
    pub relay_peer: Identity,      // Relay's peer ID
    pub relay_addrs: Vec<String>,  // Relay addresses
    pub load: f32,                 // Current load (0.0-1.0)
    pub accepting: bool,           // Accepting new sessions?
    pub rtt_ms: Option<f32>,       // Observed RTT (from tiering)
    pub tier: Option<u8>,          // Tiering level (0 = fastest)
    pub capabilities: RelayCapabilities,
}

pub struct RelayCapabilities {
    pub stun: bool,              // Supports STUN binding
    pub turn: bool,              // Supports TURN relay
    pub ice_lite: bool,          // Supports ICE-lite
    pub max_bandwidth_kbps: u32, // Bandwidth limit (0 = unlimited)
    pub region: Option<String>,  // Geographic region hint
}
```

### NAT Types

| NAT Type | Description | Hole Punch |
|----------|-------------|------------|
| `None` | Public IP, no NAT | ✓ Direct |
| `FullCone` | Any external host can reach mapped address | ✓ Works |
| `RestrictedCone` | Only hosts we've sent to can reply | ✓ Works |
| `PortRestrictedCone` | Only (host, port) we've sent to can reply | ✓ Works |
| `Symmetric` | Different mapping per destination (CGNAT) | ✗ Needs relay |

### Smart Connections

```rust
use corium::SmartConnection;

// Automatically chooses direct or relay based on NAT
let connection = network.smart_connect(&endpoint_record).await?;

match &connection {
    SmartConnection::Direct(conn) => {
        println!("Direct connection to {}", conn.remote_address());
    }
    SmartConnection::Relayed { session_id, direct_addrs, .. } => {
        println!("Relayed connection, session: {:?}", hex::encode(session_id));
        println!("Will probe {} direct addresses for upgrade", direct_addrs.len());
    }
    SmartConnection::RelayPending { .. } => {
        println!("Waiting for peer to connect to relay");
    }
}

// Check connection state
if connection.is_direct() {
    println!("Using direct path");
} else if connection.can_attempt_upgrade() {
    println!("Can attempt upgrade to direct");
}
```

### Automatic Path Switching (SmartSock)

Corium uses **SmartSock** to provide seamless relay↔direct path switching without reconnection.
Path probing happens automatically in the background:

- **Probe interval**: Every 5 seconds
- **RTT smoothing**: Exponential moving average (0.8 old + 0.2 new)
- **Path selection**: Direct preferred unless relay is 50ms+ faster
- **Failure detection**: 3 consecutive probe failures marks path dead

```rust
// SmartSock is integrated into the Node automatically
let node = Node::bind("0.0.0.0:0", keypair).await?;

// Path probing starts automatically when you connect to a peer
let conn = node.connect(&peer_record).await?;

// Access SmartSock for advanced path management
let smartsock = node.smartsock();

// Register additional direct addresses for a peer
smartsock.add_direct_candidate(&peer_identity, new_addr).await;

// Check if using relay or direct
// (SmartSock switches transparently - you don't need to check)
```

---

## Publish/Subscribe (GossipSub)

Corium includes a GossipSub-style publish/subscribe system for topic-based message distribution. Messages propagate through the network via epidemic broadcast, achieving O(log n) hop delivery with high reliability.

### How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                     Application                             │
│              subscribe(), publish(), on_message()           │
├─────────────────────────────────────────────────────────────┤
│                      GossipSub                              │
│         Topic meshes, message routing, deduplication        │
├─────────────────────────────────────────────────────────────┤
│                        Node                                 │
│              Peer discovery, DHT, connections               │
└─────────────────────────────────────────────────────────────┘
```

### Concepts

| Concept | Description |
|---------|-------------|
| **Topic** | A named channel for messages (e.g., `"chat/lobby"`, `"sensors/temp"`) |
| **Mesh** | Per-topic connection to `mesh_degree` peers (default: 6) for full message push |
| **Fanout** | Cached peers for topics we publish to but aren't subscribed to |
| **Gossip** | Periodic IHave/IWant exchanges to repair mesh gaps |

### Usage

```rust
use std::sync::Arc;
use corium::pubsub::{GossipSub, GossipConfig};
use corium::identity::Keypair;

// Create pubsub layer on top of discovery node
let keypair = Keypair::generate();
let config = GossipConfig::default();
let mut pubsub = GossipSub::new(dht.clone(), keypair, config);

// Take the message receiver for incoming messages
let mut receiver = pubsub.take_message_receiver().unwrap();

// Wrap in Arc for shared access
let pubsub = Arc::new(pubsub);

// Spawn heartbeat task for mesh maintenance
let pubsub_heartbeat = pubsub.clone();
tokio::spawn(async move {
    pubsub_heartbeat.run_heartbeat().await;
});

// Subscribe to a topic
pubsub.subscribe("chat/lobby").await?;

// Publish a message (automatically signed by keypair)
let msg_id = pubsub.publish("chat/lobby", b"Hello, world!".to_vec()).await?;

// Handle incoming messages (signatures verified automatically)
while let Some(msg) = receiver.recv().await {
    println!("[{}] {}: {:?}", msg.topic, msg.source, msg.data);
}
```

### Configuration

```rust
pub struct GossipConfig {
    pub mesh_degree: usize,         // Target peers per topic (default: 6)
    pub mesh_degree_low: usize,     // Min before seeking more (default: 4)
    pub mesh_degree_high: usize,    // Max before pruning (default: 12)
    pub message_cache_size: usize,  // Dedup cache size (default: 10,000)
    pub message_cache_ttl: Duration, // Cache TTL (default: 2 min)
    pub gossip_interval: Duration,  // IHave interval (default: 1s)
    pub heartbeat_interval: Duration, // Mesh maintenance (default: 1s)
    pub fanout_ttl: Duration,       // Fanout cache TTL (default: 60s)
    pub max_ihave_length: usize,    // Max IHave messages per gossip (default: 100)
    pub max_message_size: usize,    // Max message payload (default: 64KB)
    pub publish_rate_limit: usize,  // Local publish rate limit (msg/s)
    pub forward_rate_limit: usize,  // Forward rate limit (msg/s)
    pub per_peer_rate_limit: usize, // Per-peer rate limit (msg/s)
}
```

### Message Flow

1. **Publish**: Message sent to all mesh peers (full push)
2. **Forward**: Each peer forwards to their mesh peers (except sender)
3. **Deduplicate**: Message ID cache prevents redundant delivery
4. **Gossip**: Periodically exchange IHave to discover missed messages
5. **Repair**: IWant requests fill gaps in message delivery

---

## Telemetry

```rust
#[derive(Clone, Debug, Default)]
pub struct TelemetrySnapshot {
    pub tier_centroids: Vec<f32>,    // Latency tier centers (ms)
    pub tier_counts: Vec<usize>,     // Nodes per tier
    pub pressure: f32,               // Current pressure (0.0-1.0)
    pub stored_keys: usize,          // Keys in local storage
    pub replication_factor: usize,   // Current k
    pub concurrency: usize,          // Current alpha
}

// Get a snapshot
let snapshot = dht.telemetry_snapshot().await;
```

---

## Examples

### Basic Node

The included binary demonstrates a complete mesh node:

```bash
# Show help and all available options
cargo run -- --help

# Run with default settings (random port)
cargo run

# Bind to a specific port
cargo run -- --bind 0.0.0.0:9000

# Connect to bootstrap peer (Identity is required for TLS identity verification)
cargo run -- -B 192.168.1.100:9000/5821a288e16c6491ae72f4cf060b8d6523cd416c418c1ec3b8b5bc7608a55b7d

# Multiple bootstrap peers
cargo run -- -B 192.168.1.100:9000/5821a288... -B 192.168.1.101:9000/6932b399...

# Custom DHT parameters
cargo run -- --k 25 --alpha 5

# With debug logging
RUST_LOG=debug cargo run

# With trace logging (very verbose)
RUST_LOG=trace cargo run

# Filter to specific modules
RUST_LOG=corium=debug cargo run
```

**CLI Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-b, --bind` | `0.0.0.0:0` | Address to bind to |
| `-B, --bootstrap` | - | Bootstrap peer in `IP:PORT/IDENTITY` format (can be repeated) |
| `-k` | 20 | Bucket size / replication factor |
| `-a, --alpha` | 3 | Lookup parallelism |
| `-t, --telemetry-interval` | 300 | Telemetry logging interval (seconds) |

This starts a node with:
- Ed25519 keypair for cryptographic identity
- Self-signed TLS certificate for QUIC
- Periodic telemetry logging (every 5 minutes by default)
- Structured logging via `tracing`

Example output:
```
2024-12-02T10:00:00Z  INFO corium: DHT node started
2024-12-02T10:00:00Z  INFO corium: Identity identity="a1b2c3d4..."
2024-12-02T10:00:00Z  INFO corium: Listening address addr="0.0.0.0:54321"
2024-12-02T10:05:00Z  INFO corium: telemetry snapshot pressure="0.00" stored_keys=0 k=20 alpha=3
```

### Chatroom Example

A simple chatroom demonstrating mesh networking:

```bash
# Start first node
cargo run --example chatroom -- --name alice --room lobby --port 4433

# Connect another node (in a different terminal)
cargo run --example chatroom -- --name bob --room lobby --peer 127.0.0.1:4433
```

The chatroom example shows:
- Peer discovery via DHT
- Direct message routing
- Room-based message filtering
- JSON message serialization over QUIC streams

### Address Publishing & Resolution

```rust
use corium::Node;
use corium::tests::Identity;  // requires `tests` feature

// Create node (keypair auto-generated or use bind_with_keypair)
let node = Node::bind("0.0.0.0:0").await?;

// Publish our address to the DHT
let addresses = vec!["192.168.1.100:4433".to_string()];
node.publish_address(addresses).await?;

// Resolve a peer's addresses from the DHT
let peer_identity = Identity::from_hex("5821a288e16c6491...")?;
if let Some(record) = node.resolve_peer(&peer_identity).await? {
    println!("Peer addresses: {:?}", record.addrs);
    println!("Relay endpoints: {:?}", record.relays);
}
```

---

## Security

Corium implements comprehensive, defense-in-depth security measures across all subsystems. Security fixes are documented in the source code.

### Sybil Protection (Zero-Hash Architecture)

Corium prevents Sybil attacks by cryptographically binding each peer's Identity to their TLS certificate:

1. **Identity binding**: `Identity = Ed25519_public_key` (zero-hash: no intermediate derivation)
2. **Certificate embedding**: The Ed25519 public key is embedded in the TLS certificate's SPKI
3. **SNI pinning**: TLS SNI hostname = `hex(Identity)` = `hex(PublicKey)`
4. **Connection verification**: On each incoming connection, the server extracts the public key from the peer's certificate and compares directly to the claimed Identity
5. **Request validation**: Every RPC request's `from` Contact must match the verified Identity from the TLS handshake

This prevents attackers from claiming arbitrary Identities—they can only use Identities matching keys they control. The zero-hash property eliminates hash collision concerns entirely.

### Protocol Security

All network I/O uses bounded deserialization to prevent memory exhaustion attacks:

| Protection | Limit | Description |
|------------|-------|-------------|
| Request size | 64 KB | `MAX_DESERIALIZE_SIZE` bounds request deserialization |
| Response size | 1 MB | Larger limit for FIND_VALUE responses with data |
| Contacts per response | 100 | `MAX_CONTACTS_PER_RESPONSE` prevents routing pollution |
| Value size | 1 MB | `MAX_VALUE_SIZE` limits stored values |
| Read timeout | 5s | `REQUEST_READ_TIMEOUT` mitigates slowloris attacks |

```rust
// Bounded deserialization prevents OOM from malicious length prefixes
pub fn deserialize_request(bytes: &[u8]) -> Result<DhtRequest, bincode::Error> {
    bincode::DefaultOptions::new()
        .with_limit(MAX_DESERIALIZE_SIZE)  // 64 KB
        .deserialize(bytes)
}
```

### Connection Rate Limiting

Multi-layer rate limiting prevents DoS attacks at the connection level:

| Limit | Value | Description |
|-------|-------|-------------|
| Global connections/sec | 100 | `MAX_GLOBAL_CONNECTIONS_PER_SECOND` |
| Per-IP connections/sec | 20 | `MAX_CONNECTIONS_PER_IP_PER_SECOND` |
| Tracked IPs | 1000 | LRU cache bounds memory for IP tracking |

```rust
// Rate limiter rejects excessive connection attempts
if !rate_limiter.allow(remote_addr.ip()).await {
    warn!(remote = %remote_addr, "rate limiting: rejecting connection");
    continue;
}
```

### Connection Health & Liveness

Proactive detection of stale/dead connections:

| Feature | Value | Description |
|---------|-------|-------------|
| Health check interval | 30s | Periodic liveness probes |
| Probe timeout | 2s | `CONNECTION_PROBE_TIMEOUT` |
| Stale threshold | 5 min | Connections without activity |
| Max failures | 3 | `MAX_CONSECUTIVE_FAILURES` before marking unhealthy |
| RTT tracking | 10 samples | Ring buffer for latency monitoring |

### NAT Traversal Security

Clock skew tolerance and bounded registrations:

| Protection | Value | Description |
|------------|-------|-------------|
| Clock skew tolerance | 2000 ms | `HOLE_PUNCH_CLOCK_SKEW_TOLERANCE_MS` handles NTP drift |
| Max pending punches | 5000 | `MAX_PENDING_HOLE_PUNCHES` prevents memory exhaustion |
| Per-identity limit | 5 | `MAX_HOLE_PUNCH_PER_IDENTITY` prevents single-peer abuse |
| Ready results limit | 1000 | `MAX_READY_HOLE_PUNCHES` bounds ready queue |

### PubSub Message Authentication

All GossipSub messages are cryptographically signed to prevent spoofing and forgery:

1. **Signature creation**: Publishers sign `topic || seqno || data` with their Ed25519 private key
2. **Signature verification**: Every node verifies the signature before accepting or forwarding messages
3. **Identity binding**: The `source` field in each message is authenticated by the signature

| Attack | Protection |
|--------|------------|
| Identity spoofing | Cannot claim to be someone else without their private key |
| Message forgery | Cannot create messages on behalf of other identities |
| Seqno manipulation | Cannot inject fake sequence numbers to poison dedup caches |
| Topic substitution | Cannot move messages between topics |

### PubSub Resource Limits

Comprehensive bounds prevent memory/CPU exhaustion:

| Limit | Value | Description |
|-------|-------|-------------|
| Max topics | 10,000 | `MAX_TOPICS` prevents topic explosion |
| Peers per topic | 1,000 | `MAX_PEERS_PER_TOPIC` bounds per-topic tracking |
| Subscriptions per peer | 100 | `MAX_SUBSCRIPTIONS_PER_PEER` |
| Outbound per peer | 100 | `MAX_OUTBOUND_PER_PEER` messages queued |
| Total outbound | 50,000 | `MAX_TOTAL_OUTBOUND_MESSAGES` global limit |
| IWant messages | 10 | `DEFAULT_MAX_IWANT_MESSAGES` limits amplification |
| IWant response | 256 KB | `MAX_IWANT_RESPONSE_BYTES` caps data sent |
| IWant rate | 5/s | `DEFAULT_IWANT_RATE_LIMIT` per peer |
| Rate limit entries | 10,000 | `MAX_RATE_LIMIT_ENTRIES` with LRU eviction |

**Topic Validation**: Topic names must be printable ASCII only, preventing injection attacks.

**Rate Limiting**: Three-tier rate limits protect against flooding:
- `DEFAULT_PUBLISH_RATE_LIMIT`: 100 msg/s for local publishes
- `DEFAULT_FORWARD_RATE_LIMIT`: 1000 msg/s for forwarded messages
- `DEFAULT_PER_PEER_RATE_LIMIT`: 50 msg/s per peer

### Relay Security

Bounded resource allocation prevents relay exhaustion:

| Limit | Value | Description |
|-------|-------|-------------|
| Relay sessions | 100 | `MAX_RELAY_SESSIONS` per node |
| Forwarder tasks | 200 | `MAX_FORWARDER_TASKS` prevents task explosion |
| TURN allocations | 1,000 | `MAX_TURN_ALLOCATIONS` per server |
| Permissions/allocation | 64 | `MAX_PERMISSIONS_PER_ALLOCATION` |
| Channels/allocation | 32 | `MAX_CHANNELS_PER_ALLOCATION` |
| Relay packet size | 1,500 | `MAX_RELAY_PACKET_SIZE` bytes |
| Session timeout | 5 min | `RELAY_SESSION_TIMEOUT` idle expiration |
| Allocation lifetime | 10 min | `TURN_ALLOCATION_LIFETIME` requires refresh |

### Routing Table Security

Protection against routing pollution:

| Protection | Description |
|------------|-------------|
| Placeholder rejection | Rejects zero Identity entries |
| Eviction bounds | Max 100 iterations for bucket eviction |
| Tiering tracked peers | 10,000 max (`MAX_TIERING_TRACKED_PEERS`) |

### Storage Exhaustion Protection

The DHT implements multiple layers of protection against storage exhaustion attacks:

| Protection | Limit | Description |
|------------|-------|-------------|
| Value size | 64 KB | Rejects oversized values |
| Per-peer quota | 1 MB / 100 entries | Limits total storage per peer |
| Rate limiting | 20 stores/minute | Prevents rapid-fire STORE attacks |
| Popularity-based eviction | - | Frequently accessed data survives longer |
| Pressure-based eviction | >75% pressure | Automatic eviction under resource pressure |

```rust
// Storage rejection reasons
pub enum StoreRejection {
    ValueTooLarge,   // Value exceeds 64 KB
    QuotaExceeded,   // Peer exceeded 1 MB / 100 entries
    RateLimited,     // Peer sending >20 stores/minute
}
```

### Error Handling Hardening

Graceful degradation instead of panics:

- `unwrap_or_default()` patterns prevent panics on missing data
- `total_cmp()` for NaN-safe floating point comparisons
- Fallback to timestamp-based randomness if `getrandom` fails

### Security Test Coverage

Dedicated test suites verify security properties:

```bash
cargo test --test security          # Core cryptographic security
cargo test --test security_pubsub   # PubSub security tests
cargo test --test security_relay    # Relay/ICE security tests
cargo test --test security_gaps     # Clock skew, rate limiting, Sybil tests
cargo test --test formal_verification  # Formal property tests
```

---

## Testing

The test suite includes comprehensive coverage for DHT, security, and networking:

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test suites
cargo test --test integration          # Integration tests
cargo test --test routing_table        # Routing table tests
cargo test --test security             # Core security tests
cargo test --test security_pubsub      # PubSub security tests
cargo test --test security_relay       # Relay/ICE security tests
cargo test --test security_gaps        # Security hardening tests
cargo test --test formal_verification  # Formal property tests
cargo test --test data_distribution    # DHT data distribution tests
cargo test --test iterative_find_node_scale  # Scalability tests

# Run with specific log level
RUST_LOG=debug cargo test

# Run benchmarks (if available)
cargo bench
```

### Test Categories

| Test File | Focus |
|-----------|-------|
| `integration.rs` | End-to-end DHT operations |
| `routing_table.rs` | Kademlia routing table behavior |
| `security.rs` | Core security properties |
| `security_pubsub.rs` | PubSub message signing/verification |
| `security_relay.rs` | ICE/STUN/TURN security |
| `security_gaps.rs` | Edge cases and hardening |
| `formal_verification.rs` | Formal property verification |
| `data_distribution.rs` | DHT data distribution |
| `iterative_find_node_scale.rs` | Scalability testing |

---

## Dependencies

| Crate | Version | Purpose |
|-------|---------|--------|
| `quinn` | 0.11 | QUIC transport |
| `rustls` | 0.23 | TLS implementation |
| `rcgen` | 0.13 | Self-signed certificate generation |
| `ed25519-dalek` | 2.1 | Ed25519 keypair and signatures |
| `blake3` | 1.5 | BLAKE3 hashing |
| `x509-parser` | 0.16 | Certificate parsing for peer verification |
| `bincode` | 1.3 | Binary serialization for RPC |
| `serde` | 1.x | Serialization framework |
| `serde_json` | 1.x | JSON serialization |
| `tokio` | 1.x | Async runtime |
| `lru` | 0.12 | O(1) LRU cache |
| `tracing` | 0.1 | Structured logging |
| `tracing-subscriber` | 0.3 | Log output formatting |
| `async-trait` | 0.1 | Async trait support |
| `futures` | 0.3 | Async utilities |
| `getrandom` | 0.2 | Cryptographically secure random bytes |
| `clap` | 4.5 | CLI argument parsing |
| `hex` | 0.4 | Hexadecimal encoding |
| `rand` | 0.8 | Random number generation |

---

## References

Corium's design is informed by the following research:

### NAT Traversal with QUIC

- **Liang, J., Xu, W., Wang, T., Yang, Q., & Zhang, S.** (2024). *Implementing NAT Hole Punching with QUIC*. VTC2024-Fall Conference. [arXiv:2408.01791](https://arxiv.org/abs/2408.01791)
  
  This paper demonstrates that QUIC-based hole punching effectively reduces hole punching time compared to TCP, with pronounced advantages in weak network environments. It also shows that QUIC connection migration for connection restoration saves 2 RTTs compared to re-punching, which Corium leverages for seamless path switching.

### Distributed Hash Tables

- **Freedman, M. J., Freudenthal, E., & Mazières, D.** (2004). *Democratizing Content Publication with Coral*. NSDI '04. [PDF](https://www.cs.princeton.edu/~mfreed/docs/coral-nsdi04.pdf)

  Coral introduced the concept of a "sloppy" DHT (DSHT) with hierarchical clustering based on latency. Corium adopts similar ideas with its latency-based tiering system, which uses k-means clustering to organize peers by RTT and prioritize fast peers for lookups while offloading storage pressure to slower tiers.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
