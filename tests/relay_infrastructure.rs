//! Integration tests for the relay infrastructure.
//!
//! These tests validate the UDP relay server, relay session management,
//! and relay-assisted connectivity at an integration level.
//!
//! Run with verbose output: RUST_LOG=debug cargo test --test relay_infrastructure -- --nocapture

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

use corium::Node;
use tokio::time::timeout;

/// One-time tracing initialization
static INIT: Once = Once::new();

/// Initialize tracing for tests. Call at start of slow tests.
/// Use RUST_LOG=debug or RUST_LOG=trace for verbose output.
fn init_tracing() {
    INIT.call_once(|| {
        let filter = if std::env::var("RUST_LOG").is_ok() {
            tracing_subscriber::EnvFilter::from_default_env()
        } else {
            tracing_subscriber::EnvFilter::new("debug")
        };

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init()
            .ok();
    });
}

/// Progress marker that prints elapsed time
fn progress(start: Instant, msg: &str) {
    eprintln!("[{:>6.2}s] {}", start.elapsed().as_secs_f64(), msg);
}

/// Atomic port counter for unique port allocation across parallel tests.
/// Nodes use socket multiplexing, so relay shares the same port as QUIC.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(40000);

fn next_port() -> u16 {
    PORT_COUNTER.fetch_add(2, Ordering::SeqCst)
}

fn test_addr() -> String {
    format!("127.0.0.1:{}", next_port())
}

const TEST_TIMEOUT: Duration = Duration::from_secs(15);

// ============================================================================
// Relay Capability Tests
// ============================================================================

#[tokio::test]
async fn node_relay_capability_check() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Relay is mandatory for all nodes
    let relay_ep = node.relay_endpoint().await;
    assert!(relay_ep.is_some(), "relay endpoint should exist");
    
    let contact = relay_ep.unwrap();
    assert_eq!(
        hex::encode(contact.identity),
        node.identity(),
        "relay identity should match node"
    );
}

#[tokio::test]
async fn two_relay_nodes_capability() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    // Both nodes should have relay endpoints (relay is mandatory)
    let relay1 = node1.relay_endpoint().await;
    let relay2 = node2.relay_endpoint().await;
    
    assert!(relay1.is_some(), "node1 relay endpoint should exist");
    assert!(relay2.is_some(), "node2 relay endpoint should exist");
}

// ============================================================================
// Relay-Assisted Address Publishing
// ============================================================================

#[tokio::test]
async fn publish_address_with_relay_info() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    // Node2 acts as a potential relay
    let relay_identity = node2.peer_identity();
    
    // Node1 publishes its address with relay info
    let addrs = vec![
        "10.0.0.1:5000".to_string(),
        "192.168.1.1:5000".to_string(),
    ];
    
    let result = node1.publish_address_with_relays(addrs.clone(), vec![relay_identity]).await;
    assert!(result.is_ok(), "publish_address_with_relays should succeed");
    
    // Publish again to verify idempotency
    let result = node1.publish_address_with_relays(addrs, vec![relay_identity]).await;
    assert!(result.is_ok(), "second publish should also succeed");
}

#[tokio::test]
async fn publish_address_with_multiple_relays() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let relay1 = Node::bind(&test_addr()).await.expect("relay1 bind failed");
    let relay2 = Node::bind(&test_addr()).await.expect("relay2 bind failed");
    
    let relays = vec![
        relay1.peer_identity(),
        relay2.peer_identity(),
    ];
    
    let addrs = vec!["10.0.0.1:5000".to_string()];
    
    let result = node1.publish_address_with_relays(addrs, relays).await;
    assert!(result.is_ok(), "publish with multiple relays should succeed");
}

#[tokio::test]
async fn publish_address_with_empty_relays() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    let addrs = vec!["10.0.0.1:5000".to_string()];
    
    // Empty relay list should be valid (falls back to direct)
    let result = node.publish_address_with_relays(addrs, vec![]).await;
    assert!(result.is_ok(), "publish with empty relays should succeed");
}

// ============================================================================
// Relay Endpoint Discovery
// ============================================================================

#[tokio::test]
async fn relay_endpoint_address_format() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    if let Some(relay_ep) = node.relay_endpoint().await {
        // Relay address should be parseable
        let primary = relay_ep.addrs.first().expect("should have at least one addr");
        let addr: Result<SocketAddr, _> = primary.parse();
        assert!(addr.is_ok(), "relay addr should be valid socket address");
        
        // Relay port should be different from main port (typically +1)
        let main_addr = node.local_addr().unwrap();
        let relay_addr = addr.unwrap();
        
        // They should be on the same IP
        assert_eq!(main_addr.ip(), relay_addr.ip());
    }
}

#[tokio::test]
async fn relay_endpoint_contains_quic_addr() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    if let Some(relay_ep) = node.relay_endpoint().await {
        // The addrs field should contain the QUIC endpoint address
        let main_addr = node.local_addr().unwrap().to_string();
        
        // The addrs should contain the main addr
        let has_quic = relay_ep.addrs.iter().any(|a| a == &main_addr);
        
        // Just verify the struct is populated correctly
        assert!(!relay_ep.addrs.is_empty());
        assert!(has_quic, "relay endpoint should contain QUIC address");
    }
}

// ============================================================================
// Multi-Node Relay Scenarios
// ============================================================================

#[tokio::test]
async fn three_node_with_relay_bootstrap() {
    // Node1 is the bootstrap node and potential relay
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    let node3 = Node::bind(&test_addr()).await.expect("node3 bind failed");
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // Node2 bootstraps and publishes with node1 as relay
    node2.bootstrap(&node1_id, &node1_addr).await.expect("node2 bootstrap failed");
    
    let relay_id = node1.peer_identity();
    let addrs = vec![node2.local_addr().unwrap().to_string()];
    node2.publish_address_with_relays(addrs, vec![relay_id])
        .await
        .expect("node2 publish failed");
    
    // Node3 bootstraps
    node3.bootstrap(&node1_id, &node1_addr).await.expect("node3 bootstrap failed");
    
    // Allow time for DHT propagation
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Node3 should be able to find node2's peers
    let peers = node3.find_peers(node2.peer_identity()).await;
    assert!(peers.is_ok());
}

#[tokio::test]
async fn relay_telemetry_visibility() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Do some DHT operations
    let _ = node.put(b"test-data".to_vec()).await;
    
    // Check telemetry
    let telemetry = node.telemetry().await;
    
    // Telemetry should be accessible
    let _ = telemetry.stored_keys;
    let _ = telemetry.pressure;
}

// ============================================================================
// UDP Relay Server Port Binding
// ============================================================================

#[tokio::test]
async fn relay_server_port_availability() {
    // Bind a node
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Relay is mandatory - verify endpoint exists
    let relay1 = node.relay_endpoint().await;
    assert!(relay1.is_some(), "relay endpoint should exist");
    
    // Create another node
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    let relay2 = node2.relay_endpoint().await;
    assert!(relay2.is_some(), "relay endpoint should exist");
}

#[tokio::test]
async fn relay_server_shares_socket() {
    // With socket multiplexing, the relay server shares the QUIC socket
    let node = Node::bind(&test_addr()).await.expect("node bind failed");
    
    // Verify the relay endpoint uses the same port as QUIC
    let relay = node.relay_endpoint().await.expect("relay endpoint should exist");
    let quic_addr = node.quic_endpoint().local_addr().expect("quic addr");
    
    // The advertised relay address should use the same port
    let primary = relay.addrs.first().expect("should have relay addr");
    let relay_addr: std::net::SocketAddr = primary.parse().expect("parse relay addr");
    assert_eq!(relay_addr.port(), quic_addr.port(), "relay and QUIC should share port");
}

// ============================================================================
// Direct Connect vs Relay Fallback
// ============================================================================

#[tokio::test]
async fn direct_connect_preferred_when_available() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // Bootstrap node2 from node1 (populates routing tables)
    node2.bootstrap(&node1_id, &node1_addr).await.expect("bootstrap failed");
    
    // Node1 publishes its address for DHT resolution
    node1.publish_address(vec![node1_addr.clone()]).await.expect("publish failed");
    
    // Connect using identity only (resolves via DHT)
    let result = timeout(
        TEST_TIMEOUT,
        node2.connect(&node1_id)
    ).await;
    
    assert!(result.is_ok(), "connect should complete");
    assert!(result.unwrap().is_ok(), "direct connect should succeed");
}

#[tokio::test]
async fn connect_with_relay_available() {
    init_tracing();
    let start = Instant::now();
    progress(start, "Starting connect_with_relay_available");
    
    let relay = Node::bind(&test_addr()).await.expect("relay bind failed");
    progress(start, "Relay node bound");
    
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    progress(start, "Node1 bound");
    
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    progress(start, "Node2 bound");
    
    let relay_id = relay.identity();
    let relay_addr = relay.local_addr().unwrap().to_string();
    
    progress(start, "Starting node1 bootstrap...");
    node1.bootstrap(&relay_id, &relay_addr).await.expect("node1 bootstrap failed");
    progress(start, "Node1 bootstrap complete");
    
    progress(start, "Starting node2 bootstrap...");
    node2.bootstrap(&relay_id, &relay_addr).await.expect("node2 bootstrap failed");
    progress(start, "Node2 bootstrap complete");
    
    // Node1 publishes with relay info
    progress(start, "Getting relay identity...");
    let relay_identity = relay.peer_identity();
    let addrs = vec![node1.local_addr().unwrap().to_string()];
    progress(start, "Publishing address with relays...");
    node1.publish_address_with_relays(addrs, vec![relay_identity]).await
        .expect("publish failed");
    progress(start, "Publish complete");
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Direct connect should still work since both are reachable
    progress(start, "Starting connect via identity...");
    let result = timeout(
        TEST_TIMEOUT,
        node2.connect(&node1.identity())
    ).await;
    progress(start, "Connect complete");
    
    assert!(result.is_ok(), "connect should complete");
    assert!(result.unwrap().is_ok(), "connect should succeed");
    progress(start, "Test passed");
}

// ============================================================================
// SmartSock Integration with Relay
// ============================================================================

#[tokio::test]
async fn smartsock_inner_socket_accessible() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    let smartsock = node.smartsock();
    let inner = smartsock.inner_socket();
    
    // Should be able to get local address matching node
    let addr = inner.local_addr().expect("local_addr should work");
    assert_eq!(addr, node.local_addr().unwrap());
}

#[tokio::test]
async fn smartsock_peer_registration() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // Bootstrap node2 from node1 (populates routing tables)
    node2.bootstrap(&node1_id, &node1_addr).await.expect("bootstrap failed");
    
    // Node1 publishes its address for DHT resolution
    node1.publish_address(vec![node1_addr.clone()]).await.expect("publish failed");
    
    // Connect which should register the peer (identity-only resolves via DHT)
    let _ = timeout(
        TEST_TIMEOUT,
        node2.connect(&node1_id)
    ).await;
    
    // SmartSock should have the peer registered
    // (We can't directly check, but the connection should work)
}

// ============================================================================
// Stress Tests
// ============================================================================

#[tokio::test]
async fn multiple_relay_endpoints_sequential() {
    for _ in 0..3 {
        let node = Node::bind(&test_addr()).await.expect("bind failed");
        
        let relay = node.relay_endpoint().await;
        assert!(relay.is_some(), "relay endpoint should exist");
        
        // Clean up
        drop(node);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn sequential_relay_operations() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let relay_identity = node2.peer_identity();
    
    // Sequential publish operations (Node is not Clone)
    for i in 0..5 {
        let addrs = vec![format!("10.0.0.{}:5000", i)];
        let _ = node1.publish_address_with_relays(addrs, vec![relay_identity]).await;
    }
}

// ============================================================================
// Error Handling
// ============================================================================

#[tokio::test]
async fn invalid_relay_address_handling() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Publish with addresses that might not be reachable
    let addrs = vec![
        "0.0.0.0:0".to_string(),  // Invalid
        "255.255.255.255:1".to_string(),  // Broadcast
    ];
    
    // Should not panic, just store the data
    let _ = node.publish_address(addrs).await;
}

#[tokio::test]
async fn relay_with_closed_node() {
    let relay_identity;
    {
        let relay = Node::bind(&test_addr()).await.expect("relay bind failed");
        relay_identity = relay.peer_identity();
        // relay goes out of scope and is dropped
    }
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let node = Node::bind(&test_addr()).await.expect("node bind failed");
    
    // Publishing with closed relay should still succeed (stored locally)
    let addrs = vec!["10.0.0.1:5000".to_string()];
    let result = node.publish_address_with_relays(addrs, vec![relay_identity]).await;
    
    // May succeed or fail depending on whether connection attempt is made
    let _ = result;
}
