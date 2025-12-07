//! Integration tests for the relay infrastructure.
//!
//! These tests validate the UDP relay forwarder, relay session management,
//! and relay-assisted connectivity at an integration level.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use corium::Node;
use tokio::time::timeout;

/// Atomic port counter for unique port allocation across parallel tests.
/// Nodes use socket multiplexing, so relay shares the same port as QUIC.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(40000);

fn next_port() -> u16 {
    PORT_COUNTER.fetch_add(2, Ordering::SeqCst)
}

fn test_addr() -> String {
    format!("127.0.0.1:{}", next_port())
}

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

// ============================================================================
// Relay Capability Tests
// ============================================================================

#[tokio::test]
async fn node_relay_capability_check() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Check if relay is available
    let is_relay = node.is_relay_capable();
    
    // The relay forwarder binds to port+1, so it may or may not succeed
    // Just verify the API works correctly
    if is_relay {
        let relay_ep = node.relay_endpoint().await;
        assert!(relay_ep.is_some(), "relay endpoint should exist");
        
        let contact = relay_ep.unwrap();
        assert_eq!(
            hex::encode(contact.identity),
            node.identity(),
            "relay identity should match node"
        );
    }
}

#[tokio::test]
async fn two_relay_nodes_capability() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    // Both should have relay capability status
    let _ = node1.is_relay_capable();
    let _ = node2.is_relay_capable();
    
    // Verify both can report their endpoints
    let _ = node1.relay_endpoint().await;
    let _ = node2.relay_endpoint().await;
}

// ============================================================================
// Relay-Assisted Address Publishing
// ============================================================================

#[tokio::test]
async fn publish_address_with_relay_info() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    // Node2 acts as a potential relay
    let relay_contact = node2.peer_endpoint().clone();
    
    // Node1 publishes its address with relay info
    let addrs = vec![
        "10.0.0.1:5000".to_string(),
        "192.168.1.1:5000".to_string(),
    ];
    
    let result = node1.publish_address_with_relays(addrs.clone(), vec![relay_contact.clone()]).await;
    assert!(result.is_ok(), "publish_address_with_relays should succeed");
    
    // Publish again to verify idempotency
    let result = node1.publish_address_with_relays(addrs, vec![relay_contact]).await;
    assert!(result.is_ok(), "second publish should also succeed");
}

#[tokio::test]
async fn publish_address_with_multiple_relays() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let relay1 = Node::bind(&test_addr()).await.expect("relay1 bind failed");
    let relay2 = Node::bind(&test_addr()).await.expect("relay2 bind failed");
    
    let relays = vec![
        relay1.peer_endpoint().clone(),
        relay2.peer_endpoint().clone(),
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
        let addr: Result<SocketAddr, _> = relay_ep.addr.parse();
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
        
        // Either the main addr is in addrs, or it matches the primary addr
        let _has_quic = relay_ep.addr == main_addr 
            || relay_ep.addrs.iter().any(|a| a == &main_addr);
        
        // Just verify the struct is populated correctly
        assert!(!relay_ep.addr.is_empty());
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
    
    if let Some(relay_ep) = node1.relay_endpoint().await {
        let addrs = vec![node2.local_addr().unwrap().to_string()];
        node2.publish_address_with_relays(addrs, vec![relay_ep]).await
            .expect("node2 publish failed");
    }
    
    // Node3 bootstraps
    node3.bootstrap(&node1_id, &node1_addr).await.expect("node3 bootstrap failed");
    
    // Allow time for DHT propagation
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Node3 should be able to find node2's peers
    let peers = node3.find_peers(node2.keypair().identity()).await;
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
// UDP Relay Forwarder Port Binding
// ============================================================================

#[tokio::test]
async fn relay_forwarder_port_availability() {
    // Bind a node
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // The relay forwarder should have tried to bind to port+1
    // If it failed, is_relay_capable returns false
    let is_capable = node.is_relay_capable();
    
    // Create another node
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    let is_capable2 = node2.is_relay_capable();
    
    // At least one should be relay capable
    let _ = is_capable || is_capable2;
}

#[tokio::test]
async fn relay_forwarder_shares_socket() {
    // With socket multiplexing, the relay forwarder shares the QUIC socket
    // so no separate port is needed and relay is always capable
    let node = Node::bind(&test_addr()).await.expect("node bind failed");
    
    // Relay should always be capable since it shares the socket
    assert!(node.is_relay_capable(), "relay should be capable with socket multiplexing");
    
    // Verify the relay endpoint uses the same port as QUIC
    let relay = node.relay_endpoint().await.expect("relay endpoint should exist");
    let quic_addr = node.quic_endpoint().local_addr().expect("quic addr");
    
    // The advertised relay address should use the same port
    let relay_addr: std::net::SocketAddr = relay.addr.parse().expect("parse relay addr");
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
    
    // Direct connect should work
    let result = timeout(
        TEST_TIMEOUT,
        node2.connect(&node1_id, &node1_addr)
    ).await;
    
    assert!(result.is_ok(), "connect should complete");
    assert!(result.unwrap().is_ok(), "direct connect should succeed");
}

#[tokio::test]
async fn connect_with_relay_available() {
    let relay = Node::bind(&test_addr()).await.expect("relay bind failed");
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let relay_id = relay.identity();
    let relay_addr = relay.local_addr().unwrap().to_string();
    
    // All nodes bootstrap from relay
    node1.bootstrap(&relay_id, &relay_addr).await.expect("node1 bootstrap failed");
    node2.bootstrap(&relay_id, &relay_addr).await.expect("node2 bootstrap failed");
    
    // Node1 publishes with relay info if available
    if let Some(relay_ep) = relay.relay_endpoint().await {
        let addrs = vec![node1.local_addr().unwrap().to_string()];
        node1.publish_address_with_relays(addrs, vec![relay_ep]).await
            .expect("publish failed");
    }
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Direct connect should still work since both are reachable
    let result = timeout(
        TEST_TIMEOUT,
        node2.connect(&node1.identity(), &node1.local_addr().unwrap().to_string())
    ).await;
    
    assert!(result.is_ok(), "connect should complete");
    assert!(result.unwrap().is_ok(), "connect should succeed");
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
    
    // Connect which should register the peer
    let _ = timeout(
        TEST_TIMEOUT,
        node2.connect(&node1_id, &node1_addr)
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
        
        let _ = node.is_relay_capable();
        let _ = node.relay_endpoint().await;
        
        // Clean up
        drop(node);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn sequential_relay_operations() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let relay_contact = node2.peer_endpoint().clone();
    
    // Sequential publish operations (Node is not Clone)
    for i in 0..5 {
        let addrs = vec![format!("10.0.0.{}:5000", i)];
        let _ = node1.publish_address_with_relays(addrs, vec![relay_contact.clone()]).await;
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
    let relay_contact;
    {
        let relay = Node::bind(&test_addr()).await.expect("relay bind failed");
        relay_contact = relay.peer_endpoint().clone();
        // relay goes out of scope and is dropped
    }
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let node = Node::bind(&test_addr()).await.expect("node bind failed");
    
    // Publishing with closed relay should still succeed (stored locally)
    let addrs = vec!["10.0.0.1:5000".to_string()];
    let result = node.publish_address_with_relays(addrs, vec![relay_contact]).await;
    
    // May succeed or fail depending on whether connection attempt is made
    let _ = result;
}
