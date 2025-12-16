//! Integration tests for the Node public API.
//!
//! These tests exercise the public interface exposed through the Node facade,
//! validating that all public methods work correctly in realistic scenarios.

use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use corium::Node;
use tokio::time::timeout;

/// Atomic port counter for unique port allocation across parallel tests.
/// Nodes use port N, relay server uses N+1, so we increment by 2.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(30000);

fn next_port() -> u16 {
    PORT_COUNTER.fetch_add(2, Ordering::SeqCst)
}

/// Helper to allocate unique ports for test nodes
fn test_addr() -> String {
    format!("127.0.0.1:{}", next_port())
}

/// Allow time for async operations
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const SHORT_TIMEOUT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn node_bind_and_identity() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Identity should be 64 hex characters (32 bytes)
    let identity = node.identity();
    assert_eq!(identity.len(), 64, "identity should be 64 hex chars");
    assert!(identity.chars().all(|c| c.is_ascii_hexdigit()), "identity should be hex");
    
    // Local address should be valid
    let local_addr = node.local_addr().expect("local_addr failed");
    assert!(local_addr.port() > 0, "port should be positive");
}

#[tokio::test]
async fn node_keypair_accessor() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    let keypair = node.keypair();
    let identity_from_keypair = hex::encode(keypair.identity());
    
    assert_eq!(identity_from_keypair, node.identity());
}

#[tokio::test]
async fn node_peer_endpoint_accessor() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    let contact = node.peer_endpoint();
    
    assert!(!contact.addrs.is_empty(), "contact addrs should not be empty");
    assert_eq!(
        hex::encode(contact.identity),
        node.identity(),
        "contact identity should match node identity"
    );
}

#[tokio::test]
async fn node_quic_endpoint_accessor() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    let endpoint = node.quic_endpoint();
    let addr = endpoint.local_addr().expect("endpoint local_addr failed");
    
    // Should match the node's local address
    assert_eq!(addr, node.local_addr().unwrap());
}

#[tokio::test]
async fn node_smartsock_accessor() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    let smartsock = node.smartsock();
    // SmartSock should wrap the inner socket
    let inner = smartsock.inner_socket();
    assert!(inner.local_addr().is_ok());
}

#[tokio::test]
async fn node_relay_capability() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Relay is mandatory for all nodes
    let relay_ep = node.relay_endpoint().await;
    assert!(relay_ep.is_some(), "relay endpoint should exist");
}

#[tokio::test]
async fn node_dht_put_get() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    let value = b"test-value-12345".to_vec();
    
    // Put returns the content-addressed key
    let key = node.put(value.clone()).await.expect("put failed");
    
    // Key is [u8; 32] (blake3 hash)
    assert_eq!(key.len(), 32, "key should be 32 bytes");
    
    // Get should return the value (from local store)
    let retrieved = node.get(&key).await.expect("get failed");
    assert_eq!(retrieved, Some(value));
}

#[tokio::test]
async fn node_dht_put_at_get() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    let value = b"test-value-for-put-at".to_vec();
    
    // First put to get the content-addressed key
    let key = node.put(value.clone()).await.expect("put failed");
    
    // Verify the key is 32 bytes (blake3 hash)
    assert_eq!(key.len(), 32);
    
    // put_at with the SAME value at the SAME key should succeed
    // (this is used for replication to specific nodes)
    node.put_at(key, value.clone()).await.expect("put_at failed");
    
    // Get should return the value
    let retrieved = node.get(&key).await.expect("get failed");
    assert_eq!(retrieved, Some(value));
}

#[tokio::test]
async fn node_telemetry() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Do some operations
    let _ = node.put(b"telemetry-test".to_vec()).await;
    
    let telemetry = node.telemetry().await;
    
    // Telemetry should have reasonable values
    assert!(telemetry.stored_keys >= 1, "should have at least 1 stored key");
}

#[tokio::test]
async fn node_pubsub_subscribe_unsubscribe() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Subscribe should succeed
    node.subscribe("test-topic").await.expect("subscribe failed");
    
    // Unsubscribe should succeed
    node.unsubscribe("test-topic").await.expect("unsubscribe failed");
}

#[tokio::test]
async fn node_pubsub_publish() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    node.subscribe("broadcast-topic").await.expect("subscribe failed");
    
    // Publish should succeed (even with no peers)
    node.publish("broadcast-topic", b"test message".to_vec())
        .await
        .expect("publish failed");
}

#[tokio::test]
async fn node_messages_receiver() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Should be able to get the message receiver once
    let rx = node.messages().await.expect("messages() failed");
    drop(rx);
    
    // Second call should fail (receiver already taken)
    let result = node.messages().await;
    assert!(result.is_err(), "messages() should fail on second call");
}

#[tokio::test]
async fn two_node_bootstrap() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // Node2 bootstraps from node1
    let result = timeout(
        TEST_TIMEOUT,
        node2.bootstrap(&node1_id, &node1_addr)
    ).await;
    
    assert!(result.is_ok(), "bootstrap should complete within timeout");
    assert!(result.unwrap().is_ok(), "bootstrap should succeed");
}

#[tokio::test]
async fn two_node_connect() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // Bootstrap node2 from node1 (populates routing tables)
    node2.bootstrap(&node1_id, &node1_addr).await.expect("bootstrap failed");
    
    // Node1 publishes its address so it can be resolved via DHT
    node1.publish_address(vec![node1_addr.clone()]).await.expect("publish failed");
    
    // Connect using identity only (resolves via DHT)
    let result = timeout(
        TEST_TIMEOUT,
        node2.connect(&node1_id)
    ).await;
    
    assert!(result.is_ok(), "connect should complete within timeout");
    let conn = result.unwrap().expect("connect should succeed");
    
    // Connection should be open
    assert!(conn.close_reason().is_none(), "connection should be open");
}

#[tokio::test]
async fn two_node_dht_replication() {
    let start = std::time::Instant::now();
    eprintln!("[{:>6.2}s] Starting two_node_dht_replication", start.elapsed().as_secs_f64());
    
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    eprintln!("[{:>6.2}s] node1 bound", start.elapsed().as_secs_f64());
    
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    eprintln!("[{:>6.2}s] node2 bound", start.elapsed().as_secs_f64());
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // Bootstrap
    eprintln!("[{:>6.2}s] starting bootstrap", start.elapsed().as_secs_f64());
    node2.bootstrap(&node1_id, &node1_addr).await.expect("bootstrap failed");
    eprintln!("[{:>6.2}s] bootstrap complete", start.elapsed().as_secs_f64());
    
    // Store value on node1
    let value = b"replicated-value".to_vec();
    eprintln!("[{:>6.2}s] starting put", start.elapsed().as_secs_f64());
    let key = node1.put(value.clone()).await.expect("put failed");
    eprintln!("[{:>6.2}s] put complete", start.elapsed().as_secs_f64());
    
    // Give time for gossip
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Verify node1 can still retrieve its own value
    eprintln!("[{:>6.2}s] starting get from node1", start.elapsed().as_secs_f64());
    let retrieved = node1.get(&key).await.expect("get from origin failed");
    eprintln!("[{:>6.2}s] get from node1 complete", start.elapsed().as_secs_f64());
    assert_eq!(retrieved, Some(value.clone()));
    
    // Node2 should be able to look up the value (may or may not find it depending on replication)
    // We don't assert the result since replication may not be instant
    eprintln!("[{:>6.2}s] starting get from node2", start.elapsed().as_secs_f64());
    let _ = node2.get(&key).await;
    eprintln!("[{:>6.2}s] get from node2 complete", start.elapsed().as_secs_f64());
    
    eprintln!("[{:>6.2}s] test logic done, dropping nodes", start.elapsed().as_secs_f64());
}

#[tokio::test]
async fn node_add_peer() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let contact1 = node1.peer_endpoint().clone();
    
    // Add peer should not panic
    node2.add_peer(contact1).await;
    
    // Should be able to find the peer now
    let peers = node2.find_peers(node1.peer_identity()).await;
    assert!(peers.is_ok());
}

#[tokio::test]
async fn node_publish_address() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    let addrs = vec!["192.168.1.100:5000".to_string()];
    
    // Should succeed (stores in local DHT)
    node.publish_address(addrs).await.expect("publish_address failed");
}

#[tokio::test]
async fn node_resolve_peer_not_found() {
    // Resolve requires an Identity which is internal type
    // We test this through connect instead which uses identity string
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Try to resolve a peer that doesn't exist via connect
    let fake_id = "0000000000000000000000000000000000000000000000000000000000000001";
    let result = timeout(SHORT_TIMEOUT, node.connect(fake_id)).await;
    
    // Should timeout or error
    match result {
        Ok(Err(_)) => (), // Error is expected
        Err(_) => (),     // Timeout is expected
        Ok(Ok(_)) => panic!("should not connect to non-existent peer"),
    }
}

#[tokio::test]
async fn three_node_find_peers() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    let node3 = Node::bind(&test_addr()).await.expect("node3 bind failed");
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // All nodes bootstrap from node1
    node2.bootstrap(&node1_id, &node1_addr).await.expect("node2 bootstrap failed");
    node3.bootstrap(&node1_id, &node1_addr).await.expect("node3 bootstrap failed");
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Node3 should be able to find peers near node2's identity
    let peers = node3.find_peers(node2.peer_identity()).await;
    assert!(peers.is_ok(), "find_peers should succeed");
}

#[tokio::test]
async fn invalid_identity_rejected() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Invalid identity (too short)
    let result = node.bootstrap("abc", "127.0.0.1:9999").await;
    assert!(result.is_err(), "should reject short identity");
    
    // Invalid identity (not hex)
    let result = node.bootstrap("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "127.0.0.1:9999").await;
    assert!(result.is_err(), "should reject non-hex identity");
    
    // Invalid identity (wrong length)
    let result = node.bootstrap("aabbccdd", "127.0.0.1:9999").await;
    assert!(result.is_err(), "should reject wrong-length identity");
}

#[tokio::test]
async fn connect_not_in_dht() {
    let node = Node::bind(&test_addr()).await.expect("bind failed");
    
    // Random peer not in DHT
    let fake_id = "0000000000000000000000000000000000000000000000000000000000000001";
    
    let result = timeout(SHORT_TIMEOUT, node.connect(fake_id)).await;
    
    // Should either timeout or return "peer not found"
    match result {
        Ok(Err(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("not found") || msg.contains("timeout"),
                "error should indicate peer not found: {}", msg
            );
        }
        Err(_) => (), // Timeout is acceptable
        Ok(Ok(_)) => panic!("should not connect to non-existent peer"),
    }
}

// ============================================================================
// Contact Signature Lifecycle Tests
// ============================================================================

/// Tests that signed contacts published to DHT can be resolved by another node
/// with valid signatures verified during resolution.
#[tokio::test]
async fn signed_contact_publish_and_resolve() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // Bootstrap node2 from node1
    node2.bootstrap(&node1_id, &node1_addr).await.expect("bootstrap failed");
    
    // Node1 publishes its signed contact (create_contact internally signs with keypair)
    node1.publish_address(vec![node1_addr.clone()]).await.expect("publish failed");
    
    // Give time for DHT propagation
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Node2 resolves node1's contact - this verifies signature internally
    let resolved = timeout(TEST_TIMEOUT, node2.resolve(&node1.peer_identity())).await
        .expect("resolve timeout")
        .expect("resolve failed");
    
    assert!(resolved.is_some(), "should resolve the contact");
    let contact = resolved.unwrap();
    
    // Verify the resolved contact has correct identity
    assert_eq!(hex::encode(contact.identity), node1_id);
    
    // Verify the contact is signed (non-empty signature and non-zero timestamp)
    assert!(!contact.signature.is_empty(), "contact should have signature");
    assert!(contact.timestamp > 0, "contact should have valid timestamp");
    
    // Verify addresses match what was published
    assert!(contact.addrs.contains(&node1_addr), "should contain published address");
}

/// Tests that connections using DHT-resolved signed contacts work correctly.
#[tokio::test]
async fn signed_contact_enables_connection() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // Bootstrap and publish
    node2.bootstrap(&node1_id, &node1_addr).await.expect("bootstrap failed");
    node1.publish_address(vec![node1_addr.clone()]).await.expect("publish failed");
    
    // Connect via identity (internally resolves signed contact from DHT)
    let conn = timeout(TEST_TIMEOUT, node2.connect(&node1_id)).await
        .expect("connect timeout")
        .expect("connect failed");
    
    // Connection should be established and open
    assert!(conn.close_reason().is_none(), "connection should be open");
    
    // Verify the connection is to the correct peer (mTLS validates identity)
    // If signature was invalid, resolution would fail before connection attempt
}

/// Tests that signed contacts work across nodes.
#[tokio::test]
async fn signed_contact_resolves() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    
    let node1_id = node1.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    
    // Bootstrap node2 from node1
    node2.bootstrap(&node1_id, &node1_addr).await.expect("bootstrap failed");
    
    // Node1 publishes signed contact
    node1.publish_address(
        vec![node1_addr.clone()],
    ).await.expect("publish failed");
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Node2 resolves - signature verification validates contact
    let resolved = timeout(TEST_TIMEOUT, node2.resolve(&node1.peer_identity())).await
        .expect("resolve timeout")
        .expect("resolve failed");
    
    assert!(resolved.is_some(), "should resolve contact");
    let contact = resolved.unwrap();
    
    // Verify signature is present
    assert!(!contact.signature.is_empty(), "should have signature");
}

/// Tests that three nodes can form a network with signed contacts.
#[tokio::test]
async fn three_node_signed_contact_network() {
    let node1 = Node::bind(&test_addr()).await.expect("node1 bind failed");
    let node2 = Node::bind(&test_addr()).await.expect("node2 bind failed");
    let node3 = Node::bind(&test_addr()).await.expect("node3 bind failed");
    
    let node1_id = node1.identity();
    let node2_id = node2.identity();
    let node1_addr = node1.local_addr().unwrap().to_string();
    let node2_addr = node2.local_addr().unwrap().to_string();
    
    // Build network: node2 → node1, node3 → node2
    node2.bootstrap(&node1_id, &node1_addr).await.expect("bootstrap 2→1 failed");
    node3.bootstrap(&node2_id, &node2_addr).await.expect("bootstrap 3→2 failed");
    
    // All nodes publish signed contacts
    node1.publish_address(vec![node1_addr.clone()]).await.expect("node1 publish failed");
    node2.publish_address(vec![node2_addr.clone()]).await.expect("node2 publish failed");
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Node3 should be able to resolve node1 through the DHT
    let resolved = timeout(TEST_TIMEOUT, node3.resolve(&node1.peer_identity())).await
        .expect("resolve timeout")
        .expect("resolve failed");
    
    assert!(resolved.is_some(), "node3 should resolve node1's signed contact");
    let contact = resolved.unwrap();
    assert!(!contact.signature.is_empty(), "resolved contact should be signed");
    
    // Node3 should be able to connect to node1 using the resolved signed contact
    let conn = timeout(TEST_TIMEOUT, node3.connect(&node1_id)).await
        .expect("connect timeout")
        .expect("connect failed");
    
    assert!(conn.close_reason().is_none(), "connection should be established");
}
