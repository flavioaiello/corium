//! Integration tests for GossipSub PubSub functionality.
//!
//! These tests validate end-to-end message delivery between nodes via the
//! GossipSub epidemic broadcast protocol.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use corium::Node;
use tokio::time::timeout;

/// Atomic port counter for unique port allocation across parallel tests.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(40000);

fn next_port() -> u16 {
    PORT_COUNTER.fetch_add(2, Ordering::SeqCst)
}

fn test_addr() -> String {
    format!("127.0.0.1:{}", next_port())
}

const TEST_TIMEOUT: Duration = Duration::from_secs(15);
const MESSAGE_WAIT: Duration = Duration::from_millis(500);

// =============================================================================
// Helper Functions
// =============================================================================

// =============================================================================
// Test: 3 nodes publish/receive
// =============================================================================

/// Test that a message published on node A is received by nodes B and C.
#[tokio::test]
async fn three_node_pubsub_broadcast() {
    let node_a = Node::bind(&test_addr()).await.expect("node_a bind failed");
    let node_b = Node::bind(&test_addr()).await.expect("node_b bind failed");
    let node_c = Node::bind(&test_addr()).await.expect("node_c bind failed");
    
    let node_a_id = node_a.identity();
    let node_a_addr = node_a.local_addr().unwrap().to_string();
    
    // Build network: B → A, C → A
    node_b.bootstrap(&node_a_id, &node_a_addr).await.expect("node_b bootstrap failed");
    node_c.bootstrap(&node_a_id, &node_a_addr).await.expect("node_c bootstrap failed");
    
    let topic = "broadcast-test";
    
    // All nodes subscribe
    node_a.subscribe(topic).await.expect("node_a subscribe failed");
    node_b.subscribe(topic).await.expect("node_b subscribe failed");
    node_c.subscribe(topic).await.expect("node_c subscribe failed");
    
    // Allow mesh formation
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Get message receivers BEFORE publishing
    let mut rx_b = node_b.messages().await.expect("node_b messages failed");
    let mut rx_c = node_c.messages().await.expect("node_c messages failed");
    
    // Node A publishes a message
    let test_data = b"hello from node A".to_vec();
    node_a.publish(topic, test_data.clone()).await.expect("publish failed");
    
    // Node B should receive the message
    let msg_b = timeout(TEST_TIMEOUT, rx_b.recv()).await
        .expect("node_b receive timeout")
        .expect("node_b channel closed");
    
    assert_eq!(msg_b.topic, topic);
    assert_eq!(msg_b.from, node_a_id);
    assert_eq!(msg_b.data, test_data);
    
    // Node C should also receive the message
    let msg_c = timeout(TEST_TIMEOUT, rx_c.recv()).await
        .expect("node_c receive timeout")
        .expect("node_c channel closed");
    
    assert_eq!(msg_c.topic, topic);
    assert_eq!(msg_c.from, node_a_id);
    assert_eq!(msg_c.data, test_data);
}

// =============================================================================
// Test: 5 nodes, only subscribers receive
// =============================================================================

/// Test that only subscribed nodes receive messages (4 subscribed, 1 not).
#[tokio::test]
async fn five_node_selective_subscription() {
    let node_a = Node::bind(&test_addr()).await.expect("node_a bind failed");
    let node_b = Node::bind(&test_addr()).await.expect("node_b bind failed");
    let node_c = Node::bind(&test_addr()).await.expect("node_c bind failed");
    let node_d = Node::bind(&test_addr()).await.expect("node_d bind failed");
    let node_e = Node::bind(&test_addr()).await.expect("node_e bind failed"); // Not subscribed
    
    let node_a_id = node_a.identity();
    let node_a_addr = node_a.local_addr().unwrap().to_string();
    
    // Build network: all nodes bootstrap from A
    node_b.bootstrap(&node_a_id, &node_a_addr).await.expect("node_b bootstrap failed");
    node_c.bootstrap(&node_a_id, &node_a_addr).await.expect("node_c bootstrap failed");
    node_d.bootstrap(&node_a_id, &node_a_addr).await.expect("node_d bootstrap failed");
    node_e.bootstrap(&node_a_id, &node_a_addr).await.expect("node_e bootstrap failed");
    
    let topic = "selective-test";
    
    // Only A, B, C, D subscribe (E does NOT subscribe)
    node_a.subscribe(topic).await.expect("node_a subscribe failed");
    node_b.subscribe(topic).await.expect("node_b subscribe failed");
    node_c.subscribe(topic).await.expect("node_c subscribe failed");
    node_d.subscribe(topic).await.expect("node_d subscribe failed");
    // node_e intentionally does NOT subscribe
    
    // Allow mesh formation
    tokio::time::sleep(Duration::from_millis(300)).await;
    
    // Get message receivers
    let mut rx_b = node_b.messages().await.expect("node_b messages failed");
    let mut rx_c = node_c.messages().await.expect("node_c messages failed");
    let mut rx_d = node_d.messages().await.expect("node_d messages failed");
    let mut rx_e = node_e.messages().await.expect("node_e messages failed");
    
    // Node A publishes
    let test_data = b"selective broadcast".to_vec();
    node_a.publish(topic, test_data.clone()).await.expect("publish failed");
    
    // Subscribed nodes should receive
    let msg_b = timeout(TEST_TIMEOUT, rx_b.recv()).await
        .expect("node_b timeout").expect("node_b closed");
    assert_eq!(msg_b.data, test_data);
    
    let msg_c = timeout(TEST_TIMEOUT, rx_c.recv()).await
        .expect("node_c timeout").expect("node_c closed");
    assert_eq!(msg_c.data, test_data);
    
    let msg_d = timeout(TEST_TIMEOUT, rx_d.recv()).await
        .expect("node_d timeout").expect("node_d closed");
    assert_eq!(msg_d.data, test_data);
    
    // Node E should NOT receive (not subscribed)
    let result_e = timeout(MESSAGE_WAIT, rx_e.recv()).await;
    assert!(result_e.is_err(), "node_e should NOT receive message (not subscribed)");
}

// =============================================================================
// Test: Message deduplication
// =============================================================================

/// Test that the same message is not delivered twice to a node.
#[tokio::test]
async fn message_deduplication() {
    let node_a = Node::bind(&test_addr()).await.expect("node_a bind failed");
    let node_b = Node::bind(&test_addr()).await.expect("node_b bind failed");
    let node_c = Node::bind(&test_addr()).await.expect("node_c bind failed");
    
    let node_a_id = node_a.identity();
    let node_a_addr = node_a.local_addr().unwrap().to_string();
    let node_b_id = node_b.identity();
    let node_b_addr = node_b.local_addr().unwrap().to_string();
    
    // Build a triangle: B → A, C → A, C → B
    // This creates potential for duplicate message paths
    node_b.bootstrap(&node_a_id, &node_a_addr).await.expect("B→A bootstrap failed");
    node_c.bootstrap(&node_a_id, &node_a_addr).await.expect("C→A bootstrap failed");
    node_c.bootstrap(&node_b_id, &node_b_addr).await.expect("C→B bootstrap failed");
    
    let topic = "dedup-test";
    
    node_a.subscribe(topic).await.expect("node_a subscribe failed");
    node_b.subscribe(topic).await.expect("node_b subscribe failed");
    node_c.subscribe(topic).await.expect("node_c subscribe failed");
    
    // Allow mesh formation
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let mut rx_c = node_c.messages().await.expect("node_c messages failed");
    
    // Node A publishes multiple times with SAME content
    // (note: same content from same source should have same MessageId)
    let test_data = b"dedup test message".to_vec();
    node_a.publish(topic, test_data.clone()).await.expect("publish 1 failed");
    
    // First message should arrive
    let msg1 = timeout(TEST_TIMEOUT, rx_c.recv()).await
        .expect("first message timeout")
        .expect("channel closed");
    assert_eq!(msg1.data, test_data);
    
    // Wait and send again (different seqno, so it's a new message)
    tokio::time::sleep(Duration::from_millis(50)).await;
    node_a.publish(topic, test_data.clone()).await.expect("publish 2 failed");
    
    // Second message with different seqno should also arrive
    let msg2 = timeout(TEST_TIMEOUT, rx_c.recv()).await
        .expect("second message timeout")
        .expect("channel closed");
    assert_eq!(msg2.data, test_data);
    
    // But the message should not be duplicated (no extra copies)
    // We verify by checking that no more messages arrive quickly
    let extra = timeout(MESSAGE_WAIT, rx_c.recv()).await;
    assert!(extra.is_err(), "should not receive duplicate messages");
}

// =============================================================================
// Test: Multi-topic subscriptions
// =============================================================================

/// Test that nodes can subscribe to multiple topics and receive on correct topics.
#[tokio::test]
async fn multi_topic_subscriptions() {
    let node_a = Node::bind(&test_addr()).await.expect("node_a bind failed");
    let node_b = Node::bind(&test_addr()).await.expect("node_b bind failed");
    
    let node_a_id = node_a.identity();
    let node_a_addr = node_a.local_addr().unwrap().to_string();
    
    node_b.bootstrap(&node_a_id, &node_a_addr).await.expect("bootstrap failed");
    
    let topic1 = "sports";
    let topic2 = "weather";
    let topic3 = "news";
    
    // Node A subscribes to all topics
    node_a.subscribe(topic1).await.expect("subscribe topic1 failed");
    node_a.subscribe(topic2).await.expect("subscribe topic2 failed");
    node_a.subscribe(topic3).await.expect("subscribe topic3 failed");
    
    // Node B subscribes only to topic1 and topic2 (NOT topic3)
    node_b.subscribe(topic1).await.expect("subscribe topic1 failed");
    node_b.subscribe(topic2).await.expect("subscribe topic2 failed");
    
    // Allow mesh formation
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let mut rx_b = node_b.messages().await.expect("node_b messages failed");
    
    // Publish to all three topics from node A
    node_a.publish(topic1, b"sports update".to_vec()).await.expect("publish topic1 failed");
    node_a.publish(topic2, b"weather report".to_vec()).await.expect("publish topic2 failed");
    node_a.publish(topic3, b"breaking news".to_vec()).await.expect("publish topic3 failed");
    
    // Collect messages received by node B
    let mut received_topics: HashSet<String> = HashSet::new();
    
    // Should receive 2 messages (topic1 and topic2)
    for _ in 0..2 {
        let msg = timeout(TEST_TIMEOUT, rx_b.recv()).await
            .expect("message timeout")
            .expect("channel closed");
        received_topics.insert(msg.topic.clone());
    }
    
    // Verify received correct topics
    assert!(received_topics.contains(topic1), "should receive sports");
    assert!(received_topics.contains(topic2), "should receive weather");
    
    // Should NOT receive topic3 (not subscribed)
    let extra = timeout(MESSAGE_WAIT, rx_b.recv()).await;
    assert!(extra.is_err(), "should not receive topic3 (not subscribed)");
}

// =============================================================================
// Test: Mesh formation (graft/prune)
// =============================================================================

/// Test that mesh is properly formed and subscription changes propagate.
#[tokio::test]
async fn mesh_formation_graft_prune() {
    let node_a = Node::bind(&test_addr()).await.expect("node_a bind failed");
    let node_b = Node::bind(&test_addr()).await.expect("node_b bind failed");
    
    let node_a_id = node_a.identity();
    let node_a_addr = node_a.local_addr().unwrap().to_string();
    
    node_b.bootstrap(&node_a_id, &node_a_addr).await.expect("bootstrap failed");
    
    let topic = "mesh-test";
    
    // Initially only A subscribes
    node_a.subscribe(topic).await.expect("node_a subscribe failed");
    
    let mut rx_b = node_b.messages().await.expect("node_b messages failed");
    
    // Publish from A - B should NOT receive (not subscribed)
    node_a.publish(topic, b"before subscription".to_vec()).await.expect("publish failed");
    let result = timeout(MESSAGE_WAIT, rx_b.recv()).await;
    assert!(result.is_err(), "B should not receive before subscribing");
    
    // Now B subscribes (triggers GRAFT to A)
    node_b.subscribe(topic).await.expect("node_b subscribe failed");
    
    // Allow mesh formation (graft exchange)
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Now B should receive messages
    node_a.publish(topic, b"after subscription".to_vec()).await.expect("publish failed");
    let msg = timeout(TEST_TIMEOUT, rx_b.recv()).await
        .expect("message timeout after subscribe")
        .expect("channel closed");
    assert_eq!(msg.data, b"after subscription".to_vec());
    
    // B unsubscribes (triggers PRUNE to A)
    node_b.unsubscribe(topic).await.expect("unsubscribe failed");
    
    // Allow mesh update
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // B should no longer receive
    node_a.publish(topic, b"after unsubscribe".to_vec()).await.expect("publish failed");
    let result = timeout(MESSAGE_WAIT, rx_b.recv()).await;
    assert!(result.is_err(), "B should not receive after unsubscribing");
}

// =============================================================================
// Test: Message signature verification
// =============================================================================

/// Test that messages are signed and signature verification works end-to-end.
#[tokio::test]
async fn message_signature_verification() {
    let node_a = Node::bind(&test_addr()).await.expect("node_a bind failed");
    let node_b = Node::bind(&test_addr()).await.expect("node_b bind failed");
    
    let node_a_id = node_a.identity();
    let node_a_addr = node_a.local_addr().unwrap().to_string();
    
    node_b.bootstrap(&node_a_id, &node_a_addr).await.expect("bootstrap failed");
    
    let topic = "signed-test";
    
    node_a.subscribe(topic).await.expect("node_a subscribe failed");
    node_b.subscribe(topic).await.expect("node_b subscribe failed");
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let mut rx_b = node_b.messages().await.expect("node_b messages failed");
    
    // Publish a message - it will be signed internally by GossipSub
    let test_data = b"signed message content".to_vec();
    node_a.publish(topic, test_data.clone()).await.expect("publish failed");
    
    // Receive the message
    let msg = timeout(TEST_TIMEOUT, rx_b.recv()).await
        .expect("receive timeout")
        .expect("channel closed");
    
    // Verify the source matches the publishing node's identity
    // (if signature verification failed, the message would have been rejected)
    assert_eq!(msg.from, node_a_id, "message source should be node_a");
    assert_eq!(msg.data, test_data, "message data should match");
    assert_eq!(msg.topic, topic, "message topic should match");
}

// =============================================================================
// Test: Publisher receives own messages (loopback)
// =============================================================================

/// Test that a node receives its own published messages (loopback delivery).
/// This is the intended behavior in Corium's GossipSub implementation.
#[tokio::test]
async fn publisher_receives_own_messages_loopback() {
    let node_a = Node::bind(&test_addr()).await.expect("node_a bind failed");
    let node_b = Node::bind(&test_addr()).await.expect("node_b bind failed");
    
    let node_a_id = node_a.identity();
    let node_a_addr = node_a.local_addr().unwrap().to_string();
    
    node_b.bootstrap(&node_a_id, &node_a_addr).await.expect("bootstrap failed");
    
    let topic = "loopback-test";
    
    node_a.subscribe(topic).await.expect("node_a subscribe failed");
    node_b.subscribe(topic).await.expect("node_b subscribe failed");
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let mut rx_a = node_a.messages().await.expect("node_a messages failed");
    let mut rx_b = node_b.messages().await.expect("node_b messages failed");
    
    // Node A publishes
    node_a.publish(topic, b"from A".to_vec()).await.expect("A publish failed");
    
    // Node A should receive its own message (loopback)
    let msg_a = timeout(TEST_TIMEOUT, rx_a.recv()).await
        .expect("A loopback timeout")
        .expect("A channel closed");
    assert_eq!(msg_a.from, node_a_id, "loopback source should be self");
    assert_eq!(msg_a.data, b"from A".to_vec());
    
    // Node B should also receive
    let msg_b = timeout(TEST_TIMEOUT, rx_b.recv()).await
        .expect("B receive timeout")
        .expect("B channel closed");
    assert_eq!(msg_b.from, node_a_id);
    
    // Node B publishes
    let node_b_id = node_b.identity();
    node_b.publish(topic, b"from B".to_vec()).await.expect("B publish failed");
    
    // Node A should receive from B
    let msg_from_b = timeout(TEST_TIMEOUT, rx_a.recv()).await
        .expect("A receive from B timeout")
        .expect("A channel closed");
    assert_eq!(msg_from_b.from, node_b_id);
}

// =============================================================================
// Test: Large mesh propagation
// =============================================================================

/// Test message propagation through a larger mesh (chain topology).
#[tokio::test]
async fn chain_topology_propagation() {
    // Create a chain: A → B → C → D
    let node_a = Node::bind(&test_addr()).await.expect("node_a bind failed");
    let node_b = Node::bind(&test_addr()).await.expect("node_b bind failed");
    let node_c = Node::bind(&test_addr()).await.expect("node_c bind failed");
    let node_d = Node::bind(&test_addr()).await.expect("node_d bind failed");
    
    let node_a_id = node_a.identity();
    let node_a_addr = node_a.local_addr().unwrap().to_string();
    let node_b_id = node_b.identity();
    let node_b_addr = node_b.local_addr().unwrap().to_string();
    let node_c_id = node_c.identity();
    let node_c_addr = node_c.local_addr().unwrap().to_string();
    
    // Build chain
    node_b.bootstrap(&node_a_id, &node_a_addr).await.expect("B→A failed");
    node_c.bootstrap(&node_b_id, &node_b_addr).await.expect("C→B failed");
    node_d.bootstrap(&node_c_id, &node_c_addr).await.expect("D→C failed");
    
    let topic = "chain-test";
    
    // All nodes subscribe
    node_a.subscribe(topic).await.expect("A subscribe failed");
    node_b.subscribe(topic).await.expect("B subscribe failed");
    node_c.subscribe(topic).await.expect("C subscribe failed");
    node_d.subscribe(topic).await.expect("D subscribe failed");
    
    // Allow mesh formation across the chain
    tokio::time::sleep(Duration::from_millis(400)).await;
    
    let mut rx_d = node_d.messages().await.expect("D messages failed");
    
    // A publishes - should propagate A → B → C → D
    node_a.publish(topic, b"from the start".to_vec()).await.expect("publish failed");
    
    // D (at the end of chain) should receive
    let msg = timeout(TEST_TIMEOUT, rx_d.recv()).await
        .expect("D receive timeout")
        .expect("D channel closed");
    
    assert_eq!(msg.from, node_a_id);
    assert_eq!(msg.data, b"from the start".to_vec());
}
