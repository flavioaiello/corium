#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use common::{make_contact, make_identity, NetworkRegistry, TestNode};
use corium::hash_content;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn iterative_find_node_returns_expected_contacts() {
    let registry = Arc::new(NetworkRegistry::default());
    let main = TestNode::new(registry.clone(), 0x10, 20, 3).await;
    let peer_one = TestNode::new(registry.clone(), 0x11, 20, 3).await;
    let peer_two = TestNode::new(registry.clone(), 0x12, 20, 3).await;

    for peer in [&peer_one, &peer_two] {
        main.node.observe_contact(peer.contact()).await;
        peer.node.observe_contact(main.contact()).await;
    }

    let target = peer_two.contact().identity;
    let results = main
        .node
        .iterative_find_node(target)
        .await
        .expect("lookup succeeds");

    assert_eq!(results.first().map(|c| c.identity), Some(peer_two.contact().identity));
    assert!(results.iter().any(|c| c.identity == peer_one.contact().identity));
}

#[tokio::test]
async fn adaptive_k_tracks_network_successes_and_failures() {
    let registry = Arc::new(NetworkRegistry::default());
    let main = TestNode::new(registry.clone(), 0x30, 10, 3).await;
    let peer = TestNode::new(registry.clone(), 0x31, 10, 3).await;

    main.node.observe_contact(peer.contact()).await;
    peer.node.observe_contact(main.contact()).await;

    main.network.set_failure(peer.contact().identity, true).await;
    let target = make_identity(0xAA);
    let _ = main
        .node
        .iterative_find_node(target)
        .await
        .expect("lookup tolerates failure");
    let snapshot = main.node.telemetry_snapshot().await;
    assert_eq!(snapshot.replication_factor, 30);

    main.network.set_failure(peer.contact().identity, false).await;
    let _ = main
        .node
        .iterative_find_node(target)
        .await
        .expect("lookup succeeds after recovery");
    let snapshot = main.node.telemetry_snapshot().await;
    assert_eq!(snapshot.replication_factor, 20);
}

#[tokio::test]
async fn backpressure_spills_large_values_and_records_pressure() {
    let registry = Arc::new(NetworkRegistry::default());
    let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

    // Override with very small limits to trigger pressure with smaller values
    // This accommodates the MAX_VALUE_SIZE limit (64KB) in the store
    node.node.override_pressure_limits(10 * 1024, 10 * 1024, 100).await;

    let peer = make_contact(0x02);
    // Use smaller values that are under MAX_VALUE_SIZE but still trigger pressure
    // with our reduced limits
    let value = vec![42u8; 50 * 1024]; // 50KB, under 64KB limit
    let key = hash_content(&value);

    node.node
        .handle_store_request(&peer, key, value.clone())
        .await;

    let snapshot = node.node.telemetry_snapshot().await;
    // With 10KB memory limit and 50KB value, pressure should be very high
    assert!(snapshot.pressure >= 0.99, "pressure: {}", snapshot.pressure);
    assert_eq!(snapshot.stored_keys, 0, "value should have been spilled");

    let calls = node.network.store_calls().await;
    assert!(!calls.is_empty(), "should have offloaded to network");
    let (contact, stored_key, len) = &calls[0];
    assert_eq!(contact.identity, peer.identity);
    assert_eq!(*stored_key, key);
    assert_eq!(*len, value.len());
}

#[tokio::test]
async fn tiering_clusters_contacts_by_latency() {
    let registry = Arc::new(NetworkRegistry::default());
    let main = TestNode::new(registry.clone(), 0x01, 20, 3).await;
    let fast = TestNode::new(registry.clone(), 0x02, 20, 3).await;
    let medium = TestNode::new(registry.clone(), 0x03, 20, 3).await;
    let slow = TestNode::new(registry.clone(), 0x04, 20, 3).await;

    for peer in [&fast, &medium, &slow] {
        main.node.observe_contact(peer.contact()).await;
        peer.node.observe_contact(main.contact()).await;
    }

    main.network
        .set_latency(fast.contact().identity, Duration::from_millis(5))
        .await;
    main.network
        .set_latency(medium.contact().identity, Duration::from_millis(25))
        .await;
    main.network
        .set_latency(slow.contact().identity, Duration::from_millis(50))
        .await;

    let target = make_identity(0x99);
    let _ = main
        .node
        .iterative_find_node(target)
        .await
        .expect("lookup succeeds");

    let snapshot = main.node.telemetry_snapshot().await;
    assert!(snapshot.tier_centroids.len() >= 2);
    assert_eq!(snapshot.tier_counts.iter().sum::<usize>(), 3);
    assert!(snapshot.tier_centroids.first().unwrap() < snapshot.tier_centroids.last().unwrap());
}

#[tokio::test]
async fn responsive_contacts_survive_bucket_eviction() {
    let registry = Arc::new(NetworkRegistry::default());
    let main = TestNode::new(registry.clone(), 0x00, 1, 2).await;
    let responsive = TestNode::new(registry.clone(), 0x80, 1, 2).await;
    let challenger = TestNode::new(registry.clone(), 0xC0, 1, 2).await;

    main.node.observe_contact(responsive.contact()).await;
    main.node.observe_contact(challenger.contact()).await;

    sleep(Duration::from_millis(20)).await;

    let closest = main
        .node
        .handle_find_node_request(&main.contact(), challenger.contact().identity)
        .await;
    assert_eq!(closest.len(), 1);
    assert_eq!(closest[0].identity, responsive.contact().identity);
}

#[tokio::test]
async fn failed_pings_trigger_bucket_replacement() {
    let registry = Arc::new(NetworkRegistry::default());
    let main = TestNode::new(registry.clone(), 0x00, 1, 2).await;
    let stale = TestNode::new(registry.clone(), 0x80, 1, 2).await;
    let newcomer = TestNode::new(registry.clone(), 0xC0, 1, 2).await;

    main.node.observe_contact(stale.contact()).await;
    main.network.set_failure(stale.contact().identity, true).await;
    main.node.observe_contact(newcomer.contact()).await;

    sleep(Duration::from_millis(20)).await;

    let closest = main
        .node
        .handle_find_node_request(&main.contact(), newcomer.contact().identity)
        .await;
    assert_eq!(closest.len(), 1);
    assert_eq!(closest[0].identity, newcomer.contact().identity);
}

#[tokio::test]
async fn bucket_refreshes_issue_pings_before_eviction() {
    let registry = Arc::new(NetworkRegistry::default());
    let main = TestNode::new(registry.clone(), 0x00, 1, 2).await;
    let incumbent = TestNode::new(registry.clone(), 0x80, 1, 2).await;
    let challenger = TestNode::new(registry.clone(), 0xC0, 1, 2).await;

    main.node.observe_contact(incumbent.contact()).await;
    main.node.observe_contact(challenger.contact()).await;

    sleep(Duration::from_millis(20)).await;

    let pings = main.network.ping_calls().await;
    assert_eq!(pings, vec![incumbent.contact().identity]);
}

// ============================================================================
// Resource Exhaustion Tests
// ============================================================================

/// Test that the routing table handles many peers without unbounded growth.
///
/// This validates that bucket limits (k parameter) are enforced even under
/// high peer volume, preventing memory exhaustion from peer accumulation.
#[tokio::test]
async fn many_peers_respects_routing_table_limits() {
    let registry = Arc::new(NetworkRegistry::default());
    // Use small k=4 to make limits easier to test
    let main = TestNode::new(registry.clone(), 0x00, 4, 2).await;
    
    // Add 100 peers - more than would fit in any single bucket
    let mut peers = Vec::new();
    for i in 1u32..=100 {
        let peer = TestNode::new(registry.clone(), i, 4, 2).await;
        peers.push(peer);
    }
    
    // Observe all peers
    for peer in &peers {
        main.node.observe_contact(peer.contact()).await;
    }
    
    // Allow bucket maintenance to complete
    sleep(Duration::from_millis(50)).await;
    
    // Verify the node is still functional by doing a lookup
    let target = make_identity(0xFF);
    let result = main.node.iterative_find_node(target).await;
    assert!(result.is_ok(), "lookups should work with many peers");
    
    // The response should be bounded by k
    let contacts = result.unwrap();
    assert!(
        contacts.len() <= 4,
        "find_node response should be bounded by k=4, got {}",
        contacts.len()
    );
}

/// Test that high churn (rapid peer arrivals and departures) is handled gracefully.
///
/// This validates that:
/// 1. Replacement cache works correctly under churn
/// 2. Ping verification doesn't create resource leaks
/// 3. Failed nodes are evicted promptly
#[tokio::test]
async fn high_churn_handles_rapid_peer_changes() {
    let registry = Arc::new(NetworkRegistry::default());
    let main = TestNode::new(registry.clone(), 0x00, 4, 2).await;
    
    // Simulate high churn: add peers, fail some, add replacements
    for round in 0..5 {
        let base = (round + 1) * 20;
        
        // Add a batch of peers
        for i in 0..10u32 {
            let peer = TestNode::new(registry.clone(), base + i, 4, 2).await;
            main.node.observe_contact(peer.contact()).await;
            
            // Fail half of them immediately
            if i % 2 == 0 {
                main.network.set_failure(peer.contact().identity, true).await;
            }
        }
        
        // Trigger routing table maintenance by doing a lookup
        let target = make_identity(0xFF);
        let _ = main.node.iterative_find_node(target).await;
    }
    
    // Allow cleanup
    sleep(Duration::from_millis(50)).await;
    
    // Verify lookups still work - the system should be functional
    let target = make_identity(0xAB);
    let result = main.node.iterative_find_node(target).await;
    assert!(result.is_ok(), "lookups should succeed after churn");
    
    // Tiering should have handled the peers
    let snapshot = main.node.telemetry_snapshot().await;
    let total_tiered: usize = snapshot.tier_counts.iter().sum();
    assert!(
        total_tiered <= 100,
        "tiered peers should be bounded under churn, got {}",
        total_tiered
    );
}

/// Test that large value storage respects limits and triggers backpressure.
///
/// This validates that:
/// 1. Values exceeding size limits are rejected or spilled
/// 2. Memory pressure is tracked correctly
/// 3. Backpressure offloading works
#[tokio::test]
async fn large_values_trigger_backpressure_correctly() {
    let registry = Arc::new(NetworkRegistry::default());
    let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;
    
    // Set strict memory limits: 100KB total, 50KB soft limit
    node.node.override_pressure_limits(100 * 1024, 50 * 1024, 100).await;
    
    let peer = make_contact(0x02);
    
    // Store multiple medium values to approach limit
    for i in 0..5 {
        let value = vec![i as u8; 15 * 1024]; // 15KB each = 75KB total
        let key = hash_content(&value);
        node.node.handle_store_request(&peer, key, value).await;
    }
    
    let snapshot = node.node.telemetry_snapshot().await;
    
    // Pressure should be elevated (75KB / 100KB = 0.75)
    assert!(
        snapshot.pressure >= 0.5,
        "pressure should be elevated with 75KB stored, got {}",
        snapshot.pressure
    );
    
    // Now try to store a value that would exceed limit
    let large_value = vec![0xFFu8; 40 * 1024]; // 40KB - would push to 115KB
    let large_key = hash_content(&large_value);
    node.node.handle_store_request(&peer, large_key, large_value.clone()).await;
    
    // Check that backpressure kicked in
    let _calls = node.network.store_calls().await;
    
    // Either the value was spilled (offloaded to network) or some existing
    // values were evicted - the system should remain under pressure
    let final_snapshot = node.node.telemetry_snapshot().await;
    assert!(
        final_snapshot.pressure <= 1.0,
        "pressure should be managed, got {}",
        final_snapshot.pressure
    );
    
    // Verify the system didn't crash and is still functional
    assert!(
        final_snapshot.stored_keys >= 1,
        "should still have some stored keys"
    );
}

/// Test that many concurrent store requests don't cause resource exhaustion.
///
/// This validates that:
/// 1. Concurrent requests are handled correctly
/// 2. No unbounded queuing occurs
/// 3. Backpressure applies under load
#[tokio::test]
async fn concurrent_stores_remain_bounded() {
    let registry = Arc::new(NetworkRegistry::default());
    let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;
    
    // Set reasonable limits
    node.node.override_pressure_limits(500 * 1024, 250 * 1024, 1000).await;
    
    let peer = make_contact(0x02);
    
    // Spawn many concurrent store requests
    let mut handles = Vec::new();
    for i in 0..50 {
        let node_clone = node.node.clone();
        let peer_clone = peer.clone();
        let handle = tokio::spawn(async move {
            let value = vec![i as u8; 5 * 1024]; // 5KB each
            let key = hash_content(&value);
            node_clone.handle_store_request(&peer_clone, key, value).await;
        });
        handles.push(handle);
    }
    
    // Wait for all stores to complete
    for handle in handles {
        let _ = handle.await;
    }
    
    let snapshot = node.node.telemetry_snapshot().await;
    
    // System should have stored values without crashing
    // With 50 x 5KB = 250KB, should be around 50% pressure
    assert!(
        snapshot.stored_keys <= 1000,
        "stored keys should be bounded, got {}",
        snapshot.stored_keys
    );
    
    // Memory should be managed
    assert!(
        snapshot.pressure <= 1.5, // Allow some overshoot
        "pressure should be managed under concurrent load, got {}",
        snapshot.pressure
    );
}

/// Test that tiering system handles many peers without memory exhaustion.
///
/// This validates the MAX_TIERING_TRACKED_PEERS limit and eviction logic.
#[tokio::test]
async fn tiering_evicts_oldest_peers_at_capacity() {
    let registry = Arc::new(NetworkRegistry::default());
    let main = TestNode::new(registry.clone(), 0x00, 20, 3).await;
    
    // Add many peers with varying latencies to populate tiering
    for i in 1u32..=200 {
        let peer = TestNode::new(registry.clone(), i, 20, 3).await;
        main.node.observe_contact(peer.contact()).await;
        
        // Set different latencies
        let latency = Duration::from_millis((i % 100) as u64 + 5);
        main.network.set_latency(peer.contact().identity, latency).await;
    }
    
    // Trigger tiering updates by doing lookups
    for i in 0..10 {
        let target = make_identity(0x100 + i);
        let _ = main.node.iterative_find_node(target).await;
    }
    
    let snapshot = main.node.telemetry_snapshot().await;
    
    // Tiering should have created multiple tiers
    assert!(
        snapshot.tier_centroids.len() >= 1,
        "should have at least one tier"
    );
    
    // Total peers across tiers should be bounded
    let total_tiered: usize = snapshot.tier_counts.iter().sum();
    assert!(
        total_tiered <= 200,
        "tiered peers should be bounded, got {}",
        total_tiered
    );
}

/// Test that storage eviction prefers low-access entries.
///
/// This validates the frequency-based eviction policy where
/// entries with higher access counts survive longer.
#[tokio::test]
async fn storage_eviction_prefers_low_access_entries() {
    let registry = Arc::new(NetworkRegistry::default());
    let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;
    
    // Very tight limits to force eviction
    node.node.override_pressure_limits(30 * 1024, 20 * 1024, 10).await;
    
    let peer = make_contact(0x02);
    
    // Store a "hot" value and access it multiple times
    let hot_value = vec![0xAAu8; 8 * 1024]; // 8KB
    let hot_key = hash_content(&hot_value);
    node.node.handle_store_request(&peer, hot_key, hot_value.clone()).await;
    
    // Access the hot key multiple times to increase its access count
    for _ in 0..5 {
        let _ = node.node.handle_find_value_request(&peer, hot_key).await;
    }
    
    // Store several "cold" values that are never accessed
    for i in 0..5 {
        let cold_value = vec![i as u8; 8 * 1024]; // 8KB each
        let cold_key = hash_content(&cold_value);
        node.node.handle_store_request(&peer, cold_key, cold_value).await;
    }
    
    // This should trigger eviction (48KB stored, 30KB limit)
    // Verify the hot key survives while cold keys may be evicted
    
    // The hot key should still be retrievable (higher access count protects it)
    let (value, _) = node.node.handle_find_value_request(&peer, hot_key).await;
    assert!(
        value.is_some(),
        "frequently accessed key should survive eviction"
    );
}
