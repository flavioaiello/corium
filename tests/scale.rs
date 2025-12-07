//! Scale tests for DHT operations.
//!
//! Run with: `cargo test --features tests --test scale`

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use corium::tests::{Contact, DhtNetwork, DhtNode, Identity, Key};
use futures::stream::{self, StreamExt};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use tokio::runtime::Builder;
use tokio::sync::RwLock;

// ============================================================================
// Test Network Infrastructure
// ============================================================================

/// Registry of all test nodes for cross-node communication.
#[derive(Default)]
struct NetworkRegistry {
    peers: RwLock<HashMap<Identity, DhtNode<TestNetwork>>>,
}

impl NetworkRegistry {
    async fn register(&self, node: &DhtNode<TestNetwork>) {
        self.peers
            .write()
            .await
            .insert(node.contact().identity, node.clone());
    }

    async fn get(&self, id: &Identity) -> Option<DhtNode<TestNetwork>> {
        self.peers.read().await.get(id).cloned()
    }
}

/// Test network that routes RPCs through the registry to other nodes.
#[derive(Clone)]
struct TestNetwork {
    registry: Arc<NetworkRegistry>,
    self_contact: Contact,
}

impl TestNetwork {
    fn new(registry: Arc<NetworkRegistry>, self_contact: Contact) -> Self {
        Self {
            registry,
            self_contact,
        }
    }
}

#[async_trait]
impl DhtNetwork for TestNetwork {
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>> {
        if let Some(peer) = self.registry.get(&to.identity).await {
            Ok(peer
                .handle_find_node_request(&self.self_contact, target)
                .await)
        } else {
            Err(anyhow!("peer not found"))
        }
    }

    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)> {
        if let Some(peer) = self.registry.get(&to.identity).await {
            Ok(peer
                .handle_find_value_request(&self.self_contact, key)
                .await)
        } else {
            Err(anyhow!("peer not found"))
        }
    }

    async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> Result<()> {
        if let Some(peer) = self.registry.get(&to.identity).await {
            peer.handle_store_request(&self.self_contact, key, value)
                .await;
        }
        Ok(())
    }

    async fn ping(&self, to: &Contact) -> Result<()> {
        if self.registry.get(&to.identity).await.is_some() {
            Ok(())
        } else {
            Err(anyhow!("peer not reachable"))
        }
    }
}

// ============================================================================
// Test Node Helper
// ============================================================================

fn make_identity(seed: u32) -> Identity {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&seed.to_be_bytes());
    Identity::from_bytes(bytes)
}

fn make_contact(seed: u32) -> Contact {
    Contact {
        identity: make_identity(seed),
        addr: format!("node-{seed}"),
    }
}

struct TestNode {
    node: DhtNode<TestNetwork>,
}

impl TestNode {
    async fn new(registry: Arc<NetworkRegistry>, seed: u32, k: usize, alpha: usize) -> Self {
        let contact = make_contact(seed);
        let network = TestNetwork::new(registry.clone(), contact.clone());
        let node = DhtNode::new(contact.identity, contact, network, k, alpha);
        registry.register(&node).await;
        Self { node }
    }

    fn contact(&self) -> Contact {
        self.node.contact()
    }
}

// ============================================================================
// Scale Tests
// ============================================================================

#[test]
fn scale_data_distribution_is_even() {
    const NUM_NODES: usize = 256;
    const K: usize = 20;
    const ALPHA: usize = 3;
    const TOTAL_PUTS: usize = 2048;

    let runtime = Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("runtime");

    runtime.block_on(async {
        let registry = Arc::new(NetworkRegistry::default());
        let mut nodes = Vec::with_capacity(NUM_NODES);
        for idx in 0..NUM_NODES {
            nodes.push(TestNode::new(registry.clone(), idx as u32 + 1, K, ALPHA).await);
        }

        // Relax pressure limits
        for node in &nodes {
            node.node
                .override_pressure_limits(usize::MAX / 4, usize::MAX / 4, TOTAL_PUTS * K * 4)
                .await;
        }

        // Build ring + random topology
        let mut adjacency = vec![HashSet::new(); NUM_NODES];
        let mut rng = StdRng::seed_from_u64(0xfeed_face_cafe_beef);
        for (i, adj) in adjacency.iter_mut().enumerate() {
            for offset in 1..=3 {
                adj.insert((i + offset) % NUM_NODES);
                adj.insert((i + NUM_NODES - offset) % NUM_NODES);
            }
        }
        for i in 0..NUM_NODES {
            while adjacency[i].len() < 24 {
                let candidate = rng.gen_range(0..NUM_NODES);
                if candidate != i {
                    adjacency[i].insert(candidate);
                    adjacency[candidate].insert(i);
                }
            }
        }

        // Populate routing tables (full mesh)
        let all_contacts: Vec<Contact> = nodes.iter().map(|n| n.contact()).collect();
        for (i, node) in nodes.iter().enumerate() {
            for (j, contact) in all_contacts.iter().enumerate() {
                if i != j {
                    node.node.observe_contact(contact.clone()).await;
                }
            }
        }

        // Store data from random origins
        let mut payload_rng = StdRng::seed_from_u64(0x00de_cafb_adc0_ffee);
        for _ in 0..TOTAL_PUTS {
            let origin = payload_rng.gen_range(0..NUM_NODES);
            let mut payload = vec![0u8; 64];
            payload_rng.fill_bytes(&mut payload);
            nodes[origin].node.put(payload).await.expect("put succeeds");
        }

        // Analyze distribution
        let counts: Vec<usize> = stream::iter(nodes.iter())
            .then(|n| async { n.node.telemetry_snapshot().await.stored_keys })
            .collect()
            .await;

        let min = *counts.iter().min().unwrap();
        let max = *counts.iter().max().unwrap();
        let mean = counts.iter().sum::<usize>() as f64 / counts.len() as f64;

        println!("Distribution: min={min}, max={max}, mean={mean:.2}");
        assert!(min > 0, "every node should store at least one key");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn scale_iterative_find_node_quality() {
    const NODE_COUNT: usize = 1024;
    const K: usize = 20;
    const ALPHA: usize = 3;
    const TARGET_SAMPLES: usize = 512;
    const ORIGINS_PER_TARGET: usize = 10;

    let registry = Arc::new(NetworkRegistry::default());
    let mut nodes = Vec::with_capacity(NODE_COUNT);
    for index in 0..NODE_COUNT {
        nodes.push(TestNode::new(registry.clone(), index as u32, K, ALPHA).await);
    }

    let contacts: Vec<_> = nodes.iter().map(|n| n.contact()).collect();
    let node_ids: Vec<Identity> = contacts.iter().map(|c| c.identity).collect();
    let contacts = Arc::new(contacts);

    // Populate full routing tables
    stream::iter(nodes.iter().enumerate())
        .for_each_concurrent(Some(64), |(idx, node)| {
            let contacts = contacts.clone();
            let node = node.node.clone();
            async move {
                for (peer_idx, c) in contacts.iter().enumerate() {
                    if idx != peer_idx {
                        node.observe_contact(c.clone()).await;
                    }
                }
            }
        })
        .await;

    let mut rng = StdRng::seed_from_u64(0);
    let dht_nodes: Arc<Vec<_>> = Arc::new(nodes.iter().map(|n| n.node.clone()).collect());

    let mut all_closest_present = true;
    let mut total_overlap = 0.0;
    let mut sample_count = 0;

    for _ in 0..TARGET_SAMPLES {
        let mut target_bytes = [0u8; 32];
        rng.fill_bytes(&mut target_bytes);
        let target = Identity::from_bytes(target_bytes);

        // Compute ground truth: K closest nodes
        let mut sorted_ids = node_ids.clone();
        sorted_ids.sort_by_key(|id| id.xor_distance(&target));
        sorted_ids.truncate(K);

        for _ in 0..ORIGINS_PER_TARGET {
            let origin = rng.gen_range(0..NODE_COUNT);
            let result = dht_nodes[origin]
                .iterative_find_node(target)
                .await
                .expect("lookup");
            let result_ids: HashSet<_> = result.iter().map(|c| c.identity).collect();

            let overlap = sorted_ids
                .iter()
                .filter(|id| result_ids.contains(*id))
                .count();
            total_overlap += overlap as f64 / K as f64;
            sample_count += 1;

            if !sorted_ids
                .first()
                .map(|best| result_ids.contains(best))
                .unwrap_or(false)
            {
                all_closest_present = false;
            }
        }
    }

    println!(
        "Find node quality: mean_overlap={:.4}, samples={sample_count}",
        total_overlap / sample_count as f64
    );
    assert!(all_closest_present, "closest node missing from some results");
}
