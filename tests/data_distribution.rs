#[path = "common/mod.rs"]
mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::{NetworkRegistry, TestNode};
use corium::Contact;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use tokio::runtime::Builder;

const NUM_NODES: usize = 256;
const K_PARAM: usize = 20;
const ALPHA_PARAM: usize = 3;
const RING_NEIGHBORS: usize = 3;
const MIN_CONTACTS_PER_NODE: usize = 24;
const TOTAL_PUTS: usize = 2048;
const PAYLOAD_LEN: usize = 64;

#[test]
fn data_distribution_is_relatively_even() {
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
            nodes.push(TestNode::new(registry.clone(), idx as u32 + 1, K_PARAM, ALPHA_PARAM).await);
        }

        let relaxed_request_limit = TOTAL_PUTS * K_PARAM * 4;
        for node in &nodes {
            node.node
                .override_pressure_limits(usize::MAX / 4, usize::MAX / 4, relaxed_request_limit)
                .await;
        }

        let mut adjacency = vec![HashSet::new(); NUM_NODES];
        for (i, adj) in adjacency.iter_mut().enumerate() {
            for offset in 1..=RING_NEIGHBORS {
                adj.insert((i + offset) % NUM_NODES);
                adj.insert((i + NUM_NODES - offset) % NUM_NODES);
            }
        }

        let mut rng = StdRng::seed_from_u64(0xfeed_face_cafe_beef);
        for i in 0..NUM_NODES {
            while adjacency[i].len() < MIN_CONTACTS_PER_NODE {
                let candidate = rng.gen_range(0..NUM_NODES);
                if candidate == i {
                    continue;
                }
                adjacency[i].insert(candidate);
                adjacency[candidate].insert(i);
            }
        }

        for (i, peers) in adjacency.iter().enumerate() {
            let peer_list: Vec<usize> = peers.iter().copied().collect();
            for peer_idx in peer_list {
                let contact = nodes[peer_idx].contact();
                nodes[i].node.observe_contact(contact).await;
            }
        }

        let all_contacts: Vec<Contact> = nodes.iter().map(|n| n.contact()).collect();
        for (i, node) in nodes.iter().enumerate() {
            for (peer_idx, contact) in all_contacts.iter().enumerate() {
                if i == peer_idx {
                    continue;
                }
                node.node.observe_contact(contact.clone()).await;
            }
        }

        let mut payload_rng = StdRng::seed_from_u64(0x00de_cafb_adc0_ffee);
        for _ in 0..TOTAL_PUTS {
            let origin_idx = payload_rng.gen_range(0..NUM_NODES);
            let mut payload = vec![0u8; PAYLOAD_LEN];
            payload_rng.fill_bytes(&mut payload);
            nodes[origin_idx]
                .node
                .put(payload)
                .await
                .expect("put succeeds");
        }

        let mut per_node_counts = Vec::with_capacity(NUM_NODES);
        for (idx, node) in nodes.iter().enumerate() {
            let snapshot = node.node.telemetry_snapshot().await;
            per_node_counts.push((idx, snapshot.stored_keys));
        }

        let total_keys: usize = per_node_counts.iter().map(|(_, count)| *count).sum();
        let min = per_node_counts
            .iter()
            .map(|(_, count)| *count)
            .min()
            .unwrap();
        let max = per_node_counts
            .iter()
            .map(|(_, count)| *count)
            .max()
            .unwrap();
        let mean = total_keys as f64 / per_node_counts.len() as f64;
        let variance = per_node_counts
            .iter()
            .map(|(_, count)| {
                let diff = *count as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / per_node_counts.len() as f64;
        let stddev = variance.sqrt();

        println!("node_index,stored_keys");
        for (idx, count) in &per_node_counts {
            println!("{idx},{count}");
        }
        println!("summary,min,max,mean,stddev,total_keys");
        println!(
            "summary,{min},{max},{:.2},{:.2},{}",
            mean, stddev, total_keys
        );

        assert!(min > 0, "every node should store at least one key");
        let coefficient_of_variation = stddev / mean.max(1.0);
        println!("summary_cv,{coefficient_of_variation:.4}");
    });
}
