#[path = "common/mod.rs"]
mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::{NetworkRegistry, TestNode};
use futures::stream::{self, StreamExt};
use corium::Identity;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use serde::Serialize;
use tokio::sync::Mutex;

const NODE_COUNT: usize = 1024;
const K_PARAM: usize = 20;
const ALPHA_PARAM: usize = 3;
const TARGET_SAMPLES: usize = 512;
const ORIGINS_PER_TARGET: usize = 10;
const ROUTING_TABLE_POPULATION: usize = NODE_COUNT - 1;
const HISTOGRAM_BUCKETS: usize = 10;

#[derive(Debug, Serialize, Clone)]
struct SampleRow {
    origin_index: usize,
    target_index: usize,
    overlap_fraction: f64,
    closest_present: bool,
}

struct TargetSpec {
    index: usize,
    target: Identity,
    perfect_ids: Arc<Vec<Identity>>,
    origins: Vec<usize>,
}

#[derive(Clone)]
struct QuerySpec {
    origin_index: usize,
    target_index: usize,
    target: Identity,
    perfect_ids: Arc<Vec<Identity>>,
}

#[derive(Serialize)]
struct HistogramBucket {
    bucket_start: f64,
    bucket_end: f64,
    count: usize,
}

#[derive(Serialize)]
struct AggregateReport {
    node_count: usize,
    target_samples: usize,
    origins_per_target: usize,
    routing_table_population: usize,
    mean_overlap_fraction: f64,
    median_overlap_fraction: f64,
    histogram: Vec<HistogramBucket>,
    sample_count: usize,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn iterative_find_node_quality_report() {
    let registry = Arc::new(NetworkRegistry::default());
    let mut nodes = Vec::with_capacity(NODE_COUNT);
    for index in 0..NODE_COUNT {
        nodes.push(TestNode::new(registry.clone(), index as u32, K_PARAM, ALPHA_PARAM).await);
    }

    let contacts: Vec<_> = nodes.iter().map(|n| n.contact()).collect();
    let node_ids: Vec<Identity> = contacts.iter().map(|c| c.identity).collect();
    let contacts = Arc::new(contacts);

    stream::iter(nodes.iter().enumerate())
        .for_each_concurrent(Some(64), |(idx, node)| {
            let contacts = contacts.clone();
            let node = node.node.clone();
            async move {
                for (peer_idx, peer_contact) in contacts.iter().enumerate() {
                    if idx == peer_idx {
                        continue;
                    }
                    node.observe_contact(peer_contact.clone()).await;
                }
            }
        })
        .await;

    let mut rng = StdRng::seed_from_u64(0);
    let target_specs = build_target_specs(&mut rng, &node_ids);
    let queries = expand_queries(&target_specs);

    let discovery_nodes: Vec<_> = nodes.iter().map(|n| n.node.clone()).collect();
    let discovery_nodes = Arc::new(discovery_nodes);
    let samples = Arc::new(Mutex::new(Vec::with_capacity(queries.len())));
    let overlaps = Arc::new(Mutex::new(Vec::with_capacity(queries.len())));

    stream::iter(queries)
        .for_each_concurrent(Some(256), |query| {
            let discovery_nodes = discovery_nodes.clone();
            let samples = samples.clone();
            let overlaps = overlaps.clone();
            async move {
                let lookup_result = discovery_nodes[query.origin_index]
                    .iterative_find_node(query.target)
                    .await
                    .expect("iterative lookup succeeds");
                let result_ids: HashSet<Identity> = lookup_result.iter().map(|c| c.identity).collect();
                let overlap = query
                    .perfect_ids
                    .iter()
                    .filter(|id| result_ids.contains(*id))
                    .count();
                let overlap_fraction = overlap as f64 / K_PARAM as f64;
                let closest_present = query
                    .perfect_ids
                    .first()
                    .map(|best| result_ids.contains(best))
                    .unwrap_or(false);

                overlaps.lock().await.push(overlap_fraction);
                samples.lock().await.push(SampleRow {
                    origin_index: query.origin_index,
                    target_index: query.target_index,
                    overlap_fraction,
                    closest_present,
                });
            }
        })
        .await;

    let mut samples = Arc::try_unwrap(samples)
        .expect("samples still referenced")
        .into_inner();
    let overlaps = Arc::try_unwrap(overlaps)
        .expect("overlaps still referenced")
        .into_inner();

    samples.sort_by_key(|row| (row.target_index, row.origin_index));

    let mean_overlap = overlaps.iter().copied().sum::<f64>() / overlaps.len() as f64;

    let median_overlap = {
        let mut sorted = overlaps.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        if sorted.len() % 2 == 1 {
            sorted[sorted.len() / 2]
        } else {
            let upper = sorted.len() / 2;
            (sorted[upper - 1] + sorted[upper]) / 2.0
        }
    };

    let histogram = build_histogram(&overlaps);

    let report = AggregateReport {
        node_count: NODE_COUNT,
        target_samples: TARGET_SAMPLES,
        origins_per_target: ORIGINS_PER_TARGET,
        routing_table_population: ROUTING_TABLE_POPULATION,
        mean_overlap_fraction: mean_overlap,
        median_overlap_fraction: median_overlap,
        histogram,
        sample_count: overlaps.len(),
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );

    println!("origin_index,target_index,overlap_fraction,closest_present");
    for row in &samples {
        println!(
            "{},{},{:.6},{}",
            row.origin_index, row.target_index, row.overlap_fraction, row.closest_present
        );
    }

    assert!(
        samples.iter().all(|row| row.closest_present),
        "closest nodes missing from results"
    );
}

fn perfect_closest(node_ids: &[Identity], target: &Identity) -> Vec<Identity> {
    let mut sorted = node_ids.to_vec();
    sorted.sort_by_key(|a| a.xor_distance(target));
    sorted.truncate(K_PARAM);
    sorted
}

fn random_identity(rng: &mut StdRng) -> Identity {
    let mut id = [0u8; 32];
    rng.fill_bytes(&mut id);
    Identity::from_bytes(id)
}

fn build_histogram(samples: &[f64]) -> Vec<HistogramBucket> {
    let mut buckets = vec![0usize; HISTOGRAM_BUCKETS];
    for &value in samples {
        let mut index = (value * HISTOGRAM_BUCKETS as f64).floor() as usize;
        if index >= HISTOGRAM_BUCKETS {
            index = HISTOGRAM_BUCKETS - 1;
        }
        buckets[index] += 1;
    }

    let bucket_width = 1.0 / HISTOGRAM_BUCKETS as f64;
    buckets
        .into_iter()
        .enumerate()
        .map(|(index, count)| HistogramBucket {
            bucket_start: index as f64 * bucket_width,
            bucket_end: if index == HISTOGRAM_BUCKETS - 1 {
                1.0
            } else {
                (index + 1) as f64 * bucket_width
            },
            count,
        })
        .collect()
}

fn build_target_specs(rng: &mut StdRng, node_ids: &[Identity]) -> Vec<TargetSpec> {
    let mut specs = Vec::with_capacity(TARGET_SAMPLES);
    for index in 0..TARGET_SAMPLES {
        let target = random_identity(rng);
        let perfect_ids = Arc::new(perfect_closest(node_ids, &target));
        let mut origins = Vec::with_capacity(ORIGINS_PER_TARGET);
        for _ in 0..ORIGINS_PER_TARGET {
            origins.push(rng.gen_range(0..NODE_COUNT));
        }
        specs.push(TargetSpec {
            index,
            target,
            perfect_ids,
            origins,
        });
    }
    specs
}

fn expand_queries(targets: &[TargetSpec]) -> Vec<QuerySpec> {
    let mut queries = Vec::with_capacity(TARGET_SAMPLES * ORIGINS_PER_TARGET);
    for target in targets {
        for &origin_index in &target.origins {
            queries.push(QuerySpec {
                origin_index,
                target_index: target.index,
                target: target.target,
                perfect_ids: target.perfect_ids.clone(),
            });
        }
    }
    queries
}
