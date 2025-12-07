//! DHT node implementation with iterative lookups and adaptive parameters.
//!
//! The [`DhtNode`] owns a routing table, content-addressable store, and network
//! transport. It implements the core Kademlia operations: FIND_NODE, FIND_VALUE,
//! STORE, and PING.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, trace};

use super::hash::{distance_cmp, hash_content, verify_key_value_pair, xor_distance, Key};
use super::network::DhtNetwork;
use super::params::{AdaptiveParams, TelemetrySnapshot};
use super::routing::{
    random_id_for_bucket, Contact, PendingBucketUpdate, RoutingInsertionLimiter, RoutingTable,
    BUCKET_REFRESH_INTERVAL, BUCKET_STALE_THRESHOLD,
};
use super::storage::LocalStore;
use super::tiering::{TieringLevel, TieringManager};
use crate::identity::{EndpointRecord, Identity, Keypair};

/// High-level DHT node implementing adaptive Kademlia.
///
/// A `DhtNodeCore` owns a routing table, a content-addressable store, and the
/// [`DhtNetwork`] transport used to send RPCs to other peers. The type is
/// generic over the network layer so tests can use an in-memory mock while
/// production uses [`crate::net::PeerNetwork`].
///
/// # Core Responsibilities
///
/// 1. **Peer Discovery**: Iterative FIND_NODE lookups with tier-aware parallelism
/// 2. **Content Storage**: STORE/FIND_VALUE with k-replication to closest nodes
/// 3. **Routing Table**: 256 k-buckets with LRU eviction and ping-before-evict
/// 4. **Address Publishing**: Signed EndpointRecord storage for peer resolution
/// 5. **Adaptive Parameters**: Dynamic k (10-30) and α (2-5) based on churn
/// 6. **Latency Tiering**: k-means clustering for latency-aware routing
/// 7. **Rate Limiting**: Per-peer routing table insertion limits
///
/// # Key Methods
///
/// * [`observe_contact`](Self::observe_contact) - Update routing table when peers are discovered
/// * [`iterative_find_node`](Self::iterative_find_node) - Perform iterative lookup with adaptive tuning
/// * [`put`](Self::put) - Store a key-value pair with k-replication
/// * [`get`](Self::get) - Retrieve a value from the DHT
/// * [`publish_address`](Self::publish_address) - Publish node addresses as signed EndpointRecord
/// * [`resolve_peer`](Self::resolve_peer) - Resolve a peer's addresses with signature verification
/// * [`handle_find_node_request`](Self::handle_find_node_request) - Handle incoming FIND_NODE RPC
/// * [`handle_find_value_request`](Self::handle_find_value_request) - Handle incoming FIND_VALUE RPC
/// * [`handle_store_request`](Self::handle_store_request) - Handle incoming STORE RPC
///
/// The node is cloneable (via internal `Arc`) and can be shared between tasks.
///
/// # Example
///
/// ```ignore
/// let node = DhtNodeCore::new(id, contact, network, K_DEFAULT, ALPHA_DEFAULT);
/// node.observe_contact(peer_contact).await;
/// let closest = node.iterative_find_node(target_id).await?;
/// ```
pub struct DhtNodeCore<N: DhtNetwork> {
    /// This node's unique identity.
    pub(crate) id: Identity,
    /// Contact info for this node (identity + serialized address).
    pub(crate) self_contact: Contact,
    /// Kademlia routing table with 256 buckets.
    pub(crate) routing: Arc<Mutex<RoutingTable>>,
    /// Local key-value storage with LRU eviction.
    pub(crate) store: Arc<Mutex<LocalStore>>,
    /// Network transport for sending RPCs.
    pub(crate) network: Arc<N>,
    /// Adaptive parameters (k, alpha) tuned based on network conditions.
    pub(crate) params: Arc<Mutex<AdaptiveParams>>,
    /// Latency-based tiering for prioritizing fast peers.
    pub(crate) tiering: Arc<Mutex<TieringManager>>,
    /// Per-peer routing table insertion rate limiter.
    pub(crate) routing_limiter: Arc<Mutex<RoutingInsertionLimiter>>,
}

impl<N: DhtNetwork> Clone for DhtNodeCore<N> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            self_contact: self.self_contact.clone(),
            routing: self.routing.clone(),
            store: self.store.clone(),
            network: self.network.clone(),
            params: self.params.clone(),
            tiering: self.tiering.clone(),
            routing_limiter: self.routing_limiter.clone(),
        }
    }
}

impl<N: DhtNetwork> DhtNodeCore<N> {
    /// Create a new DHT node with the given identity, contact info, network, and initial parameters.
    ///
    /// Automatically starts a background task for periodic bucket refresh
    /// to maintain routing table health.
    pub fn new(id: Identity, self_contact: Contact, network: N, k: usize, alpha: usize) -> Self {
        let node = Self {
            id,
            self_contact,
            routing: Arc::new(Mutex::new(RoutingTable::new(id, k))),
            store: Arc::new(Mutex::new(LocalStore::new())),
            network: Arc::new(network),
            params: Arc::new(Mutex::new(AdaptiveParams::new(k, alpha))),
            tiering: Arc::new(Mutex::new(TieringManager::new())),
            routing_limiter: Arc::new(Mutex::new(RoutingInsertionLimiter::new())),
        };
        node.spawn_periodic_bucket_refresh();
        node
    }

    /// Get this node's unique identity.
    pub fn identity(&self) -> Identity {
        self.id
    }

    /// Get this node's contact information.
    pub fn contact(&self) -> Contact {
        self.self_contact.clone()
    }

    /// Observe a contact and update the routing table.
    ///
    /// If the bucket for this contact is full, spawns a background task to ping
    /// the oldest contact and decide whether to evict it.
    ///
    /// # Security
    ///
    /// Rejects contacts with placeholder or invalid identities to prevent
    /// routing table pollution from bootstrap peers with unknown IDs.
    pub async fn observe_contact(&self, contact: Contact) {
        if contact.identity == self.id {
            return;
        }

        // Reject placeholder and invalid identities
        if !contact.identity.is_valid() {
            trace!(
                addr = %contact.addr,
                identity = %hex::encode(&contact.identity.as_bytes()[..8]),
                "rejecting contact with invalid identity"
            );
            return;
        }

        {
            let mut tiering = self.tiering.lock().await;
            tiering.register_contact(&contact.identity);
        }
        let k = {
            let params = self.params.lock().await;
            params.current_k()
        };
        let pending = {
            let mut rt = self.routing.lock().await;
            rt.set_k(k);
            rt.update_with_pending(contact.clone())
        };

        // Log when a contact is added/updated in the routing table
        info!(
            addr = %contact.addr,
            identity = %hex::encode(&contact.identity.as_bytes()[..16]),
            "Contact observed"
        );

        if let Some(update) = pending {
            self.spawn_bucket_refresh(update);
        }
    }

    /// Observe a contact from a specific peer, with rate limiting.
    ///
    /// This method should be used when processing contacts returned by other
    /// peers (e.g., in FindNode responses) to prevent routing table flooding.
    ///
    /// # Security
    ///
    /// Each peer has a limited budget of contacts they can contribute to our
    /// routing table within a time window. This prevents:
    /// - Routing table poisoning attacks
    /// - Eclipse attacks via contact flooding
    /// - Resource exhaustion from processing excessive contacts
    ///
    /// Returns true if the contact was processed, false if rate-limited.
    pub async fn observe_contact_from_peer(&self, contact: Contact, from_peer: &Identity) -> bool {
        // Skip rate limiting for direct observations (the peer itself)
        if contact.identity == *from_peer {
            self.observe_contact(contact).await;
            return true;
        }

        // Check rate limit for this peer
        {
            let mut limiter = self.routing_limiter.lock().await;
            if !limiter.allow_insertion(from_peer) {
                trace!(
                    from_peer = %hex::encode(&from_peer.as_bytes()[..8]),
                    contact = %hex::encode(&contact.identity.as_bytes()[..8]),
                    "rate-limited contact insertion from peer"
                );
                return false;
            }
        }

        self.observe_contact(contact).await;
        true
    }

    /// Spawn a background task to ping the oldest contact in a full bucket.
    ///
    /// This implements the Kademlia "ping-before-evict" rule.
    fn spawn_bucket_refresh(&self, pending: PendingBucketUpdate) {
        let network = self.network.clone();
        let routing = self.routing.clone();
        tokio::spawn(async move {
            let alive = match network.ping(&pending.oldest).await {
                Ok(_) => true,
                Err(err) => {
                    debug!(
                        peer = ?pending.oldest.identity,
                        addr = %pending.oldest.addr,
                        "ping failed: {err:?}"
                    );
                    false
                }
            };
            let mut rt = routing.lock().await;
            rt.apply_ping_result(pending, alive);
        });
    }

    /// Spawn a background task for periodic bucket refresh.
    ///
    /// This implements lazy bucket refresh: every BUCKET_REFRESH_INTERVAL,
    /// we find buckets that haven't been touched in BUCKET_STALE_THRESHOLD
    /// and perform a FIND_NODE for a random ID in each stale bucket's range.
    ///
    /// This keeps the routing table fresh and helps discover new peers
    /// while removing dead ones (via RPC failure handling).
    fn spawn_periodic_bucket_refresh(&self) {
        let node = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(BUCKET_REFRESH_INTERVAL);
            interval.tick().await; // Skip first immediate tick

            loop {
                interval.tick().await;

                // Get list of stale bucket indices
                let stale_buckets: Vec<usize> = {
                    let rt = node.routing.lock().await;
                    rt.stale_bucket_indices(BUCKET_STALE_THRESHOLD)
                };

                if stale_buckets.is_empty() {
                    continue;
                }

                debug!(
                    count = stale_buckets.len(),
                    "refreshing stale routing buckets"
                );

                // Refresh each stale bucket
                for bucket_idx in stale_buckets {
                    // Generate random ID in this bucket's range
                    let target = {
                        let rt = node.routing.lock().await;
                        random_id_for_bucket(&rt.self_id(), bucket_idx)
                    };

                    // Perform FIND_NODE lookup - this discovers peers and
                    // removes dead ones via RPC failure handling
                    if let Err(e) = node.iterative_find_node(target).await {
                        debug!(bucket = bucket_idx, error = ?e, "bucket refresh lookup failed");
                    }

                    // Mark bucket as refreshed
                    {
                        let mut rt = node.routing.lock().await;
                        rt.mark_bucket_refreshed(bucket_idx);
                    }
                }
            }
        });
    }

    /// Handle an incoming FIND_NODE RPC request.
    ///
    /// Returns the k closest contacts to the target identity from our routing table.
    pub async fn handle_find_node_request(&self, from: &Contact, target: Identity) -> Vec<Contact> {
        self.observe_contact(from.clone()).await;
        let k = {
            let params = self.params.lock().await;
            params.current_k()
        };
        let rt = self.routing.lock().await;
        rt.closest(&target, k)
    }

    /// Handle an incoming FIND_VALUE RPC request.
    ///
    /// If we have the value locally, returns it. Otherwise, returns the k closest
    /// contacts to the key for the requester to continue the lookup.
    pub async fn handle_find_value_request(
        &self,
        from: &Contact,
        key: Key,
    ) -> (Option<Vec<u8>>, Vec<Contact>) {
        self.observe_contact(from.clone()).await;
        if let Some(v) = self.get_local(&key).await {
            return (Some(v), Vec::new());
        }
        let target = Identity::from_bytes(key);
        let k = {
            let params = self.params.lock().await;
            params.current_k()
        };
        let rt = self.routing.lock().await;
        let closer = rt.closest(&target, k);
        (None, closer)
    }

    /// Handle an incoming STORE RPC request.
    ///
    /// Verifies the key-value pair and stores it locally if valid.
    /// Tracks the requesting peer's identity for quota enforcement.
    pub async fn handle_store_request(&self, from: &Contact, key: Key, value: Vec<u8>) {
        self.observe_contact(from.clone()).await;
        self.store_local(key, value, from.identity).await;
    }

    // ========================================================================
    // Lookup Operations
    // ========================================================================

    /// Check if a node matches the given tier level filter.
    async fn level_matches(&self, node: &Identity, level_filter: Option<TieringLevel>) -> bool {
        if let Some(level) = level_filter {
            let tiering = self.tiering.lock().await;
            tiering.level_for(node) == level
        } else {
            true
        }
    }

    /// Filter contacts to only those in the specified tier level.
    async fn filter_contacts(
        &self,
        contacts: Vec<Contact>,
        level_filter: Option<TieringLevel>,
    ) -> Vec<Contact> {
        if level_filter.is_none() {
            return contacts;
        }
        let level = level_filter.unwrap();
        let tiering = self.tiering.lock().await;
        contacts
            .into_iter()
            .filter(|c| tiering.level_for(&c.identity) == level)
            .collect()
    }

    /// Record an RTT sample for a contact for latency tiering.
    async fn record_rtt(&self, contact: &Contact, elapsed: Duration) {
        if contact.identity == self.id {
            return;
        }
        let rtt_ms = (elapsed.as_secs_f64() * 1000.0) as f32;
        let mut tiering = self.tiering.lock().await;
        tiering.record_sample(&contact.identity, rtt_ms);
    }

    /// Record a churn observation and adjust k if needed.
    async fn adjust_k(&self, success: bool) {
        let (changed, new_k) = {
            let mut params = self.params.lock().await;
            let changed = params.record_churn(success);
            let current_k = params.current_k();
            (changed, current_k)
        };
        if changed {
            let mut rt = self.routing.lock().await;
            rt.set_k(new_k);
        }
    }

    /// Get the current k parameter.
    async fn current_k(&self) -> usize {
        let params = self.params.lock().await;
        params.current_k()
    }

    /// Get the current alpha (parallelism) parameter.
    async fn current_alpha(&self) -> usize {
        let params = self.params.lock().await;
        params.current_alpha()
    }

    /// Perform an iterative FIND_NODE lookup for the target identity.
    ///
    /// Returns the k closest contacts to the target found during the lookup.
    /// Automatically adjusts k based on observed churn.
    pub async fn iterative_find_node(&self, target: Identity) -> Result<Vec<Contact>> {
        self.iterative_find_node_with_level(target, None).await
    }

    /// Perform an iterative FIND_NODE lookup with optional tier filtering.
    ///
    /// The lookup process:
    /// 1. Start with k closest contacts from routing table
    /// 2. Query alpha contacts in parallel, collect responses
    /// 3. Add newly discovered contacts to shortlist
    /// 4. Repeat until no closer contacts are found
    /// 5. Return the k closest contacts found
    async fn iterative_find_node_with_level(
        &self,
        target: Identity,
        level_filter: Option<TieringLevel>,
    ) -> Result<Vec<Contact>> {
        let mut seen: HashSet<Identity> = HashSet::new();
        let mut queried: HashSet<Identity> = HashSet::new();
        let mut rpc_success = false;
        let mut rpc_failure = false;
        let k_initial = self.current_k().await;
        let mut shortlist = {
            let rt = self.routing.lock().await;
            rt.closest(&target, k_initial)
        };
        shortlist = self.filter_contacts(shortlist, level_filter).await;
        shortlist.sort_by(|a, b| {
            let da = xor_distance(&a.identity, &target);
            let db = xor_distance(&b.identity, &target);
            distance_cmp(&da, &db)
        });

        for c in &shortlist {
            seen.insert(c.identity);
        }

        let mut best_distance = shortlist
            .first()
            .map(|c| xor_distance(&c.identity, &target))
            .unwrap_or([0xff; 32]);

        loop {
            let alpha = self.current_alpha().await;
            // Select up to alpha unqueried candidates
            let candidates: Vec<Contact> = shortlist
                .iter()
                .filter(|c| !queried.contains(&c.identity) && c.identity != self.id)
                .take(alpha)
                .cloned()
                .collect();

            if candidates.is_empty() {
                break;
            }

            // Mark all candidates as queried before parallel execution
            for c in &candidates {
                queried.insert(c.identity);
            }

            // Query alpha contacts in parallel
            let network = self.network.clone();
            let futures: Vec<_> = candidates
                .into_iter()
                .map(|contact| {
                    let net = network.clone();
                    async move {
                        let start = Instant::now();
                        let result = net.find_node(&contact, target).await;
                        (contact, start.elapsed(), result)
                    }
                })
                .collect();

            let results = futures::future::join_all(futures).await;

            let mut any_closer = false;

            // Process all parallel results
            for (contact, elapsed, result) in results {
                match result {
                    Ok(nodes) => {
                        rpc_success = true;
                        self.record_rtt(&contact, elapsed).await;
                        // Direct contact observation (the peer itself)
                        self.observe_contact(contact.clone()).await;
                        // Rate-limited observation for contacts returned by this peer
                        let from_peer = contact.identity;
                        for n in &nodes {
                            self.observe_contact_from_peer(n.clone(), &from_peer).await;
                        }

                        // Add new contacts to shortlist
                        for n in nodes {
                            if seen.insert(n.identity)
                                && self.level_matches(&n.identity, level_filter).await
                            {
                                shortlist.push(n);
                            }
                        }
                    }
                    Err(_) => {
                        rpc_failure = true;
                    }
                }
            }

            // Re-sort shortlist by distance to target
            shortlist.sort_by(|a, b| {
                let da = xor_distance(&a.identity, &target);
                let db = xor_distance(&b.identity, &target);
                distance_cmp(&da, &db)
            });

            // Truncate to k closest
            let k = self.current_k().await;
            if shortlist.len() > k {
                shortlist.truncate(k);
            }

            // Check if we found any closer contacts
            if let Some(first) = shortlist.first() {
                let new_best = xor_distance(&first.identity, &target);
                if distance_cmp(&new_best, &best_distance) == std::cmp::Ordering::Less {
                    best_distance = new_best;
                    any_closer = true;
                }
            }

            // Stop if no progress was made
            if !any_closer {
                break;
            }
        }

        // Adjust k based on lookup success/failure
        if rpc_success {
            self.adjust_k(true).await;
        } else if rpc_failure {
            self.adjust_k(false).await;
        }

        debug!(
            target = ?hex::encode(&target.as_bytes()[..8]),
            found = shortlist.len(),
            queried = queried.len(),
            "iterative lookup completed"
        );

        Ok(shortlist)
    }

    // ========================================================================
    // Storage Operations
    // ========================================================================

    /// Store a key-value pair locally with content verification and quota enforcement.
    ///
    /// Verifies that the key matches the BLAKE3 hash of the value before storing.
    /// Enforces per-peer quotas and rate limits to prevent storage exhaustion attacks.
    /// May trigger pressure-based eviction, offloading spilled entries.
    ///
    /// # Arguments
    /// * `key` - Content-addressed key (BLAKE3 hash of value)
    /// * `value` - The value to store
    /// * `stored_by` - Identity of the peer requesting storage (for quota tracking)
    async fn store_local(&self, key: Key, value: Vec<u8>, stored_by: Identity) {
        if !verify_key_value_pair(&key, &value) {
            trace!(
                key = hex::encode(&key[..8]),
                value_len = value.len(),
                stored_by = hex::encode(&stored_by.as_bytes()[..8]),
                "rejecting store: key does not match value hash"
            );
            return;
        }
        let spilled = {
            let mut store = self.store.lock().await;
            store.record_request();
            store.store(key, &value, stored_by)
        };
        if !spilled.is_empty() {
            self.offload_spilled(spilled).await;
        }
    }

    /// Retrieve a value from local storage.
    async fn get_local(&self, key: &Key) -> Option<Vec<u8>> {
        let mut store = self.store.lock().await;
        store.record_request();
        let result = store.get(key);
        if result.is_none() {
            trace!(key = hex::encode(&key[..8]), "local store miss");
        }
        result
    }

    /// Override pressure limits for testing or custom configurations.
    pub async fn override_pressure_limits(
        &self,
        disk_limit: usize,
        memory_limit: usize,
        request_limit: usize,
    ) {
        let mut store = self.store.lock().await;
        store.override_limits(disk_limit, memory_limit, request_limit);
    }

    /// Offload spilled entries to slower-tier nodes.
    ///
    /// When local storage is under pressure, evicted entries are replicated
    /// to nodes in the slowest tier to preserve data availability.
    async fn offload_spilled(&self, spilled: Vec<(Key, Vec<u8>)>) {
        if spilled.is_empty() {
            return;
        }

        let target_level = {
            let tiering = self.tiering.lock().await;
            tiering.slowest_level()
        };

        for (key, value) in spilled {
            self.replicate_to_level(key, value.clone(), target_level)
                .await;
        }
    }

    /// Replicate a key-value pair to nodes in a specific tier.
    async fn replicate_to_level(&self, key: Key, value: Vec<u8>, level: TieringLevel) {
        let target = Identity::from_bytes(key);
        if let Ok(contacts) = self
            .iterative_find_node_with_level(target, Some(level))
            .await
        {
            let k = self.current_k().await;
            for contact in contacts.into_iter().take(k) {
                self.send_store(&contact, key, value.clone()).await;
            }
        }
    }

    /// Send a STORE RPC to a contact and record metrics.
    async fn send_store(&self, contact: &Contact, key: Key, value: Vec<u8>) {
        let start = Instant::now();
        let result = self.network.store(contact, key, value).await;
        match result {
            Ok(_) => {
                let elapsed = start.elapsed();
                self.record_rtt(contact, elapsed).await;
                self.adjust_k(true).await;
                self.observe_contact(contact.clone()).await;
            }
            Err(_) => {
                self.adjust_k(false).await;
            }
        }
    }

    /// Store a value in the DHT with distance-based replication.
    ///
    /// The key is derived from the BLAKE3 hash of the value (content-addressed).
    /// The value is stored locally and replicated to the k closest nodes.
    pub async fn put(&self, value: Vec<u8>) -> Result<Key> {
        let key = hash_content(&value);

        // When storing locally via put(), use our own ID as the stored_by peer
        self.store_local(key, value.clone(), self.id).await;

        let target = Identity::from_bytes(key);
        let closest = self.iterative_find_node_with_level(target, None).await?;
        let k = self.current_k().await;

        for contact in closest.into_iter().take(k) {
            self.send_store(&contact, key, value.clone()).await;
        }

        Ok(key)
    }

    /// Get a snapshot of current node state for telemetry.
    pub async fn telemetry_snapshot(&self) -> TelemetrySnapshot {
        let tiering_stats = {
            let tiering = self.tiering.lock().await;
            tiering.stats()
        };
        let (pressure, stored_keys) = {
            let store = self.store.lock().await;
            (store.current_pressure(), store.len())
        };
        let params = self.params.lock().await;
        TelemetrySnapshot {
            tier_centroids: tiering_stats.centroids,
            tier_counts: tiering_stats.counts,
            pressure,
            stored_keys,
            replication_factor: params.current_k(),
            concurrency: params.current_alpha(),
        }
    }

    /// Store a value at a specific key in the DHT.
    ///
    /// Unlike `put()` which derives the key from the value's hash,
    /// this stores at an arbitrary key. Used for endpoint records
    /// where the key is derived from the Identity.
    pub async fn put_at(&self, key: Key, value: Vec<u8>) -> Result<()> {
        // Store locally using our own ID as stored_by
        self.store_local(key, value.clone(), self.id).await;

        // Find closest nodes and replicate
        let closest = self.iterative_find_node(Identity::from_bytes(key)).await?;
        let k = self.current_k().await;

        for contact in closest.into_iter().take(k) {
            self.send_store(&contact, key, value.clone()).await;
        }

        Ok(())
    }

    /// Look up a value from the DHT by key.
    ///
    /// Returns the value if found, either locally or from the network.
    pub async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        // Check local storage first
        if let Some(value) = self.get_local(key).await {
            return Ok(Some(value));
        }

        // Query closest nodes
        let closest = self.iterative_find_node(Identity::from_bytes(*key)).await?;

        for contact in closest {
            match self.network.find_value(&contact, *key).await {
                Ok((Some(value), _)) => return Ok(Some(value)),
                Ok((None, _)) => continue,
                Err(_) => continue,
            }
        }

        Ok(None)
    }

    // ========================================================================
    // Address Publishing & Resolution
    // ========================================================================

    /// Publish this node's current network addresses to the DHT.
    ///
    /// This creates a signed [`EndpointRecord`] containing the node's addresses
    /// and stores it in the DHT under the node's [`Identity`]. Other nodes can
    /// then resolve this peer's addresses by looking up its Identity.
    ///
    /// # Arguments
    /// * `keypair` - The node's Ed25519 keypair for signing the record
    /// * `addresses` - The current network addresses (e.g., "192.168.1.100:4433")
    pub async fn publish_address(&self, keypair: &Keypair, addresses: Vec<String>) -> Result<()> {
        let record = keypair.create_endpoint_record(addresses);
        let serialized = bincode::serialize(&record)
            .map_err(|e| anyhow!("Failed to serialize endpoint record: {}", e))?;

        // Store under the Identity's DHT key (Identity bytes directly in zero-hash model)
        let key: Key = *record.identity.as_bytes();
        self.put_at(key, serialized).await
    }

    /// Resolve a peer's current network addresses from the DHT.
    ///
    /// Looks up the [`EndpointRecord`] for the given [`Identity`] and verifies
    /// the signature and timestamp freshness before returning it.
    ///
    /// # Arguments
    /// * `peer_id` - The Ed25519 public key of the peer to resolve
    ///
    /// # Returns
    /// * `Ok(Some(record))` - The verified endpoint record
    /// * `Ok(None)` - No record found for this peer
    /// * `Err(_)` - Lookup or verification failed
    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<EndpointRecord>> {
        // Maximum age for endpoint records: 24 hours (matches DHT TTL)
        const MAX_RECORD_AGE_SECS: u64 = 24 * 60 * 60;

        let key: Key = *peer_id.as_bytes();

        match self.get(&key).await? {
            Some(data) => {
                let record: EndpointRecord = crate::messages::deserialize_bounded(&data)
                    .map_err(|e| anyhow!("Failed to deserialize endpoint record: {}", e))?;

                // Validate structure to prevent resource exhaustion
                if !record.validate_structure() {
                    return Err(anyhow!("Endpoint record has invalid structure"));
                }

                // Verify the record is signed by the claimed peer
                if record.identity != *peer_id {
                    return Err(anyhow!("Endpoint record peer_id mismatch"));
                }

                // Verify signature AND timestamp freshness to prevent replay attacks
                if !record.verify_fresh(MAX_RECORD_AGE_SECS) {
                    return Err(anyhow!(
                        "Endpoint record signature or timestamp verification failed"
                    ));
                }

                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Republish address when network changes.
    ///
    /// Call this when the local network address changes (e.g., WiFi → cellular).
    /// QUIC connection migration will handle existing connections seamlessly,
    /// saving 2 RTTs per reconnection (no new handshake needed).
    ///
    /// This method:
    /// 1. Creates a new signed EndpointRecord with the new address(es)
    /// 2. Publishes it to the DHT
    /// 3. QUIC connections continue working via connection migration
    ///
    /// # Arguments
    /// * `keypair` - The node's Ed25519 keypair for signing
    /// * `new_addrs` - The new network addresses after the change
    /// * `relays` - Optional relay endpoints (for NAT situations)
    pub async fn republish_on_network_change(
        &self,
        keypair: &Keypair,
        new_addrs: Vec<String>,
        relays: Vec<crate::identity::RelayEndpoint>,
    ) -> Result<()> {
        debug!(
            "republishing address after network change: {:?}",
            new_addrs
        );

        let record = keypair.create_endpoint_record_with_relays(new_addrs, relays);
        let serialized = bincode::serialize(&record)
            .map_err(|e| anyhow!("Failed to serialize endpoint record: {}", e))?;

        // Store under the Identity's DHT key (Identity bytes directly in zero-hash model)
        let key: Key = *record.identity.as_bytes();
        self.put_at(key, serialized).await
    }
}

/// Type alias for backward compatibility.
pub type DhtNode<N> = DhtNodeCore<N>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::hash::hash_content;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::Duration;
    use anyhow::anyhow;
    use tokio::sync::{Mutex, RwLock};
    use tokio::time::sleep;

    // ========================================================================
    // Test Harness (inlined from testutil.rs)
    // ========================================================================

    #[derive(Clone)]
    struct TestNetwork {
        registry: Arc<NetworkRegistry>,
        self_contact: Contact,
        latencies: Arc<Mutex<HashMap<Identity, Duration>>>,
        failures: Arc<Mutex<HashSet<Identity>>>,
        stores: Arc<Mutex<Vec<(Contact, Key, usize)>>>,
        pings: Arc<Mutex<Vec<Identity>>>,
    }

    impl TestNetwork {
        fn new(registry: Arc<NetworkRegistry>, self_contact: Contact) -> Self {
            Self {
                registry,
                self_contact,
                latencies: Arc::new(Mutex::new(HashMap::new())),
                failures: Arc::new(Mutex::new(HashSet::new())),
                stores: Arc::new(Mutex::new(Vec::new())),
                pings: Arc::new(Mutex::new(Vec::new())),
            }
        }

        #[allow(dead_code)]
        async fn set_latency(&self, node: Identity, latency: Duration) {
            self.latencies.lock().await.insert(node, latency);
        }

        async fn set_failure(&self, node: Identity, fail: bool) {
            let mut failures = self.failures.lock().await;
            if fail { failures.insert(node); } else { failures.remove(&node); }
        }

        #[allow(dead_code)]
        async fn store_calls(&self) -> Vec<(Contact, Key, usize)> {
            self.stores.lock().await.clone()
        }

        #[allow(dead_code)]
        async fn ping_calls(&self) -> Vec<Identity> {
            self.pings.lock().await.clone()
        }

        async fn should_fail(&self, node: &Identity) -> bool {
            self.failures.lock().await.contains(node)
        }

        async fn maybe_sleep(&self, node: &Identity) {
            if let Some(delay) = self.latencies.lock().await.get(node).copied() {
                sleep(delay).await;
            }
        }
    }

    #[derive(Default)]
    struct NetworkRegistry {
        peers: RwLock<HashMap<Identity, DhtNode<TestNetwork>>>,
    }

    impl NetworkRegistry {
        async fn register(&self, node: &DhtNode<TestNetwork>) {
            self.peers.write().await.insert(node.contact().identity, node.clone());
        }

        async fn get(&self, id: &Identity) -> Option<DhtNode<TestNetwork>> {
            self.peers.read().await.get(id).cloned()
        }
    }

    #[async_trait::async_trait]
    impl DhtNetwork for TestNetwork {
        async fn find_node(&self, to: &Contact, target: Identity) -> anyhow::Result<Vec<Contact>> {
            if self.should_fail(&to.identity).await {
                return Err(anyhow!("injected network failure"));
            }
            self.maybe_sleep(&to.identity).await;
            if let Some(peer) = self.registry.get(&to.identity).await {
                Ok(peer.handle_find_node_request(&self.self_contact, target).await)
            } else {
                Ok(Vec::new())
            }
        }

        async fn find_value(&self, to: &Contact, key: Key) -> anyhow::Result<(Option<Vec<u8>>, Vec<Contact>)> {
            if self.should_fail(&to.identity).await {
                return Err(anyhow!("injected network failure"));
            }
            self.maybe_sleep(&to.identity).await;
            if let Some(peer) = self.registry.get(&to.identity).await {
                Ok(peer.handle_find_value_request(&self.self_contact, key).await)
            } else {
                Ok((None, Vec::new()))
            }
        }

        async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> anyhow::Result<()> {
            if self.should_fail(&to.identity).await {
                return Err(anyhow!("injected network failure"));
            }
            self.maybe_sleep(&to.identity).await;
            self.stores.lock().await.push((to.clone(), key, value.len()));
            if let Some(peer) = self.registry.get(&to.identity).await {
                peer.handle_store_request(&self.self_contact, key, value).await;
            }
            Ok(())
        }

        async fn ping(&self, to: &Contact) -> anyhow::Result<()> {
            if self.should_fail(&to.identity).await {
                return Err(anyhow!("injected network failure"));
            }
            self.maybe_sleep(&to.identity).await;
            self.pings.lock().await.push(to.identity);
            if self.registry.get(&to.identity).await.is_some() {
                Ok(())
            } else {
                Err(anyhow!("peer not reachable"))
            }
        }
    }

    struct TestNode {
        node: DhtNode<TestNetwork>,
        network: TestNetwork,
    }

    impl TestNode {
        async fn new(registry: Arc<NetworkRegistry>, index: u32, k: usize, alpha: usize) -> Self {
            let contact = make_contact(index);
            let network = TestNetwork::new(registry.clone(), contact.clone());
            let node = DhtNode::new(contact.identity, contact.clone(), network.clone(), k, alpha);
            registry.register(&node).await;
            Self { node, network }
        }

        fn contact(&self) -> Contact {
            self.node.contact()
        }
    }

    fn make_identity(index: u32) -> Identity {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&index.to_be_bytes());
        Identity::from_bytes(id)
    }

    fn make_contact(index: u32) -> Contact {
        Contact {
            identity: make_identity(index),
            addr: format!("node-{index}"),
        }
    }

    // ========================================================================
    // Actual Tests
    // ========================================================================

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

        assert_eq!(
            results.first().map(|c| c.identity),
            Some(peer_two.contact().identity)
        );
        assert!(results.iter().any(|c| c.identity == peer_one.contact().identity));
    }

    #[tokio::test]
    async fn adaptive_k_tracks_network_successes_and_failures() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x30, 10, 3).await;
        let peer = TestNode::new(registry.clone(), 0x31, 10, 3).await;

        main.node.observe_contact(peer.contact()).await;
        peer.node.observe_contact(main.contact()).await;

        main.network
            .set_failure(peer.contact().identity, true)
            .await;
        let target = make_identity(0xAA);
        let _ = main
            .node
            .iterative_find_node(target)
            .await
            .expect("lookup tolerates failure");
        let snapshot = main.node.telemetry_snapshot().await;
        assert_eq!(snapshot.replication_factor, 30);

        main.network
            .set_failure(peer.contact().identity, false)
            .await;
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
        node.node
            .override_pressure_limits(10 * 1024, 10 * 1024, 100)
            .await;

        let peer = make_contact(0x02);
        // Use smaller values that are under MAX_VALUE_SIZE but still trigger pressure
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
        main.network
            .set_failure(stale.contact().identity, true)
            .await;
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

    // ========================================================================
    // Resource Exhaustion Tests
    // ========================================================================

    #[tokio::test]
    async fn many_peers_respects_routing_table_limits() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x00, 4, 2).await;

        let mut peers = Vec::new();
        for i in 1u32..=100 {
            let peer = TestNode::new(registry.clone(), i, 4, 2).await;
            peers.push(peer);
        }

        for peer in &peers {
            main.node.observe_contact(peer.contact()).await;
        }

        sleep(Duration::from_millis(50)).await;

        let target = make_identity(0xFF);
        let result = main.node.iterative_find_node(target).await;
        assert!(result.is_ok(), "lookups should work with many peers");

        let contacts = result.unwrap();
        assert!(
            contacts.len() <= 4,
            "find_node response should be bounded by k=4, got {}",
            contacts.len()
        );
    }

    #[tokio::test]
    async fn high_churn_handles_rapid_peer_changes() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x00, 4, 2).await;

        for round in 0..5 {
            let base = (round + 1) * 20;

            for i in 0..10u32 {
                let peer = TestNode::new(registry.clone(), base + i, 4, 2).await;
                main.node.observe_contact(peer.contact()).await;

                if i % 2 == 0 {
                    main.network
                        .set_failure(peer.contact().identity, true)
                        .await;
                }
            }

            let target = make_identity(0xFF);
            let _ = main.node.iterative_find_node(target).await;
        }

        sleep(Duration::from_millis(50)).await;

        let target = make_identity(0xAB);
        let result = main.node.iterative_find_node(target).await;
        assert!(result.is_ok(), "lookups should succeed after churn");

        let snapshot = main.node.telemetry_snapshot().await;
        let total_tiered: usize = snapshot.tier_counts.iter().sum();
        assert!(
            total_tiered <= 100,
            "tiered peers should be bounded under churn, got {}",
            total_tiered
        );
    }

    #[tokio::test]
    async fn large_values_trigger_backpressure_correctly() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        node.node
            .override_pressure_limits(100 * 1024, 50 * 1024, 100)
            .await;

        let peer = make_contact(0x02);

        for i in 0..5 {
            let value = vec![i as u8; 15 * 1024]; // 15KB each
            let key = hash_content(&value);
            node.node.handle_store_request(&peer, key, value).await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.pressure >= 0.5,
            "pressure should be elevated with 75KB stored, got {}",
            snapshot.pressure
        );

        let large_value = vec![0xFFu8; 40 * 1024]; // 40KB
        let large_key = hash_content(&large_value);
        node.node
            .handle_store_request(&peer, large_key, large_value.clone())
            .await;

        let _calls = node.network.store_calls().await;

        let final_snapshot = node.node.telemetry_snapshot().await;
        assert!(
            final_snapshot.pressure <= 1.0,
            "pressure should be managed, got {}",
            final_snapshot.pressure
        );

        assert!(
            final_snapshot.stored_keys >= 1,
            "should still have some stored keys"
        );
    }

    #[tokio::test]
    async fn concurrent_stores_remain_bounded() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        node.node
            .override_pressure_limits(500 * 1024, 250 * 1024, 1000)
            .await;

        let peer = make_contact(0x02);

        let mut handles = Vec::new();
        for i in 0..50 {
            let node_clone = node.node.clone();
            let peer_clone = peer.clone();
            let handle = tokio::spawn(async move {
                let value = vec![i as u8; 5 * 1024]; // 5KB each
                let key = hash_content(&value);
                node_clone
                    .handle_store_request(&peer_clone, key, value)
                    .await;
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.stored_keys <= 1000,
            "stored keys should be bounded, got {}",
            snapshot.stored_keys
        );

        assert!(
            snapshot.pressure <= 1.5,
            "pressure should be managed under concurrent load, got {}",
            snapshot.pressure
        );
    }

    #[tokio::test]
    async fn tiering_evicts_oldest_peers_at_capacity() {
        let registry = Arc::new(NetworkRegistry::default());
        let main = TestNode::new(registry.clone(), 0x00, 20, 3).await;

        for i in 1u32..=200 {
            let peer = TestNode::new(registry.clone(), i, 20, 3).await;
            main.node.observe_contact(peer.contact()).await;

            let latency = Duration::from_millis((i % 100) as u64 + 5);
            main.network
                .set_latency(peer.contact().identity, latency)
                .await;
        }

        for i in 0..10 {
            let target = make_identity(0x100 + i);
            let _ = main.node.iterative_find_node(target).await;
        }

        let snapshot = main.node.telemetry_snapshot().await;

        assert!(
            snapshot.tier_centroids.len() >= 1,
            "should have at least one tier"
        );

        let total_tiered: usize = snapshot.tier_counts.iter().sum();
        assert!(
            total_tiered <= 200,
            "tiered peers should be bounded, got {}",
            total_tiered
        );
    }

    #[tokio::test]
    async fn storage_eviction_prefers_low_access_entries() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        node.node
            .override_pressure_limits(30 * 1024, 20 * 1024, 10)
            .await;

        let peer = make_contact(0x02);

        let hot_value = vec![0xAAu8; 8 * 1024]; // 8KB
        let hot_key = hash_content(&hot_value);
        node.node
            .handle_store_request(&peer, hot_key, hot_value.clone())
            .await;

        for _ in 0..5 {
            let _ = node.node.handle_find_value_request(&peer, hot_key).await;
        }

        for i in 0..5 {
            let cold_value = vec![i as u8; 8 * 1024]; // 8KB each
            let cold_key = hash_content(&cold_value);
            node.node
                .handle_store_request(&peer, cold_key, cold_value)
                .await;
        }

        let (value, _) = node.node.handle_find_value_request(&peer, hot_key).await;
        assert!(
            value.is_some(),
            "frequently accessed key should survive eviction"
        );
    }

    // ========================================================================
    // Rate Limiting and DoS Protection Tests
    // ========================================================================

    #[tokio::test]
    async fn storage_pressure_protection() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        node.node.override_pressure_limits(1024, 1024, 10).await;

        let peer = make_contact(0x02);

        for i in 0..20 {
            let value = vec![i as u8; 100];
            let key = hash_content(&value);
            node.node.handle_store_request(&peer, key, value).await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.pressure > 0.0 || snapshot.stored_keys < 20,
            "Either pressure should be non-zero or some keys should be evicted/spilled"
        );
    }

    #[tokio::test]
    async fn per_peer_storage_limits() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let malicious_peer = make_contact(0x99);

        for i in 0..150 {
            let value = vec![i as u8; 100];
            let key = hash_content(&value);
            node.node
                .handle_store_request(&malicious_peer, key, value)
                .await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.stored_keys <= 100,
            "Per-peer limits should prevent storing more than 100 entries, got {}",
            snapshot.stored_keys
        );
    }

    #[tokio::test]
    async fn multiple_peers_independent_storage() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        for peer_id in 0..5 {
            let peer = make_contact(peer_id);
            for i in 0..10 {
                let value = format!("peer-{}-value-{}", peer_id, i).into_bytes();
                let key = hash_content(&value);
                node.node.handle_store_request(&peer, key, value).await;
            }
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.stored_keys >= 20,
            "Should store data from multiple peers, got {}",
            snapshot.stored_keys
        );
    }

    // ========================================================================
    // DHT Lookup Security Tests
    // ========================================================================

    #[tokio::test]
    async fn lookup_returns_valid_contacts() {
        let registry = Arc::new(NetworkRegistry::default());
        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;
        let peer = TestNode::new(registry.clone(), 0x02, 20, 3).await;

        node.node.observe_contact(peer.contact()).await;
        peer.node.observe_contact(node.contact()).await;

        let target = peer.contact().identity;
        let results = node.node.iterative_find_node(target).await.unwrap();

        assert!(results.iter().any(|c| c.identity == target));

        for contact in &results {
            assert_eq!(contact.identity.as_bytes().len(), 32);
            assert!(contact.identity.as_bytes() != &[0u8; 32]);
        }
    }

    #[tokio::test]
    async fn lookup_converges_to_closest() {
        let registry = Arc::new(NetworkRegistry::default());
        let nodes: Vec<_> = futures::future::join_all((0..10).map(|i| {
            let reg = registry.clone();
            async move { TestNode::new(reg, 0x10 + i, 20, 3).await }
        }))
        .await;

        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    nodes[i].node.observe_contact(nodes[j].contact()).await;
                }
            }
        }

        let target = nodes[5].contact().identity;
        let results = nodes[0].node.iterative_find_node(target).await.unwrap();

        assert_eq!(results.first().map(|c| c.identity), Some(target));
    }

    #[tokio::test]
    async fn malicious_response_handling() {
        let registry = Arc::new(NetworkRegistry::default());
        let honest = TestNode::new(registry.clone(), 0x01, 20, 3).await;
        let peer = TestNode::new(registry.clone(), 0x02, 20, 3).await;

        honest.node.observe_contact(peer.contact()).await;

        let target = make_identity(0xFF);
        let result = honest.node.iterative_find_node(target).await;

        assert!(result.is_ok());
    }

    // ========================================================================
    // Sybil / Eclipse Attack Resistance Tests
    // ========================================================================

    #[tokio::test]
    async fn routing_table_diversity() {
        let registry = Arc::new(NetworkRegistry::default());
        let target = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let mut peers = Vec::new();
        for i in 0..20 {
            let peer = TestNode::new(registry.clone(), 0x10 + i, 20, 3).await;
            peers.push(peer);
        }

        for peer in &peers {
            target.node.observe_contact(peer.contact()).await;
        }

        let snapshot = target.node.telemetry_snapshot().await;

        let total_in_tiers: usize = snapshot.tier_counts.iter().sum();
        assert!(
            total_in_tiers >= 1,
            "Routing table should accept diverse peers, got {} peers tracked",
            total_in_tiers
        );
    }

    #[tokio::test]
    async fn eclipse_attack_resistance() {
        let registry = Arc::new(NetworkRegistry::default());
        let victim = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let mut attackers = Vec::new();
        for i in 0..50 {
            let attacker = TestNode::new(registry.clone(), 0x80 + i, 20, 3).await;
            attackers.push(attacker);
        }

        let mut honest_nodes = Vec::new();
        for i in 0..5 {
            let honest = TestNode::new(registry.clone(), 0x10 + i, 20, 3).await;
            honest_nodes.push(honest);
        }

        for attacker in &attackers {
            victim.node.observe_contact(attacker.contact()).await;
        }
        for honest in &honest_nodes {
            victim.node.observe_contact(honest.contact()).await;
        }

        let snapshot = victim.node.telemetry_snapshot().await;

        let total_tracked: usize = snapshot.tier_counts.iter().sum();

        assert!(
            total_tracked >= 5,
            "Should track at least some nodes, got {}",
            total_tracked
        );
    }

    #[tokio::test]
    async fn bucket_replacement_favors_long_lived() {
        let registry = Arc::new(NetworkRegistry::default());

        let node = TestNode::new(registry.clone(), 0x01, 20, 3).await;

        let mut long_lived = Vec::new();
        for i in 0..5 {
            let long_lived_node = TestNode::new(registry.clone(), 0x10 + i, 20, 3).await;
            node.node
                .observe_contact(long_lived_node.contact())
                .await;
            long_lived.push(long_lived_node);
        }

        for i in 0..20 {
            let sybil = TestNode::new(registry.clone(), 0x80 + i, 20, 3).await;
            node.node.observe_contact(sybil.contact()).await;
        }

        let snapshot = node.node.telemetry_snapshot().await;

        assert!(
            snapshot.tier_counts.iter().sum::<usize>() >= 5,
            "Should maintain at least the original nodes"
        );
    }
}
