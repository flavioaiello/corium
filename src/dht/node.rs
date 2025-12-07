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
