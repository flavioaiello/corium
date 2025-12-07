use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::seq::IteratorRandom;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::identity::Identity;
use crate::rpc::HyParViewRpc;


#[derive(Clone, Debug)]
pub struct HyParViewConfig {
    pub active_view_capacity: usize,
    pub passive_view_capacity: usize,
    pub shuffle_active_count: usize,
    pub shuffle_passive_count: usize,
    pub forward_join_ttl: u8,
    pub passive_random_walk_length: u8,
    pub shuffle_interval: Duration,
    pub neighbor_timeout: Duration,
}

impl Default for HyParViewConfig {
    fn default() -> Self {
        Self {
            active_view_capacity: 5,
            passive_view_capacity: 30,
            shuffle_active_count: 3,
            shuffle_passive_count: 4,
            forward_join_ttl: 4,
            passive_random_walk_length: 2,
            shuffle_interval: Duration::from_secs(30),
            neighbor_timeout: Duration::from_secs(5),
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    High,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HyParViewMessage {
    Join,
    ForwardJoin {
        new_peer: Identity,
        ttl: u8,
    },
    Neighbor {
        priority: Priority,
    },
    NeighborReply {
        accepted: bool,
    },
    Shuffle {
        origin: Identity,
        peers: Vec<Identity>,
        ttl: u8,
    },
    ShuffleReply {
        peers: Vec<Identity>,
    },
    Disconnect {
        alive: bool,
    },
}


#[async_trait::async_trait]
pub trait NeighborCallback: Send + Sync {
    async fn neighbor_up(&self, peer: Identity);
    async fn neighbor_down(&self, peer: &Identity);
}


pub struct HyParView<N: HyParViewRpc> {
    me: Identity,
    config: HyParViewConfig,
    network: Arc<N>,
    neighbor_callback: RwLock<Option<Arc<dyn NeighborCallback>>>,
    
    active_view: RwLock<HashSet<Identity>>,
    passive_view: RwLock<HashSet<Identity>>,
    pending_neighbors: RwLock<HashMap<Identity, Instant>>,
    alive_disconnecting: RwLock<HashSet<Identity>>,
    last_shuffle: RwLock<Instant>,
    rng: RwLock<rand::rngs::StdRng>,
}

impl<N: HyParViewRpc + Send + Sync + 'static> HyParView<N> {
    pub fn new(me: Identity, config: HyParViewConfig, network: Arc<N>) -> Self {
        Self {
            me,
            config,
            network,
            neighbor_callback: RwLock::new(None),
            active_view: RwLock::new(HashSet::new()),
            passive_view: RwLock::new(HashSet::new()),
            pending_neighbors: RwLock::new(HashMap::new()),
            alive_disconnecting: RwLock::new(HashSet::new()),
            last_shuffle: RwLock::new(Instant::now()),
            rng: RwLock::new(rand::rngs::StdRng::from_entropy()),
        }
    }

    #[allow(dead_code)]
    pub fn with_neighbor_callback(self, callback: Arc<dyn NeighborCallback>) -> Self {
        Self {
            me: self.me,
            config: self.config,
            network: self.network,
            neighbor_callback: RwLock::new(Some(callback)),
            active_view: self.active_view,
            passive_view: self.passive_view,
            pending_neighbors: self.pending_neighbors,
            alive_disconnecting: self.alive_disconnecting,
            last_shuffle: self.last_shuffle,
            rng: self.rng,
        }
    }

    pub async fn set_neighbor_callback(&self, callback: Arc<dyn NeighborCallback>) {
        *self.neighbor_callback.write().await = Some(callback);
    }

    #[allow(dead_code)]
    pub async fn active_view(&self) -> HashSet<Identity> {
        self.active_view.read().await.clone()
    }

    #[allow(dead_code)]
    pub async fn passive_view(&self) -> HashSet<Identity> {
        self.passive_view.read().await.clone()
    }

    pub async fn request_join(&self, bootstrap: Identity) {
        if bootstrap == self.me {
            return;
        }

        if let Err(e) = self.network.send_hyparview(&bootstrap, self.me, HyParViewMessage::Join).await {
            warn!(peer = %hex::encode(&bootstrap.as_bytes()[..8]), error = %e, "failed to send Join");
            return;
        }

        self.add_to_active(bootstrap, Priority::High, true).await;
    }

    pub async fn handle_message(&self, from: Identity, message: HyParViewMessage) {
        match message {
            HyParViewMessage::Join => self.on_join(from).await,
            HyParViewMessage::ForwardJoin { new_peer, ttl } => {
                self.on_forward_join(from, new_peer, ttl).await;
            }
            HyParViewMessage::Neighbor { priority } => {
                self.on_neighbor(from, priority).await;
            }
            HyParViewMessage::NeighborReply { accepted } => {
                self.on_neighbor_reply(from, accepted).await;
            }
            HyParViewMessage::Shuffle { origin, peers, ttl } => {
                self.on_shuffle(from, origin, peers, ttl).await;
            }
            HyParViewMessage::ShuffleReply { peers } => {
                self.on_shuffle_reply(peers).await;
            }
            HyParViewMessage::Disconnect { alive } => {
                self.on_disconnect(from, alive).await;
            }
        }
    }

    pub async fn handle_peer_disconnected(&self, peer: Identity) {
        let removed = {
            let mut active = self.active_view.write().await;
            active.remove(&peer)
        };

        if removed {
            let was_alive = {
                let mut alive = self.alive_disconnecting.write().await;
                alive.remove(&peer)
            };

            if was_alive {
                self.add_to_passive(peer).await;
            }

            self.emit_neighbor_down(&peer).await;
            self.try_promote_passive().await;
        }

        self.pending_neighbors.write().await.remove(&peer);    }

    pub async fn do_shuffle(&self) {
        let target = {
            let active = self.active_view.read().await;
            let mut rng = self.rng.write().await;
            active.iter().choose(&mut *rng).copied()
        };

        if let Some(target) = target {
            let peers = self.sample_for_shuffle().await;

            let msg = HyParViewMessage::Shuffle {
                origin: self.me,
                peers,
                ttl: self.config.forward_join_ttl,
            };

            if let Err(e) = self.network.send_hyparview(&target, self.me, msg).await {
                warn!(peer = %hex::encode(&target.as_bytes()[..8]), error = %e, "failed to send Shuffle");
            }
        }

        *self.last_shuffle.write().await = Instant::now();
    }

    pub async fn handle_neighbor_timeout(&self, peer: Identity) {
        let was_pending = {
            let mut pending = self.pending_neighbors.write().await;
            pending.remove(&peer).is_some()
        };

        if was_pending {
            debug!(peer = %hex::encode(&peer.as_bytes()[..8]), "neighbor request timed out");
            self.try_promote_passive().await;
        }
    }

    async fn cleanup_stale_pending_neighbors(&self) {
        let timeout = self.config.neighbor_timeout;
        let now = Instant::now();
        
        let stale_peers: Vec<Identity> = {
            let pending = self.pending_neighbors.read().await;
            pending
                .iter()
                .filter(|(_, inserted_at)| now.duration_since(**inserted_at) > timeout)
                .map(|(peer, _)| *peer)
                .collect()
        };

        for peer in stale_peers {
            self.handle_neighbor_timeout(peer).await;
        }
    }

    pub async fn quit(&self) {
        let peers: Vec<Identity> = {
            let active = self.active_view.read().await;
            active.iter().copied().collect()
        };

        for peer in peers {
            let _ = self.network.send_hyparview(
                &peer,
                self.me,
                HyParViewMessage::Disconnect { alive: false },
            ).await;
        }

        self.active_view.write().await.clear();
        self.passive_view.write().await.clear();
    }

    pub fn spawn_shuffle_loop(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(this.config.shuffle_interval);
            interval.tick().await;
            loop {
                interval.tick().await;
                this.do_shuffle().await;
                this.cleanup_stale_pending_neighbors().await;
            }
        })
    }


    async fn on_join(&self, from: Identity) {
        debug!(peer = %hex::encode(&from.as_bytes()[..8]), "received Join");

        self.add_to_active(from, Priority::High, true).await;

        let peers: Vec<Identity> = {
            let active = self.active_view.read().await;
            active.iter().filter(|p| **p != from).copied().collect()
        };

        let msg = HyParViewMessage::ForwardJoin {
            new_peer: from,
            ttl: self.config.forward_join_ttl,
        };

        for peer in peers {
            if let Err(e) = self.network.send_hyparview(&peer, self.me, msg.clone()).await {
                warn!(peer = %hex::encode(&peer.as_bytes()[..8]), error = %e, "failed to forward Join");
            }
        }
    }

    async fn on_forward_join(&self, from: Identity, new_peer: Identity, ttl: u8) {
        if new_peer == self.me {
            return;
        }

        {
            let active = self.active_view.read().await;
            if active.contains(&new_peer) {
                return;
            }
        }

        let active_len = self.active_view.read().await.len();

        if ttl == 0 || active_len <= 1 {
            self.add_to_active(new_peer, Priority::Low, true).await;
            return;
        }

        if ttl == self.config.passive_random_walk_length {
            self.add_to_passive(new_peer).await;
        }

        let next = {
            let active = self.active_view.read().await;
            let mut rng = self.rng.write().await;
            active
                .iter()
                .filter(|p| **p != from && **p != new_peer)
                .choose(&mut *rng)
                .copied()
        };

        if let Some(next) = next {
            let msg = HyParViewMessage::ForwardJoin {
                new_peer,
                ttl: ttl.saturating_sub(1),
            };
            if let Err(e) = self.network.send_hyparview(&next, self.me, msg).await {
                warn!(peer = %hex::encode(&next.as_bytes()[..8]), error = %e, "failed to forward ForwardJoin");
            }
        }
    }

    async fn on_neighbor(&self, from: Identity, priority: Priority) {
        let is_full = {
            let active = self.active_view.read().await;
            active.len() >= self.config.active_view_capacity
        };

        let accepted = if is_full {
            priority == Priority::High
        } else {
            true
        };

        if accepted {
            self.add_to_active_unchecked(from).await;
        }

        let reply = HyParViewMessage::NeighborReply { accepted };
        if let Err(e) = self.network.send_hyparview(&from, self.me, reply).await {
            warn!(peer = %hex::encode(&from.as_bytes()[..8]), error = %e, "failed to send NeighborReply");
        }
    }

    async fn on_neighbor_reply(&self, from: Identity, accepted: bool) {
        self.pending_neighbors.write().await.remove(&from);

        if accepted {
            let already_in = self.active_view.read().await.contains(&from);
            if !already_in {
                self.add_to_active_unchecked(from).await;
            }
        } else {
            self.add_to_passive(from).await;
        }
    }

    async fn on_shuffle(&self, from: Identity, origin: Identity, peers: Vec<Identity>, ttl: u8) {
        let max_shuffle_size = self.config.shuffle_active_count + self.config.shuffle_passive_count + 1;
        if peers.len() > max_shuffle_size {
            warn!(
                from = %hex::encode(&from.as_bytes()[..8]),
                peer_count = peers.len(),
                max = max_shuffle_size,
                "rejecting oversized shuffle message"
            );
            return;
        }
        
        let active_len = self.active_view.read().await.len();

        if ttl == 0 || active_len <= 1 {
            for peer in peers.iter().take(max_shuffle_size) {
                if *peer != self.me {
                    self.add_to_passive(*peer).await;
                }
            }

            let reply_peers = self.sample_for_shuffle().await;
            let reply = HyParViewMessage::ShuffleReply { peers: reply_peers };
            if let Err(e) = self.network.send_hyparview(&origin, self.me, reply).await {
                warn!(peer = %hex::encode(&origin.as_bytes()[..8]), error = %e, "failed to send ShuffleReply");
            }
        } else {
            let next = {
                let active = self.active_view.read().await;
                let mut rng = self.rng.write().await;
                active
                    .iter()
                    .filter(|p| **p != from && **p != origin)
                    .choose(&mut *rng)
                    .copied()
            };

            if let Some(next) = next {
                let msg = HyParViewMessage::Shuffle {
                    origin,
                    peers,
                    ttl: ttl.saturating_sub(1),
                };
                if let Err(e) = self.network.send_hyparview(&next, self.me, msg).await {
                    warn!(peer = %hex::encode(&next.as_bytes()[..8]), error = %e, "failed to forward Shuffle");
                }
            }
        }
    }

    async fn on_shuffle_reply(&self, peers: Vec<Identity>) {
        let max_shuffle_size = self.config.shuffle_active_count + self.config.shuffle_passive_count + 1;
        if peers.len() > max_shuffle_size {
            warn!(
                peer_count = peers.len(),
                max = max_shuffle_size,
                "rejecting oversized shuffle reply"
            );
            return;
        }
        
        for peer in peers.into_iter().take(max_shuffle_size) {
            if peer != self.me {
                self.add_to_passive(peer).await;
            }
        }
    }

    async fn on_disconnect(&self, from: Identity, alive: bool) {
        if alive {
            self.alive_disconnecting.write().await.insert(from);
        }

        let removed = {
            let mut active = self.active_view.write().await;
            active.remove(&from)
        };

        if removed {
            self.emit_neighbor_down(&from).await;

            if alive {
                self.add_to_passive(from).await;
            }

            self.try_promote_passive().await;
        }
    }


    async fn add_to_passive(&self, peer: Identity) -> bool {
        if peer == self.me {
            return false;
        }

        {
            let active = self.active_view.read().await;
            if active.contains(&peer) {
                return false;
            }
        }

        let mut passive = self.passive_view.write().await;
        if passive.len() >= self.config.passive_view_capacity {
            let evict = {
                let mut rng = self.rng.write().await;
                passive.iter().choose(&mut *rng).copied()
            };
            if let Some(evict) = evict {
                passive.remove(&evict);
            }
        }

        passive.insert(peer)
    }

    async fn add_to_active(&self, peer: Identity, priority: Priority, send_neighbor: bool) {
        if peer == self.me {
            return;
        }

        {
            let active = self.active_view.read().await;
            if active.contains(&peer) {
                return;
            }
        }

        let is_full = {
            let active = self.active_view.read().await;
            active.len() >= self.config.active_view_capacity
        };

        if is_full {
            if priority == Priority::High {
                let evict = {
                    let active = self.active_view.read().await;
                    let mut rng = self.rng.write().await;
                    active.iter().choose(&mut *rng).copied()
                };
                if let Some(evict) = evict {
                    self.disconnect_peer(evict, true).await;
                }
            } else {
                self.add_to_passive(peer).await;
                return;
            }
        }

        {
            let mut passive = self.passive_view.write().await;
            passive.remove(&peer);
        }
        {
            let mut active = self.active_view.write().await;
            active.insert(peer);
        }

        self.emit_neighbor_up(peer).await;

        if send_neighbor {
            self.pending_neighbors.write().await.insert(peer, Instant::now());

            let msg = HyParViewMessage::Neighbor { priority };
            if let Err(e) = self.network.send_hyparview(&peer, self.me, msg).await {
                warn!(peer = %hex::encode(&peer.as_bytes()[..8]), error = %e, "failed to send Neighbor");
            }
        }
    }

    async fn add_to_active_unchecked(&self, peer: Identity) {
        if peer == self.me {
            return;
        }

        {
            let active = self.active_view.read().await;
            if active.contains(&peer) {
                return;
            }
        }

        self.passive_view.write().await.remove(&peer);
        self.active_view.write().await.insert(peer);
        self.emit_neighbor_up(peer).await;
    }

    async fn disconnect_peer(&self, peer: Identity, alive: bool) {
        let shuffle_peers = self.sample_for_shuffle().await;
        let _ = self.network.send_hyparview(
            &peer,
            self.me,
            HyParViewMessage::ShuffleReply { peers: shuffle_peers },
        ).await;

        let _ = self.network.send_hyparview(
            &peer,
            self.me,
            HyParViewMessage::Disconnect { alive },
        ).await;

        self.active_view.write().await.remove(&peer);
        self.emit_neighbor_down(&peer).await;

        if alive {
            self.add_to_passive(peer).await;
        }
    }

    async fn try_promote_passive(&self) {
        let is_full = {
            let active = self.active_view.read().await;
            active.len() >= self.config.active_view_capacity
        };

        if is_full {
            return;
        }

        let peer = {
            let passive = self.passive_view.read().await;
            let alive_disconnecting = self.alive_disconnecting.read().await;
            let mut rng = self.rng.write().await;
            passive
                .iter()
                .filter(|p| !alive_disconnecting.contains(*p))
                .choose(&mut *rng)
                .copied()
        };

        if let Some(peer) = peer {
            self.passive_view.write().await.remove(&peer);

            let is_empty = self.active_view.read().await.is_empty();
            let priority = if is_empty { Priority::High } else { Priority::Low };

            self.add_to_active(peer, priority, true).await;
        }
    }

    async fn sample_for_shuffle(&self) -> Vec<Identity> {
        let mut peers = Vec::new();

        {
            let active = self.active_view.read().await;
            let mut rng = self.rng.write().await;
            for peer in active.iter().choose_multiple(&mut *rng, self.config.shuffle_active_count) {
                peers.push(*peer);
            }
        }

        {
            let passive = self.passive_view.read().await;
            let mut rng = self.rng.write().await;
            for peer in passive.iter().choose_multiple(&mut *rng, self.config.shuffle_passive_count) {
                peers.push(*peer);
            }
        }

        peers.push(self.me);

        peers
    }

    async fn emit_neighbor_up(&self, peer: Identity) {
        debug!(peer = %hex::encode(&peer.as_bytes()[..8]), "neighbor up");
        let cb = self.neighbor_callback.read().await;
        if let Some(ref callback) = *cb {
            callback.neighbor_up(peer).await;
        }
    }

    async fn emit_neighbor_down(&self, peer: &Identity) {
        debug!(peer = %hex::encode(&peer.as_bytes()[..8]), "neighbor down");
        let cb = self.neighbor_callback.read().await;
        if let Some(ref callback) = *cb {
            callback.neighbor_down(peer).await;
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;

    fn make_identity(id: u8) -> Identity {
        Identity::from_bytes([id; 32])
    }

    struct MockNetwork {
        sent: Mutex<Vec<(Identity, HyParViewMessage)>>,
    }

    impl MockNetwork {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
            }
        }

        async fn sent_messages(&self) -> Vec<(Identity, HyParViewMessage)> {
            self.sent.lock().await.clone()
        }
    }

    #[async_trait::async_trait]
    impl HyParViewRpc for MockNetwork {
        async fn send_hyparview(
            &self,
            to: &Identity,
            _from: Identity,
            message: HyParViewMessage,
        ) -> anyhow::Result<()> {
            self.sent.lock().await.push((*to, message));
            Ok(())
        }
    }

    struct MockCallback {
        up_count: AtomicUsize,
        down_count: AtomicUsize,
    }

    impl MockCallback {
        fn new() -> Self {
            Self {
                up_count: AtomicUsize::new(0),
                down_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl NeighborCallback for MockCallback {
        async fn neighbor_up(&self, _peer: Identity) {
            self.up_count.fetch_add(1, Ordering::SeqCst);
        }

        async fn neighbor_down(&self, _peer: &Identity) {
            self.down_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn test_join_adds_to_active() {
        let me = make_identity(0);
        let network = Arc::new(MockNetwork::new());
        let hv = HyParView::new(me, HyParViewConfig::default(), network.clone());

        let peer1 = make_identity(1);
        hv.handle_message(peer1, HyParViewMessage::Join).await;

        let active = hv.active_view().await;
        assert!(active.contains(&peer1));
    }

    #[tokio::test]
    async fn test_neighbor_callback_fired() {
        let me = make_identity(0);
        let network = Arc::new(MockNetwork::new());
        let callback = Arc::new(MockCallback::new());
        
        let hv = HyParView::new(me, HyParViewConfig::default(), network.clone());
        hv.set_neighbor_callback(callback.clone()).await;

        let peer1 = make_identity(1);
        hv.handle_message(peer1, HyParViewMessage::Join).await;

        assert_eq!(callback.up_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_disconnect_moves_to_passive() {
        let me = make_identity(0);
        let network = Arc::new(MockNetwork::new());
        let hv = HyParView::new(me, HyParViewConfig::default(), network.clone());

        let peer1 = make_identity(1);
        hv.handle_message(peer1, HyParViewMessage::Join).await;
        assert!(hv.active_view().await.contains(&peer1));

        hv.handle_message(peer1, HyParViewMessage::Disconnect { alive: true }).await;
        
        assert!(!hv.active_view().await.contains(&peer1));
        assert!(hv.passive_view().await.contains(&peer1));
    }

    #[tokio::test]
    async fn mock_network_sent_messages_accessible() {
        let network = MockNetwork::new();
        
        let sent = network.sent_messages().await;
        assert!(sent.is_empty());
    }
}
