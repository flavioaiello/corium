use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::seq::IteratorRandom;
use rand::SeedableRng;
use tokio::sync::mpsc;
#[cfg(test)]
use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::identity::Identity;
use crate::messages::{HyParViewMessage, Priority};
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


#[async_trait::async_trait]
pub trait NeighborCallback: Send + Sync {
    async fn neighbor_up(&self, peer: Identity);
    async fn neighbor_down(&self, peer: &Identity);
}


// ============================================================================
// Commands sent from Handle to Actor
// ============================================================================

enum Command {
    SetNeighborCallback(Arc<dyn NeighborCallback>),
    RequestJoin(Identity),
    HandleMessage { from: Identity, message: HyParViewMessage },
    HandlePeerDisconnected(Identity),
    Quit,
    // Test-only queries with response channels
    #[cfg(test)]
    GetActiveView(oneshot::Sender<HashSet<Identity>>),
    #[cfg(test)]
    GetPassiveView(oneshot::Sender<HashSet<Identity>>),
}


// ============================================================================
// HyParView Handle (public API - cheap to clone)
// ============================================================================

#[derive(Clone)]
pub struct HyParView {
    cmd_tx: mpsc::Sender<Command>,
}

impl HyParView {
    /// Spawn a new HyParView actor and return a handle to it.
    /// The actor runs until all handles are dropped.
    pub fn spawn<N: HyParViewRpc + Send + Sync + 'static>(
        me: Identity,
        config: HyParViewConfig,
        network: Arc<N>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        
        let actor = HyParViewActor::new(me, config, network);
        tokio::spawn(actor.run(cmd_rx));
        
        Self { cmd_tx }
    }

    pub async fn set_neighbor_callback(&self, callback: Arc<dyn NeighborCallback>) {
        let _ = self.cmd_tx.send(Command::SetNeighborCallback(callback)).await;
    }

    pub async fn request_join(&self, bootstrap: Identity) {
        let _ = self.cmd_tx.send(Command::RequestJoin(bootstrap)).await;
    }

    pub async fn handle_message(&self, from: Identity, message: HyParViewMessage) {
        let _ = self.cmd_tx.send(Command::HandleMessage { from, message }).await;
    }

    pub async fn handle_peer_disconnected(&self, peer: Identity) {
        let _ = self.cmd_tx.send(Command::HandlePeerDisconnected(peer)).await;
    }

    pub async fn quit(&self) {
        let _ = self.cmd_tx.send(Command::Quit).await;
    }

    /// Query the active view (connected peers). Test-only.
    #[cfg(test)]
    pub async fn active_view(&self) -> HashSet<Identity> {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::GetActiveView(tx)).await.is_err() {
            return HashSet::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Query the passive view (known but not connected peers). Test-only.
    #[cfg(test)]
    pub async fn passive_view(&self) -> HashSet<Identity> {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::GetPassiveView(tx)).await.is_err() {
            return HashSet::new();
        }
        rx.await.unwrap_or_default()
    }
}

struct HyParViewActor<N: HyParViewRpc> {
    me: Identity,
    config: HyParViewConfig,
    network: Arc<N>,
    neighbor_callback: Option<Arc<dyn NeighborCallback>>,
    
    active_view: HashSet<Identity>,
    passive_view: HashSet<Identity>,
    pending_neighbors: HashMap<Identity, Instant>,
    alive_disconnecting: HashSet<Identity>,
    last_shuffle: Instant,
    rng: rand::rngs::StdRng,
}

impl<N: HyParViewRpc + Send + Sync + 'static> HyParViewActor<N> {
    fn new(me: Identity, config: HyParViewConfig, network: Arc<N>) -> Self {
        Self {
            me,
            config,
            network,
            neighbor_callback: None,
            active_view: HashSet::new(),
            passive_view: HashSet::new(),
            pending_neighbors: HashMap::new(),
            alive_disconnecting: HashSet::new(),
            last_shuffle: Instant::now(),
            rng: rand::rngs::StdRng::from_entropy(),
        }
    }

    async fn run(mut self, mut cmd_rx: mpsc::Receiver<Command>) {
        let mut shuffle_interval = tokio::time::interval(self.config.shuffle_interval);
        shuffle_interval.tick().await; // Skip initial tick
        
        loop {
            tokio::select! {
                // Handle commands from handles
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(Command::SetNeighborCallback(cb)) => {
                            self.neighbor_callback = Some(cb);
                        }
                        Some(Command::RequestJoin(bootstrap)) => {
                            self.request_join(bootstrap).await;
                        }
                        Some(Command::HandleMessage { from, message }) => {
                            self.handle_message(from, message).await;
                        }
                        Some(Command::HandlePeerDisconnected(peer)) => {
                            self.handle_peer_disconnected(peer).await;
                        }
                        Some(Command::Quit) => {
                            self.quit().await;
                            break;
                        }
                        #[cfg(test)]
                        Some(Command::GetActiveView(tx)) => {
                            let _ = tx.send(self.active_view.clone());
                        }
                        #[cfg(test)]
                        Some(Command::GetPassiveView(tx)) => {
                            let _ = tx.send(self.passive_view.clone());
                        }
                        None => {
                            // All handles dropped - graceful shutdown
                            self.quit().await;
                            break;
                        }
                    }
                }
                
                // Periodic shuffle
                _ = shuffle_interval.tick() => {
                    self.do_shuffle().await;
                    self.cleanup_stale_pending_neighbors().await;
                }
            }
        }
        
        debug!("HyParView actor shutting down");
    }

    async fn request_join(&mut self, bootstrap: Identity) {
        if bootstrap == self.me {
            return;
        }

        if let Err(e) = self.network.send_hyparview(&bootstrap, self.me, HyParViewMessage::Join).await {
            warn!(peer = %hex::encode(&bootstrap.as_bytes()[..8]), error = %e, "failed to send Join");
            return;
        }

        self.add_to_active(bootstrap, Priority::High, true).await;
    }

    async fn handle_message(&mut self, from: Identity, message: HyParViewMessage) {
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

    async fn handle_peer_disconnected(&mut self, peer: Identity) {
        let removed = self.active_view.remove(&peer);

        if removed {
            let was_alive = self.alive_disconnecting.remove(&peer);

            if was_alive {
                self.add_to_passive(peer).await;
            }

            self.emit_neighbor_down(&peer).await;
            self.try_promote_passive().await;
        }

        self.pending_neighbors.remove(&peer);
    }

    async fn do_shuffle(&mut self) {
        let target = self.active_view.iter().choose(&mut self.rng).copied();

        if let Some(target) = target {
            let peers = self.sample_for_shuffle();

            let msg = HyParViewMessage::Shuffle {
                origin: self.me,
                peers,
                ttl: self.config.forward_join_ttl,
            };

            if let Err(e) = self.network.send_hyparview(&target, self.me, msg).await {
                warn!(peer = %hex::encode(&target.as_bytes()[..8]), error = %e, "failed to send Shuffle");
            }
        }

        self.last_shuffle = Instant::now();
    }

    async fn quit(&mut self) {
        let peers: Vec<Identity> = self.active_view.iter().copied().collect();

        for peer in peers {
            let _ = self.network.send_hyparview(
                &peer,
                self.me,
                HyParViewMessage::Disconnect { alive: false },
            ).await;
        }

        self.active_view.clear();
        self.passive_view.clear();
    }

    async fn on_join(&mut self, from: Identity) {
        debug!(peer = %hex::encode(&from.as_bytes()[..8]), "received Join");

        self.add_to_active(from, Priority::High, true).await;

        let peers: Vec<Identity> = self.active_view.iter()
            .filter(|p| **p != from)
            .copied()
            .collect();

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

    async fn on_forward_join(&mut self, from: Identity, new_peer: Identity, ttl: u8) {
        if new_peer == self.me {
            return;
        }

        if self.active_view.contains(&new_peer) {
            return;
        }

        let active_len = self.active_view.len();

        if ttl == 0 || active_len <= 1 {
            self.add_to_active(new_peer, Priority::Low, true).await;
            return;
        }

        if ttl == self.config.passive_random_walk_length {
            self.add_to_passive(new_peer).await;
        }

        let next = self.active_view.iter()
            .filter(|p| **p != from && **p != new_peer)
            .choose(&mut self.rng)
            .copied();

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

    async fn on_neighbor(&mut self, from: Identity, priority: Priority) {
        let is_full = self.active_view.len() >= self.config.active_view_capacity;

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

    async fn on_neighbor_reply(&mut self, from: Identity, accepted: bool) {
        self.pending_neighbors.remove(&from);

        if accepted {
            if !self.active_view.contains(&from) {
                self.add_to_active_unchecked(from).await;
            }
        } else {
            // If peer was prematurely added to active view (neighbor_up already emitted),
            // we must emit neighbor_down to keep PlumTree in sync
            if self.active_view.remove(&from) {
                self.emit_neighbor_down(&from).await;
                debug!(
                    peer = %hex::encode(&from.as_bytes()[..8]),
                    "neighbor request rejected, removed from active view"
                );
            }
            self.add_to_passive(from).await;
        }
    }

    async fn on_shuffle(&mut self, from: Identity, origin: Identity, peers: Vec<Identity>, ttl: u8) {
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
        
        let active_len = self.active_view.len();

        if ttl == 0 || active_len <= 1 {
            for peer in peers.iter().take(max_shuffle_size) {
                if *peer != self.me {
                    self.add_to_passive(*peer).await;
                }
            }

            let reply_peers = self.sample_for_shuffle();
            let reply = HyParViewMessage::ShuffleReply { peers: reply_peers };
            if let Err(e) = self.network.send_hyparview(&origin, self.me, reply).await {
                warn!(peer = %hex::encode(&origin.as_bytes()[..8]), error = %e, "failed to send ShuffleReply");
            }
        } else {
            let next = self.active_view.iter()
                .filter(|p| **p != from && **p != origin)
                .choose(&mut self.rng)
                .copied();

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

    async fn on_shuffle_reply(&mut self, peers: Vec<Identity>) {
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

    async fn on_disconnect(&mut self, from: Identity, alive: bool) {
        if alive {
            self.alive_disconnecting.insert(from);
        }

        let removed = self.active_view.remove(&from);

        if removed {
            self.emit_neighbor_down(&from).await;

            if alive {
                self.add_to_passive(from).await;
            }

            self.try_promote_passive().await;
        }
    }


    async fn cleanup_stale_pending_neighbors(&mut self) {
        let timeout = self.config.neighbor_timeout;
        let now = Instant::now();
        
        let stale_peers: Vec<Identity> = self.pending_neighbors
            .iter()
            .filter(|(_, inserted_at)| now.duration_since(**inserted_at) > timeout)
            .map(|(peer, _)| *peer)
            .collect();

        for peer in stale_peers {
            self.pending_neighbors.remove(&peer);
            debug!(peer = %hex::encode(&peer.as_bytes()[..8]), "neighbor request timed out");
            self.try_promote_passive().await;
        }
    }

    async fn add_to_passive(&mut self, peer: Identity) -> bool {
        if peer == self.me {
            return false;
        }

        if self.active_view.contains(&peer) {
            return false;
        }

        if self.passive_view.len() >= self.config.passive_view_capacity {
            let evict = self.passive_view.iter().choose(&mut self.rng).copied();
            if let Some(evict) = evict {
                self.passive_view.remove(&evict);
            }
        }

        self.passive_view.insert(peer)
    }

    async fn add_to_active(&mut self, peer: Identity, priority: Priority, send_neighbor: bool) {
        if peer == self.me {
            return;
        }

        if self.active_view.contains(&peer) {
            return;
        }

        let is_full = self.active_view.len() >= self.config.active_view_capacity;

        if is_full {
            if priority == Priority::High {
                let evict = self.active_view.iter().choose(&mut self.rng).copied();
                if let Some(evict) = evict {
                    self.disconnect_peer(evict, true).await;
                }
            } else {
                self.add_to_passive(peer).await;
                return;
            }
        }

        self.passive_view.remove(&peer);
        self.active_view.insert(peer);

        self.emit_neighbor_up(peer).await;

        if send_neighbor {
            self.pending_neighbors.insert(peer, Instant::now());

            let msg = HyParViewMessage::Neighbor { priority };
            if let Err(e) = self.network.send_hyparview(&peer, self.me, msg).await {
                warn!(peer = %hex::encode(&peer.as_bytes()[..8]), error = %e, "failed to send Neighbor");
            }
        }
    }

    async fn add_to_active_unchecked(&mut self, peer: Identity) {
        if peer == self.me {
            return;
        }

        if self.active_view.contains(&peer) {
            return;
        }

        self.passive_view.remove(&peer);
        self.active_view.insert(peer);
        self.emit_neighbor_up(peer).await;
    }

    async fn disconnect_peer(&mut self, peer: Identity, alive: bool) {
        let shuffle_peers = self.sample_for_shuffle();
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

        self.active_view.remove(&peer);
        self.emit_neighbor_down(&peer).await;

        if alive {
            self.add_to_passive(peer).await;
        }
    }

    async fn try_promote_passive(&mut self) {
        let is_full = self.active_view.len() >= self.config.active_view_capacity;

        if is_full {
            return;
        }

        let peer = self.passive_view.iter()
            .filter(|p| !self.alive_disconnecting.contains(*p))
            .choose(&mut self.rng)
            .copied();

        if let Some(peer) = peer {
            self.passive_view.remove(&peer);

            let is_empty = self.active_view.is_empty();
            let priority = if is_empty { Priority::High } else { Priority::Low };

            self.add_to_active(peer, priority, true).await;
        }
    }

    fn sample_for_shuffle(&mut self) -> Vec<Identity> {
        let mut peers = Vec::new();

        for peer in self.active_view.iter().choose_multiple(&mut self.rng, self.config.shuffle_active_count) {
            peers.push(*peer);
        }

        for peer in self.passive_view.iter().choose_multiple(&mut self.rng, self.config.shuffle_passive_count) {
            peers.push(*peer);
        }

        peers.push(self.me);

        peers
    }

    async fn emit_neighbor_up(&self, peer: Identity) {
        debug!(
            peer = %hex::encode(&peer.as_bytes()[..8]),
            active_view_size = self.active_view.len(),
            passive_view_size = self.passive_view.len(),
            "neighbor up"
        );
        if let Some(ref callback) = self.neighbor_callback {
            callback.neighbor_up(peer).await;
        }
    }

    async fn emit_neighbor_down(&self, peer: &Identity) {
        debug!(
            peer = %hex::encode(&peer.as_bytes()[..8]),
            active_view_size = self.active_view.len(),
            passive_view_size = self.passive_view.len(),
            "neighbor down"
        );
        if let Some(ref callback) = self.neighbor_callback {
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
        let hv = HyParView::spawn(me, HyParViewConfig::default(), network.clone());

        let peer1 = make_identity(1);
        hv.handle_message(peer1, HyParViewMessage::Join).await;
        
        // Give actor time to process
        tokio::time::sleep(Duration::from_millis(10)).await;

        let active = hv.active_view().await;
        assert!(active.contains(&peer1));
    }

    #[tokio::test]
    async fn test_neighbor_callback_fired() {
        let me = make_identity(0);
        let network = Arc::new(MockNetwork::new());
        let callback = Arc::new(MockCallback::new());
        
        let hv = HyParView::spawn(me, HyParViewConfig::default(), network.clone());
        hv.set_neighbor_callback(callback.clone()).await;

        let peer1 = make_identity(1);
        hv.handle_message(peer1, HyParViewMessage::Join).await;
        
        // Give actor time to process
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(callback.up_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_disconnect_moves_to_passive() {
        let me = make_identity(0);
        let network = Arc::new(MockNetwork::new());
        let hv = HyParView::spawn(me, HyParViewConfig::default(), network.clone());

        let peer1 = make_identity(1);
        hv.handle_message(peer1, HyParViewMessage::Join).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(hv.active_view().await.contains(&peer1));

        hv.handle_message(peer1, HyParViewMessage::Disconnect { alive: true }).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        assert!(!hv.active_view().await.contains(&peer1));
        assert!(hv.passive_view().await.contains(&peer1));
    }

    #[tokio::test]
    async fn test_graceful_shutdown_on_drop() {
        let me = make_identity(0);
        let network = Arc::new(MockNetwork::new());
        
        {
            let hv = HyParView::spawn(me, HyParViewConfig::default(), network.clone());
            hv.handle_message(make_identity(1), HyParViewMessage::Join).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
            // hv goes out of scope here
        }
        
        // Actor should have exited gracefully
        tokio::time::sleep(Duration::from_millis(50)).await;
        // No assertion needed - test passes if no panic/hang
    }
}
