use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock as StdRwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use quinn::{AsyncUdpSocket, UdpPoller};
use quinn::udp::{RecvMeta, Transmit};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

use crate::identity::Identity;
use crate::relay::{Relay, RelayTunnel, RELAY_MAGIC, MAX_RELAY_FRAME_SIZE};


/// Callback trait for path change notifications.
/// Implementors receive notifications when SmartSock detects better paths to peers.
#[async_trait::async_trait]
pub trait PathEventHandler: Send + Sync {
    /// Called when a better path to a peer is discovered and activated.
    async fn on_path_improved(&self, peer: Identity, new_path: PathChoice);
    
    /// Called when a peer becomes unreachable (all paths failed).
    async fn on_peer_unreachable(&self, peer: Identity);
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub identity: Identity,
    pub addrs: Vec<String>,
}

impl Contact {
    pub fn single(identity: Identity, addr: impl Into<String>) -> Self {
        Self {
            identity,
            addrs: vec![addr.into()],
        }
    }
    
    /// Get the primary address (first in the list).
    pub fn primary_addr(&self) -> Option<&str> {
        self.addrs.first().map(|s| s.as_str())
    }

    pub fn all_addrs(&self) -> impl Iterator<Item = &str> {
        self.addrs.iter().map(|s| s.as_str())
    }
}

impl PartialEq for Contact {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl Eq for Contact {}

impl Hash for Contact {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
    }
}


// Transport-specific constants (relay constants are in relay.rs)
pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_SMARTSOCK_PEERS: usize = 10_000;

pub const PROBE_MAGIC: [u8; 4] = *b"SMPR";
pub const PROBE_TYPE_REQUEST: u8 = 0x01;
pub const PROBE_TYPE_RESPONSE: u8 = 0x02;
pub const PROBE_HEADER_SIZE: usize = 21;
pub const PATH_PROBE_INTERVAL: Duration = Duration::from_secs(5);
pub const PATH_STALE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_PROBE_FAILURES: u32 = 3;
/// Relay tunnels are cleaned up if idle longer than this.
/// Matches the server-side SESSION_TIMEOUT in relay.rs.
const RELAY_TUNNEL_STALE_TIMEOUT: Duration = Duration::from_secs(300);
const RELAY_RTT_ADVANTAGE_MS: f32 = 50.0;
const RTT_EMA_OLD: f32 = 0.8;
const RTT_EMA_NEW: f32 = 0.2;

const MAX_PENDING_PROBES_PER_PEER: usize = 64;
const MAX_CANDIDATES_PER_PEER: usize = 24;
const MAX_DIRECT_ADDRS_PER_PEER: usize = 16;

#[derive(Debug, Clone)]
pub struct PathProbeRequest {
    pub tx_id: u64,
    pub timestamp_ms: u64,
}

impl PathProbeRequest {
    pub fn new(tx_id: u64) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self { tx_id, timestamp_ms }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PROBE_HEADER_SIZE);
        buf.extend_from_slice(&PROBE_MAGIC);
        buf.push(PROBE_TYPE_REQUEST);
        buf.extend_from_slice(&self.tx_id.to_le_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf
    }
    
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < PROBE_HEADER_SIZE {
            return None;
        }
        if data[0..4] != PROBE_MAGIC || data[4] != PROBE_TYPE_REQUEST {
            return None;
        }
        Some(Self {
            tx_id: u64::from_le_bytes(data[5..13].try_into().ok()?),
            timestamp_ms: u64::from_le_bytes(data[13..21].try_into().ok()?),
        })
    }
    
    pub fn is_probe_request(data: &[u8]) -> bool {
        data.len() >= 5 && data[0..4] == PROBE_MAGIC && data[4] == PROBE_TYPE_REQUEST
    }
}

#[derive(Debug, Clone)]
pub struct PathProbeResponse {
    pub tx_id: u64,
    pub echo_timestamp_ms: u64,
    pub observed_addr: SocketAddr,
}

impl PathProbeResponse {
    pub fn from_request(req: &PathProbeRequest, observed_addr: SocketAddr) -> Self {
        Self {
            tx_id: req.tx_id,
            echo_timestamp_ms: req.timestamp_ms,
            observed_addr,
        }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&PROBE_MAGIC);
        buf.push(PROBE_TYPE_RESPONSE);
        buf.extend_from_slice(&self.tx_id.to_le_bytes());
        buf.extend_from_slice(&self.echo_timestamp_ms.to_le_bytes());
        
        match self.observed_addr {
            SocketAddr::V4(addr) => {
                buf.push(4);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_le_bytes());
            }
            SocketAddr::V6(addr) => {
                buf.push(6);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_le_bytes());
            }
        }
        buf
    }
    
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < PROBE_HEADER_SIZE + 1 {
            return None;
        }
        if data[0..4] != PROBE_MAGIC || data[4] != PROBE_TYPE_RESPONSE {
            return None;
        }
        
        let tx_id = u64::from_le_bytes(data[5..13].try_into().ok()?);
        let echo_timestamp_ms = u64::from_le_bytes(data[13..21].try_into().ok()?);
        
        let addr_type = data[21];
        let observed_addr = match addr_type {
            4 if data.len() >= 28 => {
                let ip = Ipv4Addr::new(data[22], data[23], data[24], data[25]);
                let port = u16::from_le_bytes(data[26..28].try_into().ok()?);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            6 if data.len() >= 40 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[22..38]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_le_bytes(data[38..40].try_into().ok()?);
                SocketAddr::new(IpAddr::V6(ip), port)
            }
            _ => return None,
        };
        
        Some(Self { tx_id, echo_timestamp_ms, observed_addr })
    }
    
    pub fn is_probe_response(data: &[u8]) -> bool {
        data.len() >= 5 && data[0..4] == PROBE_MAGIC && data[4] == PROBE_TYPE_RESPONSE
    }
    
    pub fn rtt_ms(&self) -> f32 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        (now_ms.saturating_sub(self.echo_timestamp_ms)) as f32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCandidateState {
    Unknown,
    Probing,
    Active,
    Failed,
}

#[derive(Debug, Clone)]
pub struct PathCandidateInfo {
    pub addr: SocketAddr,
    pub is_relay: bool,
    pub session_id: Option<[u8; 16]>,
    pub state: PathCandidateState,
    pub rtt_ms: Option<f32>,
    pub last_success: Option<Instant>,
    pub last_probe: Option<Instant>,
    pub failures: u32,
    pub probe_seq: u64,
}

impl PathCandidateInfo {
    pub fn new_direct(addr: SocketAddr) -> Self {
        Self {
            addr,
            is_relay: false,
            session_id: None,
            state: PathCandidateState::Unknown,
            rtt_ms: None,
            last_success: None,
            last_probe: None,
            failures: 0,
            probe_seq: 0,
        }
    }
    
    pub fn new_relay(relay_addr: SocketAddr, session_id: [u8; 16]) -> Self {
        Self {
            addr: relay_addr,
            is_relay: true,
            session_id: Some(session_id),
            state: PathCandidateState::Unknown,
            rtt_ms: None,
            last_success: None,
            last_probe: None,
            failures: 0,
            probe_seq: 0,
        }
    }
    
    pub fn needs_probe(&self) -> bool {
        match self.state {
            PathCandidateState::Failed => false,
            PathCandidateState::Unknown => true,
            PathCandidateState::Probing | PathCandidateState::Active => {
                self.last_probe
                    .map(|t| t.elapsed() >= PATH_PROBE_INTERVAL)
                    .unwrap_or(true)
            }
        }
    }
    
    pub fn is_usable(&self) -> bool {
        matches!(self.state, PathCandidateState::Active | PathCandidateState::Probing)
            && self.last_success
                .map(|t| t.elapsed() < PATH_STALE_TIMEOUT)
                .unwrap_or(false)
    }
    
    pub fn record_success(&mut self, rtt: Duration) {
        let rtt_sample = rtt.as_secs_f32() * 1000.0;
        self.rtt_ms = Some(match self.rtt_ms {
            Some(prev) => prev * RTT_EMA_OLD + rtt_sample * RTT_EMA_NEW,
            None => rtt_sample,
        });
        self.state = PathCandidateState::Active;
        self.last_success = Some(Instant::now());
        self.failures = 0;
    }
    
    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= MAX_PROBE_FAILURES {
            self.state = PathCandidateState::Failed;
        }
    }
    
    pub fn mark_probed(&mut self) {
        self.last_probe = Some(Instant::now());
        self.probe_seq = self.probe_seq.wrapping_add(1);
        if self.state == PathCandidateState::Unknown {
            self.state = PathCandidateState::Probing;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SmartAddr(SocketAddr);

impl SmartAddr {
    const PREFIX: [u8; 6] = [0xfd, 0x00, 0xc0, 0xf1, 0x00, 0x00];
    
    const DEFAULT_PORT: u16 = 1;

    pub fn from_identity(identity: &Identity) -> Self {
        let hash = blake3::hash(identity.as_bytes());
        let hash_bytes = hash.as_bytes();
        
        let mut octets = [0u8; 16];
        octets[..6].copy_from_slice(&Self::PREFIX);
        octets[6..16].copy_from_slice(&hash_bytes[..10]);
        
        let ipv6 = Ipv6Addr::from(octets);
        Self(SocketAddr::new(IpAddr::V6(ipv6), Self::DEFAULT_PORT))
    }
    
    pub fn is_smart_addr(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                octets[..6] == Self::PREFIX
            }
            IpAddr::V4(_) => false,
        }
    }
    
    pub fn socket_addr(&self) -> SocketAddr {
        self.0
    }
}

impl Debug for SmartAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SmartAddr({})", self.0)
    }
}

impl From<SmartAddr> for SocketAddr {
    fn from(addr: SmartAddr) -> Self {
        addr.0
    }
}

#[derive(Debug, Clone)]
pub enum PathChoice {
    Direct { addr: SocketAddr, rtt_ms: f32 },
    Relay { 
        relay_addr: SocketAddr, 
        session_id: [u8; 16],
        rtt_ms: f32,
    },
}

#[derive(Debug)]
pub struct PeerPathState {
    pub identity: Identity,
    pub direct_addrs: Vec<SocketAddr>,
    pub relay_tunnels: HashMap<[u8; 16], RelayTunnel>,
    pub active_path: Option<PathChoice>,
    /// Last time we received data from this peer. Used for LRU eviction.
    pub last_recv: Option<Instant>,
    pub candidates: HashMap<SocketAddr, PathCandidateInfo>,
    pub pending_probes: HashMap<u64, (SocketAddr, Instant)>,
    next_probe_counter: u64,
    identity_probe_prefix: u64,
}

impl PeerPathState {
    pub fn new(identity: Identity) -> Self {
        let identity_hash = blake3::hash(identity.as_bytes());
        let identity_probe_prefix = u64::from_le_bytes(identity_hash.as_bytes()[0..8].try_into().unwrap());
        
        // Use CSPRNG for probe counter initialization, with deterministic fallback
        // if system RNG is unavailable (early boot, containers, etc.)
        let next_probe_counter = {
            let mut counter_bytes = [0u8; 8];
            if getrandom::getrandom(&mut counter_bytes).is_ok() {
                u64::from_le_bytes(counter_bytes)
            } else {
                // Fallback: derive from identity hash + high-resolution timestamp
                // This is less random but avoids panic in degraded environments
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
                let timestamp_bytes = timestamp.to_le_bytes();
                let mut fallback_input = Vec::with_capacity(40);
                fallback_input.extend_from_slice(identity_hash.as_bytes());
                fallback_input.extend_from_slice(&timestamp_bytes);
                let fallback_hash = blake3::hash(&fallback_input);
                u64::from_le_bytes(fallback_hash.as_bytes()[8..16].try_into().unwrap())
            }
        };
        
        Self {
            identity,
            direct_addrs: Vec::new(),
            relay_tunnels: HashMap::new(),
            active_path: None,
            last_recv: None,
            candidates: HashMap::new(),
            pending_probes: HashMap::new(),
            next_probe_counter,
            identity_probe_prefix,
        }
    }
    
    fn next_probe_id(&mut self) -> u64 {
        let counter = self.next_probe_counter;
        self.next_probe_counter = self.next_probe_counter.wrapping_add(1);
        self.identity_probe_prefix ^ counter
    }
    
    pub fn best_addr(&self) -> Option<SocketAddr> {
        match &self.active_path {
            Some(PathChoice::Direct { addr, .. }) => Some(*addr),
            Some(PathChoice::Relay { relay_addr, .. }) => Some(*relay_addr),
            None => {
                self.direct_addrs.first().copied()
                    .or_else(|| self.relay_tunnels.values().next().map(|t| t.relay_addr))
            }
        }
    }

    /// Returns the currently active relay tunnel, if the active path uses a relay.
    pub fn active_tunnel(&self) -> Option<&RelayTunnel> {
        match &self.active_path {
            Some(PathChoice::Relay { session_id, .. }) => {
                self.relay_tunnels.get(session_id)
            }
            _ => None,
        }
    }

    /// Returns whether the current active path uses a relay tunnel.
    pub fn is_relayed(&self) -> bool {
        matches!(self.active_path, Some(PathChoice::Relay { .. }))
    }
    
    pub fn add_direct_candidate(&mut self, addr: SocketAddr) {
        if self.candidates.len() >= MAX_CANDIDATES_PER_PEER && !self.candidates.contains_key(&addr) {
            return;
        }
        self.candidates.entry(addr).or_insert_with(|| PathCandidateInfo::new_direct(addr));
        if !self.direct_addrs.contains(&addr) {
            if self.direct_addrs.len() >= MAX_DIRECT_ADDRS_PER_PEER {
                return;
            }
            self.direct_addrs.push(addr);
        }
    }
    
    pub fn add_relay_candidate(&mut self, relay_addr: SocketAddr, session_id: [u8; 16]) {
        if self.candidates.len() >= MAX_CANDIDATES_PER_PEER && !self.candidates.contains_key(&relay_addr) {
            return;
        }
        self.candidates.entry(relay_addr).or_insert_with(|| PathCandidateInfo::new_relay(relay_addr, session_id));
    }
    
    pub fn candidates_needing_probe(&self) -> Vec<SocketAddr> {
        self.candidates
            .iter()
            .filter(|(_, c)| c.needs_probe())
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    pub fn generate_probe(&mut self, addr: SocketAddr) -> Option<(u64, PathProbeRequest)> {
        if !self.candidates.contains_key(&addr) {
            return None;
        }
        
        if self.pending_probes.len() >= MAX_PENDING_PROBES_PER_PEER {
            let oldest_tx_id = self.pending_probes
                .iter()
                .min_by_key(|(_, (_, sent_at))| *sent_at)
                .map(|(tx_id, _)| *tx_id);
            if let Some(old_id) = oldest_tx_id {
                self.pending_probes.remove(&old_id);
            }
        }
        
        let tx_id = self.next_probe_id();
        
        let candidate = self.candidates.get_mut(&addr)?;
        candidate.mark_probed();
        self.pending_probes.insert(tx_id, (addr, Instant::now()));
        
        Some((tx_id, PathProbeRequest::new(tx_id)))
    }
    
    pub fn handle_probe_response(&mut self, tx_id: u64, rtt: Duration) -> bool {
        let (addr, _sent_at) = match self.pending_probes.remove(&tx_id) {
            Some(info) => info,
            None => return false,
        };
        
        let candidate = match self.candidates.get_mut(&addr) {
            Some(c) => c,
            None => return false,
        };
        
        let was_failed = candidate.state == PathCandidateState::Failed;
        candidate.record_success(rtt);
        
        tracing::debug!(
            peer = ?self.identity,
            addr = %addr,
            rtt_ms = ?candidate.rtt_ms,
            is_relay = candidate.is_relay,
            "probe response received"
        );
        
        was_failed || candidate.state == PathCandidateState::Active
    }
    
    pub fn expire_probes(&mut self, timeout: Duration) {
        let now = Instant::now();
        let expired: Vec<_> = self.pending_probes
            .iter()
            .filter(|(_, (_, sent))| now.duration_since(*sent) > timeout)
            .map(|(tx_id, (addr, _))| (*tx_id, *addr))
            .collect();
        
        for (tx_id, addr) in expired {
            self.pending_probes.remove(&tx_id);
            if let Some(candidate) = self.candidates.get_mut(&addr) {
                candidate.record_failure();
            }
        }
    }
    
    pub fn select_best_path(&self) -> Option<PathChoice> {
        let usable: Vec<_> = self.candidates
            .iter()
            .filter(|(_, c)| c.is_usable())
            .collect();
        
        if usable.is_empty() {
            return None;
        }
        
        let best_direct = usable.iter()
            .filter(|(_, c)| !c.is_relay)
            .min_by(|(_, a), (_, b)| {
                a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal)
            });
        
        let best_relay = usable.iter()
            .filter(|(_, c)| c.is_relay)
            .min_by(|(_, a), (_, b)| {
                a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal)
            });
        
        match (best_direct, best_relay) {
            (Some((_, direct)), Some((_, relay))) => {
                let direct_rtt = direct.rtt_ms.unwrap_or(f32::MAX);
                let relay_rtt = relay.rtt_ms.unwrap_or(f32::MAX);
                
                if relay_rtt + RELAY_RTT_ADVANTAGE_MS < direct_rtt {
                    Some(PathChoice::Relay {
                        relay_addr: relay.addr,
                        session_id: relay.session_id.unwrap_or([0; 16]),
                        rtt_ms: relay_rtt,
                    })
                } else {
                    Some(PathChoice::Direct {
                        addr: direct.addr,
                        rtt_ms: direct_rtt,
                    })
                }
            }
            (Some((_, direct)), None) => {
                Some(PathChoice::Direct {
                    addr: direct.addr,
                    rtt_ms: direct.rtt_ms.unwrap_or(f32::MAX),
                })
            }
            (None, Some((_, relay))) => {
                Some(PathChoice::Relay {
                    relay_addr: relay.addr,
                    session_id: relay.session_id.unwrap_or([0; 16]),
                    rtt_ms: relay.rtt_ms.unwrap_or(f32::MAX),
                })
            }
            (None, None) => None,
        }
    }
    
    pub fn maybe_switch_path(&mut self) -> Option<PathChoice> {
        let best = self.select_best_path()?;
        let was_relayed = self.is_relayed();
        // Capture tunnel age before switching (for diagnostics when leaving relay path)
        let tunnel_age_secs = self.active_tunnel().map(|t| t.age().as_secs());
        
        let should_switch = match (&self.active_path, &best) {
            (None, _) => true,
            (Some(PathChoice::Relay { .. }), PathChoice::Direct { .. }) => {
                true
            }
            (Some(PathChoice::Direct { rtt_ms: old_rtt, .. }), PathChoice::Direct { rtt_ms: new_rtt, .. }) => {
                *new_rtt + 10.0 < *old_rtt
            }
            (Some(PathChoice::Direct { rtt_ms: direct_rtt, .. }), PathChoice::Relay { rtt_ms: relay_rtt, .. }) => {
                *relay_rtt + RELAY_RTT_ADVANTAGE_MS < *direct_rtt
            }
            (Some(PathChoice::Relay { rtt_ms: old_rtt, .. }), PathChoice::Relay { rtt_ms: new_rtt, .. }) => {
                *new_rtt + 20.0 < *old_rtt
            }
        };
        
        if should_switch {
            tracing::info!(
                peer = ?self.identity,
                was_relayed = was_relayed,
                tunnel_age_secs = ?tunnel_age_secs,
                old_path = ?self.active_path,
                new_path = ?best,
                "switching to better path"
            );
            self.active_path = Some(best.clone());
            Some(best)
        } else {
            None
        }
    }
}

pub struct SmartSock {
    inner: Arc<tokio::net::UdpSocket>,
    
    peers: RwLock<HashMap<SmartAddr, PeerPathState>>,
    
    reverse_map: RwLock<HashMap<SocketAddr, SmartAddr>>,
    
    local_addr: SocketAddr,

    udprelay: StdRwLock<Option<Relay>>,
    
    /// Optional handler for path change events (uses tokio RwLock for async safety)
    path_event_handler: RwLock<Option<Arc<dyn PathEventHandler>>>,
}

impl SmartSock {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        
        Ok(Self {
            inner: Arc::new(socket),
            peers: RwLock::new(HashMap::new()),
            reverse_map: RwLock::new(HashMap::new()),
            local_addr,
            udprelay: StdRwLock::new(None),
            path_event_handler: RwLock::new(None),
        })
    }

    pub fn set_udprelay(&self, relay: Relay) {
        if let Ok(mut guard) = self.udprelay.write() {
            *guard = Some(relay);
        }
    }

    /// Get the relay handle, if configured.
    pub fn relay(&self) -> Option<Relay> {
        self.udprelay.read().ok().and_then(|g| g.clone())
    }

    /// Get the local address this socket is bound to.
    pub fn local_address(&self) -> SocketAddr {
        self.local_addr
    }
    
    /// Set the path event handler to receive notifications when paths change.
    pub async fn set_path_event_handler(&self, handler: Arc<dyn PathEventHandler>) {
        let mut guard = self.path_event_handler.write().await;
        *guard = Some(handler);
    }
    
    /// Get the current path event handler, if set.
    async fn get_path_event_handler(&self) -> Option<Arc<dyn PathEventHandler>> {
        self.path_event_handler.read().await.clone()
    }
    
    /// Cache a contact by parsing its addresses and registering as a peer.
    /// This is a convenience method that handles address parsing.
    pub async fn cache_contact(&self, contact: &Contact) {
        // Parse all addresses from the contact
        let mut addrs: Vec<SocketAddr> = Vec::new();
        
        // Parse all addresses
        for addr_str in &contact.addrs {
            if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
            }
        }
        
        // Only register if we have at least one valid address
        if !addrs.is_empty() {
            self.register_peer(contact.identity, addrs).await;
        }
    }

    pub async fn register_peer(
        &self,
        identity: Identity,
        direct_addrs: Vec<SocketAddr>,
    ) -> SmartAddr {
        let smart_addr = SmartAddr::from_identity(&identity);
        
        let mut state = PeerPathState::new(identity);
        state.direct_addrs = direct_addrs.clone();
        
        if let Some(addr) = direct_addrs.first() {
            state.active_path = Some(PathChoice::Direct { 
                addr: *addr, 
                rtt_ms: f32::MAX,            });
        }
        
        {
            let mut peers = self.peers.write().await;
            
            if peers.len() >= MAX_SMARTSOCK_PEERS && !peers.contains_key(&smart_addr) {
                if let Some(oldest_addr) = peers.iter()
                    .min_by_key(|(_, s)| s.last_recv)
                    .map(|(k, _)| *k)
                {
                    if let Some(evicted) = peers.remove(&oldest_addr) {
                        let mut reverse = self.reverse_map.write().await;
                        for addr in &evicted.direct_addrs {
                            reverse.remove(addr);
                        }
                        for tunnel in evicted.relay_tunnels.values() {
                            reverse.remove(&tunnel.relay_addr);
                        }
                        for addr in evicted.candidates.keys() {
                            reverse.remove(addr);
                        }
                        debug!(
                            evicted = ?evicted.identity,
                            direct_addrs = evicted.direct_addrs.len(),
                            relay_tunnels = evicted.relay_tunnels.len(),
                            candidates = evicted.candidates.len(),
                            "evicted oldest peer from SmartSock to make room"
                        );
                    }
                }
            }
            
            peers.insert(smart_addr, state);
        }
        
        {
            let mut reverse = self.reverse_map.write().await;
            for addr in direct_addrs {
                reverse.insert(addr, smart_addr);
            }
        }
        
        smart_addr
    }
    
    pub async fn add_relay_tunnel(
        &self,
        identity: &Identity,
        session_id: [u8; 16],
        relay_addr: SocketAddr,
    ) -> Option<SmartAddr> {
        let smart_addr = SmartAddr::from_identity(identity);
        
        let tunnel = RelayTunnel::new(session_id, relay_addr, *identity);
        
        let mut peers = self.peers.write().await;
        let state = peers.get_mut(&smart_addr)?;
        
        state.relay_tunnels.insert(session_id, tunnel);
        
        drop(peers);
        {
            let mut reverse = self.reverse_map.write().await;
            reverse.insert(relay_addr, smart_addr);
        }
        
        tracing::debug!(
            peer = ?identity,
            session = hex::encode(session_id),
            relay = %relay_addr,
            "added relay tunnel for peer"
        );
        
        Some(smart_addr)
    }
    
    pub async fn remove_relay_tunnel(
        &self,
        identity: &Identity,
        session_id: &[u8; 16],
    ) {
        let smart_addr = SmartAddr::from_identity(identity);
        
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            if let Some(tunnel) = state.relay_tunnels.remove(session_id) {
                drop(peers);
                let mut reverse = self.reverse_map.write().await;
                reverse.remove(&tunnel.relay_addr);
                
                tracing::debug!(
                    peer = ?identity,
                    session = hex::encode(session_id),
                    "removed relay tunnel"
                );
            }
        }
    }
    
    /// Remove all relay tunnels for a peer. Called when a connection is closed.
    pub async fn cleanup_peer_relay_tunnels(&self, identity: &Identity) -> Vec<[u8; 16]> {
        let smart_addr = SmartAddr::from_identity(identity);
        
        // First pass: collect relay addresses and session IDs while holding the lock
        let mut removed_sessions = Vec::new();
        let mut relay_addrs_to_remove = Vec::new();
        
        {
            let mut peers = self.peers.write().await;
            if let Some(state) = peers.get_mut(&smart_addr) {
                let session_ids: Vec<[u8; 16]> = state.relay_tunnels.keys().copied().collect();
                for session_id in session_ids {
                    if let Some(tunnel) = state.relay_tunnels.remove(&session_id) {
                        removed_sessions.push(session_id);
                        relay_addrs_to_remove.push(tunnel.relay_addr);
                    }
                }
            }
        } // Release peers lock before acquiring reverse_map lock
        
        // Second pass: clean up reverse map entries
        if !relay_addrs_to_remove.is_empty() {
            let mut reverse = self.reverse_map.write().await;
            for relay_addr in relay_addrs_to_remove {
                reverse.remove(&relay_addr);
            }
        }
        
        if !removed_sessions.is_empty() {
            tracing::debug!(
                peer = ?identity,
                tunnels_removed = removed_sessions.len(),
                "cleaned up all relay tunnels for peer"
            );
        }
        
        removed_sessions
    }
    
    /// Get contact information for a peer from SmartSock's peer registry.
    /// Uses try_read to avoid blocking if the lock is contended.
    pub fn get_peer_contact_nonblocking(&self, identity: &Identity) -> Option<Contact> {
        let smart_addr = SmartAddr::from_identity(identity);
        let peers = self.peers.try_read().ok()?;
        let state = peers.get(&smart_addr)?;
        
        // Build contact from peer state
        let addrs: Vec<String> = state.direct_addrs.iter()
            .map(|a| a.to_string())
            .collect();
        
        Some(Contact {
            identity: state.identity,
            addrs,
        })
    }
    
    /// Get contact information for a peer from SmartSock's peer registry (async version).
    pub async fn get_peer_contact(&self, identity: &Identity) -> Option<Contact> {
        let smart_addr = SmartAddr::from_identity(identity);
        let peers = self.peers.read().await;
        let state = peers.get(&smart_addr)?;
        
        // Build contact from peer state
        let addrs: Vec<String> = state.direct_addrs.iter()
            .map(|a| a.to_string())
            .collect();
        
        Some(Contact {
            identity: state.identity,
            addrs,
        })
    }
    
    pub async fn use_relay_path(
        &self,
        identity: &Identity,
        session_id: [u8; 16],
    ) -> bool {
        let smart_addr = SmartAddr::from_identity(identity);
        
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            if let Some(tunnel) = state.relay_tunnels.get(&session_id) {
                state.active_path = Some(PathChoice::Relay {
                    relay_addr: tunnel.relay_addr,
                    session_id,
                    rtt_ms: f32::MAX,                });
                tracing::debug!(
                    peer = ?identity,
                    session = hex::encode(session_id),
                    "switched to relay path"
                );
                return true;
            }
        }
        false
    }
    
    pub async fn use_direct_path(
        &self,
        identity: &Identity,
        addr: SocketAddr,
    ) -> bool {
        let smart_addr = SmartAddr::from_identity(identity);
        
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            state.active_path = Some(PathChoice::Direct {
                addr,
                rtt_ms: f32::MAX,
            });
            tracing::debug!(
                peer = ?identity,
                addr = %addr,
                "switched to direct path"
            );
            return true;
        }
        false
    }
    
    pub async fn update_path(&self, identity: &Identity, path: PathChoice) {
        let smart_addr = SmartAddr::from_identity(identity);
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            tracing::debug!(
                peer = ?identity,
                path = ?path,
                "updating peer path"
            );
            state.active_path = Some(path);
        }
    }
    
    /// Send a probe packet through a relay tunnel to complete the relay session.
    /// 
    /// This is called by the receiving peer (B) after getting an IncomingConnection
    /// notification. The probe packet is a minimal CRLY-framed message that:
    /// 1. Registers B's UDP address with the relay
    /// 2. Triggers the relay to complete the session (learn B's address)
    /// 
    /// # Arguments
    /// * `peer` - The peer identity we're establishing the relay tunnel with
    /// * `session_id` - The relay session ID
    pub async fn send_relay_probe(
        &self,
        peer: &Identity,
        session_id: [u8; 16],
    ) -> io::Result<()> {
        let smart_addr = SmartAddr::from_identity(peer);
        
        let relay_addr = {
            let peers = self.peers.read().await;
            let state = peers.get(&smart_addr).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "peer not registered")
            })?;
            
            let tunnel = state.relay_tunnels.get(&session_id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "relay tunnel not found")
            })?;
            
            tunnel.relay_addr
        };
        
        // Build a minimal CRLY probe packet: magic + session_id + minimal payload
        // The payload can be empty or contain a small marker - the relay just needs
        // to see the CRLY header to identify it as a relay packet
        let probe_payload = b"PROBE";
        let mut frame = Vec::with_capacity(crate::relay::RELAY_HEADER_SIZE + probe_payload.len());
        frame.extend_from_slice(&RELAY_MAGIC);
        frame.extend_from_slice(&session_id);
        frame.extend_from_slice(probe_payload);
        
        self.inner.send_to(&frame, relay_addr).await?;
        
        tracing::debug!(
            peer = ?peer,
            session = hex::encode(session_id),
            relay = %relay_addr,
            "sent relay probe to complete session"
        );
        
        Ok(())
    }
    
    pub async fn add_direct_candidate(&self, identity: &Identity, addr: SocketAddr) {
        let smart_addr = SmartAddr::from_identity(identity);
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            state.add_direct_candidate(addr);
        }
        drop(peers);
        
        let mut reverse = self.reverse_map.write().await;
        reverse.insert(addr, smart_addr);
    }
    
    pub async fn add_relay_candidate(&self, identity: &Identity, relay_addr: SocketAddr, session_id: [u8; 16]) {
        let smart_addr = SmartAddr::from_identity(identity);
        let mut peers = self.peers.write().await;
        if let Some(state) = peers.get_mut(&smart_addr) {
            state.add_relay_candidate(relay_addr, session_id);
        }
    }
    
    pub async fn generate_probes(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut probes = Vec::new();
        let mut peers = self.peers.write().await;
        
        for (_, state) in peers.iter_mut() {
            let addrs_to_probe = state.candidates_needing_probe();
            for addr in addrs_to_probe {
                if let Some((_, probe)) = state.generate_probe(addr) {
                    probes.push((addr, probe.to_bytes()));
                }
            }
        }
        
        probes
    }
    
    pub async fn probe_all_paths(&self) -> io::Result<usize> {
        let probes = self.generate_probes().await;
        let count = probes.len();
        
        for (addr, probe_bytes) in probes {
            if let Err(e) = self.inner.send_to(&probe_bytes, addr).await {
                tracing::trace!(
                    addr = %addr,
                    error = %e,
                    "failed to send path probe"
                );
            }
        }
        
        Ok(count)
    }
    
    pub fn handle_probe_request(&self, data: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        let request = PathProbeRequest::from_bytes(data)?;
        let response = PathProbeResponse::from_request(&request, from);
        Some(response.to_bytes())
    }
    
    pub async fn handle_probe_response(&self, data: &[u8]) -> bool {
        let response = match PathProbeResponse::from_bytes(data) {
            Some(r) => r,
            None => return false,
        };
        
        let rtt = Duration::from_millis(response.rtt_ms() as u64);
        
        let mut peers = self.peers.write().await;
        for (_, state) in peers.iter_mut() {
            if state.handle_probe_response(response.tx_id, rtt) {
                state.maybe_switch_path();
                return true;
            }
        }
        
        false
    }
    
    pub async fn expire_probes(&self) {
        let timeout = PATH_PROBE_INTERVAL * 2;
        let mut peers = self.peers.write().await;
        for (_, state) in peers.iter_mut() {
            state.expire_probes(timeout);
        }
    }
    
    /// Clean up relay tunnels that have been idle longer than RELAY_TUNNEL_STALE_TIMEOUT.
    /// This provides defense-in-depth against leaks if connection-close cleanup is missed.
    pub async fn cleanup_stale_relay_tunnels(&self) -> usize {
        let mut stale_tunnels: Vec<(SmartAddr, [u8; 16], std::net::SocketAddr, u64, Identity)> = Vec::new();
        
        // First pass: identify stale tunnels while holding the lock
        {
            let peers = self.peers.read().await;
            for (smart_addr, _state) in peers.iter() {
                for (session_id, tunnel) in &_state.relay_tunnels {
                    if tunnel.is_older_than(RELAY_TUNNEL_STALE_TIMEOUT) {
                        stale_tunnels.push((
                            *smart_addr,
                            *session_id,
                            tunnel.relay_addr,
                            tunnel.age().as_secs(),
                            tunnel.peer_identity,
                        ));
                    }
                }
            }
        }
        
        if stale_tunnels.is_empty() {
            return 0;
        }
        
        // Second pass: remove stale tunnels
        let mut removed_count = 0;
        {
            let mut peers = self.peers.write().await;
            for (smart_addr, session_id, relay_addr, age_secs, peer_id) in &stale_tunnels {
                if let Some(state) = peers.get_mut(smart_addr) {
                    if state.relay_tunnels.remove(session_id).is_some() {
                        removed_count += 1;
                        tracing::debug!(
                            peer = ?peer_id,
                            session = hex::encode(session_id),
                            relay = %relay_addr,
                            age_secs = age_secs,
                            "removed stale relay tunnel"
                        );
                    }
                }
            }
        }
        
        // Third pass: clean up reverse map
        if removed_count > 0 {
            let mut reverse = self.reverse_map.write().await;
            for (_, _, relay_addr, _, _) in stale_tunnels {
                reverse.remove(&relay_addr);
            }
        }
        
        removed_count
    }
    
    pub async fn switch_to_best_paths(&self) {
        let switches: Vec<(Identity, PathChoice)> = {
            let mut peers = self.peers.write().await;
            let mut switches = Vec::new();
            for (_, state) in peers.iter_mut() {
                if let Some(new_path) = state.maybe_switch_path() {
                    switches.push((state.identity, new_path));
                }
            }
            switches
        };
        
        // Notify handler of path switches (outside of lock)
        if !switches.is_empty() {
            if let Some(handler) = self.get_path_event_handler().await {
                for (peer, new_path) in switches {
                    handler.on_path_improved(peer, new_path).await;
                }
            }
        }
    }
    
    pub fn spawn_probe_loop(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let sock = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PATH_PROBE_INTERVAL);
            // Run stale tunnel cleanup every 60 seconds (12 probe intervals)
            let mut cleanup_counter = 0u32;
            const CLEANUP_INTERVAL_TICKS: u32 = 12;
            
            loop {
                interval.tick().await;
                
                sock.expire_probes().await;
                
                match sock.probe_all_paths().await {
                    Ok(count) if count > 0 => {
                        tracing::trace!(probes_sent = count, "path probing tick");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "path probing error");
                    }
                    _ => {}
                }
                
                sock.switch_to_best_paths().await;
                
                // Periodic cleanup of stale relay tunnels
                cleanup_counter += 1;
                if cleanup_counter >= CLEANUP_INTERVAL_TICKS {
                    cleanup_counter = 0;
                    let removed = sock.cleanup_stale_relay_tunnels().await;
                    if removed > 0 {
                        tracing::debug!(removed = removed, "cleaned up stale relay tunnels");
                    }
                }
            }
        })
    }
    
    pub fn inner_socket(&self) -> &Arc<tokio::net::UdpSocket> {
        &self.inner
    }
    
    pub fn into_endpoint(
        self,
        server_config: quinn::ServerConfig,
    ) -> io::Result<(quinn::Endpoint, Arc<Self>)> {
        let smartsock = Arc::new(self);
        
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("no async runtime found"))?;
        
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            smartsock.clone(),
            runtime,
        )?;
        
        Ok((endpoint, smartsock))
    }
    
    pub async fn bind_endpoint(
        addr: std::net::SocketAddr,
        server_config: quinn::ServerConfig,
    ) -> io::Result<(quinn::Endpoint, Arc<Self>)> {
        let smartsock = Self::bind(addr).await?;
        let (endpoint, smartsock) = smartsock.into_endpoint(server_config)?;
        
        // Spawn probe loop internally
        let probe_smartsock = smartsock.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PATH_PROBE_INTERVAL);
            // Run stale tunnel cleanup every 60 seconds (12 probe intervals)
            let mut cleanup_counter = 0u32;
            const CLEANUP_INTERVAL_TICKS: u32 = 12;
            
            loop {
                interval.tick().await;
                
                probe_smartsock.expire_probes().await;
                
                match probe_smartsock.probe_all_paths().await {
                    Ok(count) if count > 0 => {
                        tracing::trace!(probes_sent = count, "path probing tick");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "path probing error");
                    }
                    _ => {}
                }
                
                probe_smartsock.switch_to_best_paths().await;
                
                // Periodic cleanup of stale relay tunnels
                cleanup_counter += 1;
                if cleanup_counter >= CLEANUP_INTERVAL_TICKS {
                    cleanup_counter = 0;
                    let removed = probe_smartsock.cleanup_stale_relay_tunnels().await;
                    if removed > 0 {
                        tracing::debug!(removed = removed, "cleaned up stale relay tunnels");
                    }
                }
            }
        });
        
        Ok((endpoint, smartsock))
    }
}

impl Debug for SmartSock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmartSock")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

struct SmartSockPoller {
    inner: Arc<tokio::net::UdpSocket>,
}

impl Debug for SmartSockPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmartSockPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for SmartSockPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.inner.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for SmartSock {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SmartSockPoller {
            inner: self.inner.clone(),
        })
    }
    
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if SmartAddr::is_smart_addr(&transmit.destination) {
            let smart_addr = SmartAddr(transmit.destination);
            
            let peers_guard = match self.peers.try_read() {
                Ok(guard) => guard,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "peer map locked"
                    ));
                }
            };
            
            let state = match peers_guard.get(&smart_addr) {
                Some(s) => s,
                None => {
                    tracing::warn!(
                        dest = ?transmit.destination,
                        "no peer state for SmartAddr"
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "unknown peer"
                    ));
                }
            };
            
            match &state.active_path {
                Some(PathChoice::Relay { relay_addr, session_id, .. }) => {
                    if let Some(tunnel) = state.relay_tunnels.get(session_id) {
                        let frame = tunnel.encode_frame(transmit.contents);
                        let relay_dest = *relay_addr;
                        drop(peers_guard);
                        
                        if frame.len() > MAX_RELAY_FRAME_SIZE {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "relay frame too large"
                            ));
                        }
                        
                        self.inner.try_send_to(&frame, relay_dest)
                            .map(|_| ())
                    } else {
                        drop(peers_guard);
                        Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "relay tunnel not found"
                        ))
                    }
                }
                Some(PathChoice::Direct { addr, .. }) => {
                    let dest = *addr;
                    drop(peers_guard);
                    self.inner.try_send_to(transmit.contents, dest)
                        .map(|_| ())
                }
                None => {
                    if let Some(addr) = state.best_addr() {
                        drop(peers_guard);
                        self.inner.try_send_to(transmit.contents, addr)
                            .map(|_| ())
                    } else {
                        drop(peers_guard);
                        Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "no path to peer"
                        ))
                    }
                }
            }
        } else {
            self.inner.try_send_to(transmit.contents, transmit.destination)
                .map(|_| ())
        }
    }
    
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty() && !meta.is_empty());
        
        let mut buf = [0u8; 65535];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        
        match self.inner.poll_recv_from(cx, &mut read_buf) {
            Poll::Ready(Ok(src_addr)) => {
                let received = read_buf.filled();
                
                // Dispatch relay packets to relay server (multiplexing)
                if received.len() >= 4 && received[0..4] == RELAY_MAGIC {
                    if let Ok(guard) = self.udprelay.read() {
                        if let Some(udprelay) = guard.as_ref() {
                            let udprelay = udprelay.clone();
                            let data = received.to_vec();
                            tokio::spawn(async move {
                                udprelay.process_packet(&data, src_addr).await;
                            });
                            
                            // Packet handled by relay server, skip for Quinn
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                }
                
                if PathProbeRequest::is_probe_request(received) {
                    if let Some(response_bytes) = self.handle_probe_request(received, src_addr) {
                        let _ = self.inner.try_send_to(&response_bytes, src_addr);
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                
                if PathProbeResponse::is_probe_response(received) {
                    if let Some(response) = PathProbeResponse::from_bytes(received) {
                        let rtt = Duration::from_millis(response.rtt_ms() as u64);
                        if let Ok(mut peers) = self.peers.try_write() {
                            for (_, state) in peers.iter_mut() {
                                if state.handle_probe_response(response.tx_id, rtt) {
                                    state.maybe_switch_path();
                                    break;
                                }
                            }
                        }
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                
                let (payload, translated_addr, smart_addr_for_recv) = if let Some((session_id, payload)) = RelayTunnel::decode_frame(received) {
                    let smart_addr = match self.reverse_map.try_read() {
                        Ok(guard) => {
                            guard.get(&src_addr).copied()
                        }
                        Err(_) => None,
                    };
                    
                    let verified_smart_addr = smart_addr.and_then(|sa| {
                        match self.peers.try_read() {
                            Ok(peers) => {
                                if let Some(state) = peers.get(&sa) {
                                    if state.relay_tunnels.contains_key(&session_id) {
                                        return Some(sa);
                                    }
                                }
                                None
                            }
                            Err(_) => Some(sa),
                        }
                    });
                    
                    let addr = verified_smart_addr
                        .map(|sa| sa.0)
                        .unwrap_or(src_addr);
                    
                    (payload, addr, verified_smart_addr)
                } else {
                    // For non-relay packets, do NOT rewrite the observed source address.
                    // QUIC connection tracking is keyed on the real remote SocketAddr;
                    // rewriting this to a synthetic SmartAddr can cause handshakes and
                    // existing connections to stall or be dropped.
                    let sa = match self.reverse_map.try_read() {
                        Ok(guard) => guard.get(&src_addr).copied(),
                        Err(_) => None,
                    };
                    (received, src_addr, sa)
                };
                
                // Update last_recv for LRU eviction tracking
                if let Some(sa) = smart_addr_for_recv {
                    if let Ok(mut peers) = self.peers.try_write() {
                        if let Some(state) = peers.get_mut(&sa) {
                            state.last_recv = Some(Instant::now());
                        }
                    }
                }
                
                let copy_len = payload.len().min(bufs[0].len());
                bufs[0][..copy_len].copy_from_slice(&payload[..copy_len]);
                
                meta[0] = RecvMeta {
                    addr: translated_addr,
                    len: copy_len,
                    stride: copy_len,
                    ecn: None,
                    dst_ip: None,
                };
                
                Poll::Ready(Ok(1))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
    
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
    
    fn max_transmit_segments(&self) -> usize {
        1
    }
    
    fn max_receive_segments(&self) -> usize {
        1
    }
    
    fn may_fragment(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{RelayTunnel, RELAY_MAGIC, RELAY_HEADER_SIZE};

    #[test]
    fn test_smart_addr_from_identity() {
        let identity = Identity::from([1u8; 32]);
        let addr = SmartAddr::from_identity(&identity);
        
        assert!(SmartAddr::is_smart_addr(&addr.socket_addr()));
        
        let addr2 = SmartAddr::from_identity(&identity);
        assert_eq!(addr.socket_addr(), addr2.socket_addr());
        
        let other = Identity::from([2u8; 32]);
        let addr3 = SmartAddr::from_identity(&other);
        assert_ne!(addr.socket_addr(), addr3.socket_addr());
    }
    
    #[test]
    fn test_smart_addr_detection() {
        let identity = Identity::from([1u8; 32]);
        let smart = SmartAddr::from_identity(&identity);
        
        assert!(SmartAddr::is_smart_addr(&smart.socket_addr()));
        
        let regular_v4: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let regular_v6: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        
        assert!(!SmartAddr::is_smart_addr(&regular_v4));
        assert!(!SmartAddr::is_smart_addr(&regular_v6));
    }
    
    #[test]
    fn test_relay_frame_encoding_decoding() {
        let identity = Identity::from([42u8; 32]);
        let session_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let relay_addr: SocketAddr = "192.168.1.100:4433".parse().unwrap();
        
        let tunnel = RelayTunnel::new(session_id, relay_addr, identity);
        
        let payload = b"Hello, QUIC packet!";
        let frame = tunnel.encode_frame(payload);
        
        assert_eq!(frame.len(), RELAY_HEADER_SIZE + payload.len());
        
        assert_eq!(&frame[0..4], &RELAY_MAGIC);
        
        assert_eq!(&frame[4..20], &session_id);
        
        assert_eq!(&frame[RELAY_HEADER_SIZE..], payload.as_slice());
        
        let decoded = RelayTunnel::decode_frame(&frame);
        assert!(decoded.is_some());
        
        let (decoded_session, decoded_payload) = decoded.unwrap();
        assert_eq!(decoded_session, session_id);
        assert_eq!(decoded_payload, payload.as_slice());
    }
    
    #[test]
    fn test_relay_frame_decode_rejects_invalid() {
        assert!(RelayTunnel::decode_frame(&[1, 2, 3]).is_none());
        
        let mut bad_magic = [0u8; 30];
        bad_magic[0..4].copy_from_slice(b"NOPE");
        assert!(RelayTunnel::decode_frame(&bad_magic).is_none());
        
        assert!(RelayTunnel::decode_frame(&[]).is_none());
        
        let mut header_only = [0u8; RELAY_HEADER_SIZE];
        header_only[0..4].copy_from_slice(&RELAY_MAGIC);
        let result = RelayTunnel::decode_frame(&header_only);
        assert!(result.is_some());
        let (_, payload) = result.unwrap();
        assert!(payload.is_empty());
    }
    
    #[test]
    fn test_path_probe_request_encoding_decoding() {
        let probe = PathProbeRequest::new(12345);
        let bytes = probe.to_bytes();
        
        assert_eq!(&bytes[0..4], &PROBE_MAGIC);
        assert_eq!(bytes[4], PROBE_TYPE_REQUEST);
        
        let decoded = PathProbeRequest::from_bytes(&bytes);
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.tx_id, 12345);
        assert_eq!(decoded.timestamp_ms, probe.timestamp_ms);
        
        assert!(PathProbeRequest::is_probe_request(&bytes));
        assert!(!PathProbeResponse::is_probe_response(&bytes));
    }
    
    #[test]
    fn test_path_probe_response_encoding_decoding() {
        let request = PathProbeRequest::new(67890);
        let observed: SocketAddr = "192.168.1.1:4433".parse().unwrap();
        let response = PathProbeResponse::from_request(&request, observed);
        
        let bytes = response.to_bytes();
        
        assert_eq!(&bytes[0..4], &PROBE_MAGIC);
        assert_eq!(bytes[4], PROBE_TYPE_RESPONSE);
        
        let decoded = PathProbeResponse::from_bytes(&bytes);
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.tx_id, 67890);
        assert_eq!(decoded.echo_timestamp_ms, request.timestamp_ms);
        assert_eq!(decoded.observed_addr, observed);
        
        assert!(PathProbeResponse::is_probe_response(&bytes));
        assert!(!PathProbeRequest::is_probe_request(&bytes));
    }
    
    #[test]
    fn test_path_probe_response_ipv6() {
        let request = PathProbeRequest::new(99999);
        let observed: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let response = PathProbeResponse::from_request(&request, observed);
        
        let bytes = response.to_bytes();
        let decoded = PathProbeResponse::from_bytes(&bytes).unwrap();
        
        assert_eq!(decoded.observed_addr, observed);
    }
    
    #[test]
    fn test_path_candidate_state_machine() {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut candidate = PathCandidateInfo::new_direct(addr);
        
        assert_eq!(candidate.state, PathCandidateState::Unknown);
        assert!(candidate.needs_probe());
        assert!(!candidate.is_usable());
        
        candidate.mark_probed();
        assert_eq!(candidate.state, PathCandidateState::Probing);
        
        candidate.record_success(Duration::from_millis(50));
        assert_eq!(candidate.state, PathCandidateState::Active);
        assert!(candidate.is_usable());
        assert!(candidate.rtt_ms.is_some());
        
        let rtt = candidate.rtt_ms.unwrap();
        assert!(rtt > 40.0 && rtt < 60.0);
        
        candidate.record_success(Duration::from_millis(100));
        let new_rtt = candidate.rtt_ms.unwrap();
        assert!(new_rtt > 55.0 && new_rtt < 65.0);
    }
    
    #[test]
    fn test_path_candidate_failure_handling() {
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut candidate = PathCandidateInfo::new_direct(addr);
        
        candidate.mark_probed();
        candidate.record_success(Duration::from_millis(50));
        
        for _ in 0..MAX_PROBE_FAILURES {
            assert_ne!(candidate.state, PathCandidateState::Failed);
            candidate.record_failure();
        }
        
        assert_eq!(candidate.state, PathCandidateState::Failed);
        assert!(!candidate.needs_probe());
    }
    
    #[test]
    fn test_peer_path_state_best_path_selection() {
        let identity = Identity::from([1u8; 32]);
        let mut state = PeerPathState::new(identity);
        
        let direct1: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let direct2: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let relay: SocketAddr = "192.168.1.100:4433".parse().unwrap();
        
        state.add_direct_candidate(direct1);
        state.add_direct_candidate(direct2);
        state.add_relay_candidate(relay, [0xAB; 16]);
        
        state.candidates.get_mut(&direct1).unwrap().record_success(Duration::from_millis(50));
        
        state.candidates.get_mut(&direct2).unwrap().record_success(Duration::from_millis(30));
        
        state.candidates.get_mut(&relay).unwrap().record_success(Duration::from_millis(20));
        
        let best = state.select_best_path();
        assert!(best.is_some());
        let best = best.unwrap();
        
        match best {
            PathChoice::Direct { addr, .. } => assert_eq!(addr, direct2),
            _ => panic!("Expected direct path"),
        }
    }
    
    #[test]
    fn test_peer_path_state_relay_wins_when_much_faster() {
        let identity = Identity::from([2u8; 32]);
        let mut state = PeerPathState::new(identity);
        
        let direct: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let relay: SocketAddr = "192.168.1.100:4433".parse().unwrap();
        
        state.add_direct_candidate(direct);
        state.add_relay_candidate(relay, [0xCD; 16]);
        
        state.candidates.get_mut(&direct).unwrap().record_success(Duration::from_millis(150));
        
        state.candidates.get_mut(&relay).unwrap().record_success(Duration::from_millis(50));
        
        let best = state.select_best_path();
        assert!(best.is_some());
        
        match best.unwrap() {
            PathChoice::Relay { relay_addr, .. } => assert_eq!(relay_addr, relay),
            _ => panic!("Expected relay path"),
        }
    }

    #[test]
    fn peer_path_state_new_and_fields() {
        let id = Identity::from_bytes([1u8; 32]);
        let state = PeerPathState::new(id);
        
        assert_eq!(state.identity, id);
        assert!(state.direct_addrs.is_empty());
        assert!(state.relay_tunnels.is_empty());
        assert!(state.active_path.is_none());
        assert!(state.last_recv.is_none());
        assert!(state.candidates.is_empty());
        assert!(state.pending_probes.is_empty());
        
        let _debug = format!("{:?}", state);
    }
}
