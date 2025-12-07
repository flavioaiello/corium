//! Parallel path probing, discovery protocol, and connection manager.
//! Extracted from the legacy `net.rs` for modularity.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use getrandom::getrandom;
use lru::LruCache;
use quinn::Connection;
use tokio::sync::RwLock;
use tracing::{debug, info, trace};

use crate::identity::Identity;

use super::connection::SmartConnection;

/// Probe interval for checking alternate paths.
pub const PATH_PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// How long before a path is considered stale without probes.
pub const PATH_STALE_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum number of probe failures before marking path as dead.
pub const MAX_PROBE_FAILURES: u32 = 3;
/// Maximum candidate paths per connection.
const MAX_CANDIDATE_PATHS: usize = 16;
/// Maximum pending probes to track.
const MAX_PENDING_PROBES: usize = 64;
/// Maximum number of path probers to track.
pub const MAX_PATH_PROBERS: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Unknown,
    Probing,
    Active,
    Failed,
}

#[derive(Debug, Clone)]
pub struct PathCandidate {
    pub addr: SocketAddr,
    pub state: PathState,
    pub is_relay: bool,
    pub rtt_ms: Option<f32>,
    pub last_success: Option<Instant>,
    pub last_probe: Option<Instant>,
    pub failures: u32,
    probe_seq: u64,
}

impl PathCandidate {
    pub fn new(addr: SocketAddr, is_relay: bool) -> Self {
        Self {
            addr,
            state: PathState::Unknown,
            is_relay,
            rtt_ms: None,
            last_success: None,
            last_probe: None,
            failures: 0,
            probe_seq: 0,
        }
    }

    pub fn needs_probe(&self) -> bool {
        match self.state {
            PathState::Failed => false,
            PathState::Unknown => true,
            PathState::Probing | PathState::Active => self
                .last_probe
                .map(|t| t.elapsed() >= PATH_PROBE_INTERVAL)
                .unwrap_or(true),
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self.state, PathState::Active | PathState::Probing)
            && self
                .last_success
                .map(|t| t.elapsed() < PATH_STALE_TIMEOUT)
                .unwrap_or(false)
    }

    pub fn record_success(&mut self, rtt: Duration) {
        let rtt_ms = rtt.as_secs_f32() * 1000.0;
        self.rtt_ms = Some(match self.rtt_ms {
            Some(prev) => prev * 0.8 + rtt_ms * 0.2,
            None => rtt_ms,
        });
        self.state = PathState::Active;
        self.last_success = Some(Instant::now());
        self.failures = 0;
    }

    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= MAX_PROBE_FAILURES {
            self.state = PathState::Failed;
        }
    }
}

#[derive(Debug)]
pub struct PathProber {
    connection: Connection,
    local_endpoint_key: [u8; 32],
    paths: Vec<PathCandidate>,
    active_path: usize,
    next_probe_seq: u64,
    probe_seq_offset: u64,
    pending_probes: HashMap<u64, (usize, Instant)>,
}

impl PathProber {
    pub fn new(connection: Connection, initial_addr: SocketAddr, is_relay: bool) -> Self {
        Self::with_endpoint_key(connection, initial_addr, is_relay, [0u8; 32])
    }

    pub fn with_endpoint_key(
        connection: Connection,
        initial_addr: SocketAddr,
        is_relay: bool,
        endpoint_key: [u8; 32],
    ) -> Self {
        let mut offset_bytes = [0u8; 8];
        if getrandom(&mut offset_bytes).is_err() {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            offset_bytes = ts.to_le_bytes();
        }
        let probe_seq_offset = u64::from_le_bytes(offset_bytes);

        Self {
            connection,
            local_endpoint_key: endpoint_key,
            paths: vec![PathCandidate::new(initial_addr, is_relay)],
            active_path: 0,
            next_probe_seq: 1,
            probe_seq_offset,
            pending_probes: HashMap::new(),
        }
    }

    pub fn add_candidate(&mut self, addr: SocketAddr, is_relay: bool) -> bool {
        if self.paths.iter().any(|p| p.addr == addr) {
            return false;
        }
        if self.paths.len() >= MAX_CANDIDATE_PATHS {
            return false;
        }
        self.paths.push(PathCandidate::new(addr, is_relay));
        true
    }

    pub fn add_direct_candidates(&mut self, addrs: &[String]) {
        for addr_str in addrs {
            if let Ok(addr) = addr_str.parse() {
                let _ = self.add_candidate(addr, false);
            }
        }
    }

    pub fn active_addr(&self) -> SocketAddr {
        self.paths[self.active_path].addr
    }

    pub fn is_using_relay(&self) -> bool {
        self.paths[self.active_path].is_relay
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn active_rtt_ms(&self) -> Option<f32> {
        self.paths[self.active_path].rtt_ms
    }

    pub fn path_stats(&self) -> Vec<PathStats> {
        self.paths
            .iter()
            .enumerate()
            .map(|(i, p)| PathStats {
                addr: p.addr,
                is_relay: p.is_relay,
                is_active: i == self.active_path,
                state: p.state,
                rtt_ms: p.rtt_ms,
            })
            .collect()
    }

    fn select_best_path(&self) -> Option<usize> {
        let usable: Vec<_> = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_usable())
            .collect();

        if usable.is_empty() {
            return None;
        }

        let best_direct = usable
            .iter()
            .filter(|(_, p)| !p.is_relay)
            .min_by(|(_, a), (_, b)| a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal));

        let best_relay = usable
            .iter()
            .filter(|(_, p)| p.is_relay)
            .min_by(|(_, a), (_, b)| a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal));

        match (best_direct, best_relay) {
            (Some((di, dp)), Some((ri, rp))) => {
                let direct_rtt = dp.rtt_ms.unwrap_or(f32::MAX);
                let relay_rtt = rp.rtt_ms.unwrap_or(f32::MAX);
                if relay_rtt + 50.0 < direct_rtt {
                    Some(*ri)
                } else {
                    Some(*di)
                }
            }
            (Some((i, _)), None) => Some(*i),
            (None, Some((i, _))) => Some(*i),
            (None, None) => None,
        }
    }

    pub fn select_path(&mut self, path_index: usize) -> Option<(SocketAddr, SocketAddr)> {
        if path_index >= self.paths.len() {
            return None;
        }

        let new_addr = self.paths[path_index].addr;
        let old_addr = self.paths[self.active_path].addr;

        if new_addr != old_addr {
            let old_is_relay = self.paths[self.active_path].is_relay;
            let new_is_relay = self.paths[path_index].is_relay;
            info!(
                from = %old_addr,
                to = %new_addr,
                from_relay = old_is_relay,
                to_relay = new_is_relay,
                "selected new preferred path"
            );
            self.active_path = path_index;
            return Some((old_addr, new_addr));
        }

        self.active_path = path_index;
        None
    }

    pub fn maybe_switch_path(&mut self) -> Option<(SocketAddr, SocketAddr)> {
        if let Some(best) = self.select_best_path() {
            if best != self.active_path {
                return self.select_path(best);
            }
        }
        None
    }

    pub fn preferred_addr(&self) -> SocketAddr {
        self.paths[self.active_path].addr
    }

    pub fn has_direct_path(&self) -> bool {
        self.paths
            .iter()
            .any(|p| !p.is_relay && p.state == PathState::Active)
    }

    pub fn generate_probes(&mut self) -> Vec<(SocketAddr, PathProbe)> {
        let now = Instant::now();
        let mut probes = Vec::new();

        for (idx, path) in self.paths.iter_mut().enumerate() {
            if self.pending_probes.len() >= MAX_PENDING_PROBES {
                debug!(pending = self.pending_probes.len(), "pending probes limit reached, skipping new probes");
                break;
            }

            if path.needs_probe() {
                let seq = self.next_probe_seq.wrapping_add(self.probe_seq_offset);
                self.next_probe_seq = self.next_probe_seq.wrapping_add(1);

                path.probe_seq = seq;
                path.last_probe = Some(now);
                path.state = PathState::Probing;

                self.pending_probes.insert(seq, (idx, now));
                probes.push((path.addr, PathProbe::new(seq, self.local_endpoint_key)));
            }
        }

        probes
    }

    pub fn handle_probe_response(&mut self, seq: u64) -> bool {
        if let Some((path_idx, send_time)) = self.pending_probes.remove(&seq) {
            let rtt = send_time.elapsed();
            if path_idx >= self.paths.len() {
                debug!(seq = seq, path_idx = path_idx, "probe response for invalid path index");
                return false;
            }
            if let Some(path) = self.paths.get_mut(path_idx) {
                path.record_success(rtt);
                debug!(addr = %path.addr, rtt_ms = rtt.as_secs_f32() * 1000.0, is_relay = path.is_relay, "probe response received");
            }
            return self.maybe_switch_path().is_some();
        }
        trace!(seq = seq, "probe response for unknown sequence, ignoring");
        false
    }

    pub fn expire_probes(&mut self, timeout: Duration) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .pending_probes
            .iter()
            .filter(|(_, (_, send_time))| now.duration_since(*send_time) > timeout)
            .map(|(seq, (idx, _))| (*seq, *idx))
            .collect();

        for (seq, path_idx) in expired {
            self.pending_probes.remove(&seq);
            if let Some(path) = self.paths.get_mut(path_idx) {
                path.record_failure();
                debug!(addr = %path.addr, "probe timeout");
            }
        }
    }

    pub fn cleanup_stale_paths(&mut self) {
        let active_addr = self.paths[self.active_path].addr;
        self.paths.retain(|p| p.state != PathState::Failed || p.addr == active_addr);
        self.active_path = self
            .paths
            .iter()
            .position(|p| p.addr == active_addr)
            .unwrap_or(0);
    }
}

/// Magic bytes for path discovery messages.
const PATH_MAGIC: &[u8; 4] = b"QMPD";
const MSG_PATH_PROBE: u8 = 0x01;
const MSG_PATH_REPLY: u8 = 0x02;
const MSG_REACH_ME: u8 = 0x03;

#[derive(Debug, Clone)]
pub struct PathProbe {
    pub tx_id: u64,
    pub endpoint_key: [u8; 32],
    pub timestamp_ms: u64,
}

impl PathProbe {
    pub fn new(tx_id: u64, endpoint_key: [u8; 32]) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            tx_id,
            endpoint_key,
            timestamp_ms,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(53);
        buf.extend_from_slice(PATH_MAGIC);
        buf.push(MSG_PATH_PROBE);
        buf.extend_from_slice(&self.tx_id.to_le_bytes());
        buf.extend_from_slice(&self.endpoint_key);
        buf.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 53 || &data[0..4] != PATH_MAGIC || data[4] != MSG_PATH_PROBE {
            return None;
        }
        Some(Self {
            tx_id: u64::from_le_bytes(data[5..13].try_into().ok()?),
            endpoint_key: data[13..45].try_into().ok()?,
            timestamp_ms: u64::from_le_bytes(data[45..53].try_into().ok()?),
        })
    }

    pub fn to_reply(&self, observed_addr: SocketAddr) -> PathReply {
        PathReply {
            tx_id: self.tx_id,
            observed_addr,
            echo_timestamp_ms: self.timestamp_ms,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PathReply {
    pub tx_id: u64,
    pub observed_addr: SocketAddr,
    pub echo_timestamp_ms: u64,
}

impl PathReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(PATH_MAGIC);
        buf.push(MSG_PATH_REPLY);
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
        if data.len() < 23 || &data[0..4] != PATH_MAGIC || data[4] != MSG_PATH_REPLY {
            return None;
        }

        let tx_id = u64::from_le_bytes(data[5..13].try_into().ok()?);
        let echo_timestamp_ms = u64::from_le_bytes(data[13..21].try_into().ok()?);

        let observed_addr = match data[21] {
            4 if data.len() >= 28 => {
                let ip = Ipv4Addr::new(data[22], data[23], data[24], data[25]);
                let port = u16::from_le_bytes(data[26..28].try_into().ok()?);
                SocketAddr::from((ip, port))
            }
            6 if data.len() >= 40 => {
                let octets: [u8; 16] = data[22..38].try_into().ok()?;
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_le_bytes(data[38..40].try_into().ok()?);
                SocketAddr::from((ip, port))
            }
            _ => return None,
        };

        Some(Self {
            tx_id,
            observed_addr,
            echo_timestamp_ms,
        })
    }

    pub fn rtt_ms(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        now.saturating_sub(self.echo_timestamp_ms)
    }
}

#[derive(Debug, Clone)]
pub struct ReachMe {
    pub endpoint_key: [u8; 32],
    pub endpoints: Vec<SocketAddr>,
}

impl ReachMe {
    pub fn new(endpoint_key: [u8; 32], endpoints: Vec<SocketAddr>) -> Self {
        Self { endpoint_key, endpoints }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(37 + self.endpoints.len() * 19);
        buf.extend_from_slice(PATH_MAGIC);
        buf.push(MSG_REACH_ME);
        buf.extend_from_slice(&self.endpoint_key);
        buf.push(self.endpoints.len() as u8);

        for addr in &self.endpoints {
            match addr {
                SocketAddr::V4(a) => {
                    buf.push(4);
                    buf.extend_from_slice(&a.ip().octets());
                    buf.extend_from_slice(&a.port().to_le_bytes());
                }
                SocketAddr::V6(a) => {
                    buf.push(6);
                    buf.extend_from_slice(&a.ip().octets());
                    buf.extend_from_slice(&a.port().to_le_bytes());
                }
            }
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 38 || &data[0..4] != PATH_MAGIC || data[4] != MSG_REACH_ME {
            return None;
        }

        let endpoint_key: [u8; 32] = data[5..37].try_into().ok()?;
        let count = data[37] as usize;

        let min_bytes_needed = 38 + count * 7;
        if data.len() < min_bytes_needed {
            return None;
        }
        const MAX_ENDPOINTS: usize = 64;
        if count > MAX_ENDPOINTS {
            return None;
        }

        let mut endpoints = Vec::with_capacity(count);
        let mut pos = 38;

        for _ in 0..count {
            if pos >= data.len() {
                break;
            }
            match data[pos] {
                4 if pos + 7 <= data.len() => {
                    let ip = Ipv4Addr::new(data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]);
                    let port = u16::from_le_bytes(data[pos + 5..pos + 7].try_into().ok()?);
                    endpoints.push(SocketAddr::from((ip, port)));
                    pos += 7;
                }
                6 if pos + 19 <= data.len() => {
                    let octets: [u8; 16] = data[pos + 1..pos + 17].try_into().ok()?;
                    let ip = Ipv6Addr::from(octets);
                    let port = u16::from_le_bytes(data[pos + 17..pos + 19].try_into().ok()?);
                    endpoints.push(SocketAddr::from((ip, port)));
                    pos += 19;
                }
                _ => break,
            }
        }

        Some(Self { endpoint_key, endpoints })
    }
}

#[derive(Debug, Clone)]
pub enum PathMessage {
    Probe(PathProbe),
    Reply(PathReply),
    ReachMe(ReachMe),
}

impl PathMessage {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 5 || &data[0..4] != PATH_MAGIC {
            return None;
        }
        match data[4] {
            MSG_PATH_PROBE => PathProbe::from_bytes(data).map(PathMessage::Probe),
            MSG_PATH_REPLY => PathReply::from_bytes(data).map(PathMessage::Reply),
            MSG_REACH_ME => ReachMe::from_bytes(data).map(PathMessage::ReachMe),
            _ => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PathMessage::Probe(p) => p.to_bytes(),
            PathMessage::Reply(r) => r.to_bytes(),
            PathMessage::ReachMe(r) => r.to_bytes(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PathStats {
    pub addr: SocketAddr,
    pub is_relay: bool,
    pub is_active: bool,
    pub state: PathState,
    pub rtt_ms: Option<f32>,
}

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

pub struct ConnectionManager {
    probers: RwLock<LruCache<Identity, PathProber>>,
    probe_socket: RwLock<Option<Arc<tokio::net::UdpSocket>>>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            probers: RwLock::new(LruCache::new(NonZeroUsize::new(MAX_PATH_PROBERS).unwrap())),
            probe_socket: RwLock::new(None),
        }
    }

    pub async fn register_with_paths(
        &self,
        peer_id: Identity,
        connection: Connection,
        initial_addr: SocketAddr,
        is_relay: bool,
        direct_addrs: &[String],
    ) {
        let mut prober = PathProber::new(connection, initial_addr, is_relay);
        prober.add_direct_candidates(direct_addrs);

        let mut probers = self.probers.write().await;
        probers.put(peer_id, prober);
    }

    pub async fn register(&self, peer_id: Identity, smart_conn: SmartConnection) {
        let (connection, initial_addr, is_relay, direct_addrs) = match &smart_conn {
            SmartConnection::Direct(conn) => {
                let addr = conn.remote_address();
                (conn.clone(), addr, false, vec![])
            }
            SmartConnection::RelayPending { relay_connection, direct_addrs, .. }
            | SmartConnection::Relayed { relay_connection, direct_addrs, .. } => {
                let addr = relay_connection.remote_address();
                (relay_connection.clone(), addr, true, direct_addrs.clone())
            }
        };

        self.register_with_paths(peer_id, connection, initial_addr, is_relay, &direct_addrs).await;
    }

    pub async fn add_direct_candidates(&self, peer_id: &Identity, addrs: &[String]) {
        let mut probers = self.probers.write().await;
        if let Some(prober) = probers.get_mut(peer_id) {
            prober.add_direct_candidates(addrs);
        }
    }

    pub async fn get(&self, peer_id: &Identity) -> Option<Connection> {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| p.connection().clone())
    }

    pub async fn is_direct(&self, peer_id: &Identity) -> bool {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| !p.is_using_relay()).unwrap_or(false)
    }

    pub async fn active_rtt_ms(&self, peer_id: &Identity) -> Option<f32> {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).and_then(|p| p.active_rtt_ms())
    }

    pub async fn remove(&self, peer_id: &Identity) {
        let mut probers = self.probers.write().await;
        probers.pop(peer_id);
    }

    pub async fn probe_all_paths(&self) {
        let probes: Vec<(Identity, Vec<(SocketAddr, PathProbe)>)> = {
            let mut probers = self.probers.write().await;
            probers
                .iter_mut()
                .map(|(peer_id, prober)| {
                    prober.expire_probes(PROBE_TIMEOUT);
                    (*peer_id, prober.generate_probes())
                })
                .filter(|(_, probes)| !probes.is_empty())
                .collect()
        };

        for (peer_id, path_probes) in probes {
            for (addr, probe) in path_probes {
                if let Err(e) = self.send_probe(addr, &probe).await {
                    debug!(peer = ?peer_id, addr = %addr, error = %e, "failed to send probe");
                }
            }
        }
    }

    async fn send_probe(&self, addr: SocketAddr, probe: &PathProbe) -> Result<()> {
        let probe_bytes = probe.to_bytes();

        let socket = {
            let mut socket_guard = self.probe_socket.write().await;
            if socket_guard.is_none() {
                let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                *socket_guard = Some(Arc::new(udp));
            }
            socket_guard.as_ref().unwrap().clone()
        };

        socket.send_to(&probe_bytes, addr).await?;
        debug!(addr = %addr, seq = probe.tx_id, "sent probe");
        Ok(())
    }

    pub async fn handle_probe_response(&self, peer_id: &Identity, seq: u64) -> bool {
        let mut probers = self.probers.write().await;
        if let Some(prober) = probers.get_mut(peer_id) {
            let better_path_found = prober.handle_probe_response(seq);
            if better_path_found {
                let addr = prober.preferred_addr();
                info!(peer = ?peer_id, addr = %addr, "better path found, QUIC will migrate on next send");
            }
            return better_path_found;
        }
        false
    }

    pub async fn preferred_addr(&self, peer_id: &Identity) -> Option<SocketAddr> {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| p.preferred_addr())
    }

    pub async fn has_direct_path(&self, peer_id: &Identity) -> bool {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| p.has_direct_path()).unwrap_or(false)
    }

    pub fn spawn_probe_loop(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PATH_PROBE_INTERVAL);
            loop {
                interval.tick().await;
                self.probe_all_paths().await;
            }
        })
    }

    pub async fn path_stats(&self, peer_id: &Identity) -> Option<Vec<PathStats>> {
        let mut probers = self.probers.write().await;
        probers.get(peer_id).map(|p| p.path_stats())
    }

    pub async fn stats(&self) -> ConnectionStats {
        let probers = self.probers.write().await;
        let total = probers.len();
        let direct = probers.iter().filter(|(_, p)| !p.is_using_relay()).count();
        let relayed = total - direct;
        let upgradeable = probers
            .iter()
            .filter(|(_, p)| p.is_using_relay() && p.paths.iter().any(|path| !path.is_relay))
            .count();

        ConnectionStats {
            total,
            direct,
            relayed,
            upgradeable,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub total: usize,
    pub direct: usize,
    pub relayed: usize,
    pub upgradeable: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_candidate_rtt_smoothing() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut path = PathCandidate::new(addr, false);
        
        assert_eq!(path.state, PathState::Unknown);
        assert!(path.rtt_ms.is_none());
        
        // First RTT measurement
        path.record_success(Duration::from_millis(100));
        assert_eq!(path.rtt_ms, Some(100.0));
        assert_eq!(path.state, PathState::Active);
        
        // Second measurement - EMA smoothing (0.8 * 100 + 0.2 * 50 = 90)
        path.record_success(Duration::from_millis(50));
        assert!((path.rtt_ms.unwrap() - 90.0).abs() < 0.1);
        
        // Third measurement - EMA continues
        path.record_success(Duration::from_millis(50));
        assert!((path.rtt_ms.unwrap() - 82.0).abs() < 0.1);
    }

    #[test]
    fn test_path_candidate_failure_handling() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut path = PathCandidate::new(addr, false);
        
        // Mark active first
        path.record_success(Duration::from_millis(50));
        assert_eq!(path.state, PathState::Active);
        assert_eq!(path.failures, 0);
        
        // Failures accumulate
        path.record_failure();
        assert_eq!(path.failures, 1);
        assert_eq!(path.state, PathState::Active);
        
        path.record_failure();
        assert_eq!(path.failures, 2);
        assert_eq!(path.state, PathState::Active);
        
        // Third failure marks as failed
        path.record_failure();
        assert_eq!(path.failures, 3);
        assert_eq!(path.state, PathState::Failed);
    }

    #[test]
    fn test_path_probe_serialization() {
        let endpoint_key = [0x42u8; 32];
        let probe = PathProbe::new(0x123456789ABCDEF0, endpoint_key);
        
        let bytes = probe.to_bytes();
        assert_eq!(&bytes[0..4], PATH_MAGIC);
        assert_eq!(bytes[4], MSG_PATH_PROBE);
        
        let parsed = PathProbe::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.tx_id, probe.tx_id);
        assert_eq!(parsed.endpoint_key, endpoint_key);
        assert_eq!(parsed.timestamp_ms, probe.timestamp_ms);
    }

    #[test]
    fn test_path_reply_serialization() {
        let observed_addr: SocketAddr = "203.0.113.5:12345".parse().unwrap();
        let reply = PathReply {
            tx_id: 42,
            observed_addr,
            echo_timestamp_ms: 12345,
        };
        
        let bytes = reply.to_bytes();
        assert_eq!(&bytes[0..4], PATH_MAGIC);
        assert_eq!(bytes[4], MSG_PATH_REPLY);
        
        let parsed = PathReply::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.tx_id, reply.tx_id);
        assert_eq!(parsed.observed_addr, reply.observed_addr);
        assert_eq!(parsed.echo_timestamp_ms, reply.echo_timestamp_ms);
    }

    #[test]
    fn test_reach_me_serialization() {
        let endpoint_key = [0xAB; 32];
        let endpoints = vec![
            "192.168.1.1:8080".parse().unwrap(),
            "[2001:db8::1]:9090".parse().unwrap(),
        ];
        let reach = ReachMe::new(endpoint_key, endpoints.clone());
        
        let bytes = reach.to_bytes();
        assert_eq!(&bytes[0..4], PATH_MAGIC);
        assert_eq!(bytes[4], MSG_REACH_ME);
        
        let parsed = ReachMe::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.endpoint_key, endpoint_key);
        assert_eq!(parsed.endpoints.len(), 2);
        assert_eq!(parsed.endpoints[0], endpoints[0]);
        assert_eq!(parsed.endpoints[1], endpoints[1]);
    }

    #[test]
    fn test_path_selection_prefers_direct() {
        let direct_addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let relay_addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        
        let mut paths = [
            PathCandidate::new(relay_addr, true),
            PathCandidate::new(direct_addr, false),
        ];
        
        // Both paths active with same RTT - should prefer direct (index 1)
        paths[0].record_success(Duration::from_millis(50));
        paths[1].record_success(Duration::from_millis(50));
        
        // Simulate selection logic
        let usable: Vec<_> = paths.iter().enumerate()
            .filter(|(_, p)| p.is_usable())
            .collect();
        
        let best_direct = usable.iter()
            .filter(|(_, p)| !p.is_relay)
            .min_by(|(_, a), (_, b)| {
                a.rtt_ms.partial_cmp(&b.rtt_ms).unwrap_or(std::cmp::Ordering::Equal)
            });
        
        assert!(best_direct.is_some());
        assert_eq!(best_direct.unwrap().0, 1); // Direct path at index 1
    }

    #[test]
    fn test_path_selection_relay_faster_threshold() {
        let direct_addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let relay_addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        
        let mut paths = [
            PathCandidate::new(relay_addr, true),
            PathCandidate::new(direct_addr, false),
        ];
        
        // Relay is 60ms faster (above 50ms threshold) - should prefer relay
        paths[0].record_success(Duration::from_millis(40));
        paths[1].record_success(Duration::from_millis(100));
        
        let relay_rtt = paths[0].rtt_ms.unwrap();
        let direct_rtt = paths[1].rtt_ms.unwrap();
        
        // Relay + 50 < direct means relay is preferred
        assert!(relay_rtt + 50.0 < direct_rtt);
    }
}
