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
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::identity::Identity;
use crate::messages::{RelayRequest, RelayResponse};


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
    pub addr: String,
    #[serde(default)]
    pub addrs: Vec<String>,
}

impl Contact {
    pub fn single(identity: Identity, addr: impl Into<String>) -> Self {
        Self {
            identity,
            addr: addr.into(),
            addrs: Vec::new(),
        }
    }

    pub fn all_addrs<'a>(&'a self) -> impl Iterator<Item = &'a str> + 'a {
        std::iter::once(self.addr.as_str()).chain(self.addrs.iter().map(|s| s.as_str()))
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


pub const RELAY_MAGIC: [u8; 4] = *b"CRLY";
pub const RELAY_HEADER_SIZE: usize = 20;
pub const MAX_SESSIONS: usize = 10_000;
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
pub const PENDING_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_SMARTSOCK_PEERS: usize = 10_000;

pub const MAX_RELAY_FRAME_SIZE: usize = 1400;
pub const PROBE_MAGIC: [u8; 4] = *b"SMPR";
pub const PROBE_TYPE_REQUEST: u8 = 0x01;
pub const PROBE_TYPE_RESPONSE: u8 = 0x02;
pub const PROBE_HEADER_SIZE: usize = 21;
pub const PATH_PROBE_INTERVAL: Duration = Duration::from_secs(5);
pub const PATH_STALE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_PROBE_FAILURES: u32 = 3;
const RELAY_RTT_ADVANTAGE_MS: f32 = 50.0;
const RTT_EMA_OLD: f32 = 0.8;
const RTT_EMA_NEW: f32 = 0.2;

const MAX_PENDING_PROBES_PER_PEER: usize = 64;
const MAX_CANDIDATES_PER_PEER: usize = 24;
const MAX_DIRECT_ADDRS_PER_PEER: usize = 16;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError {
    pub code: Option<u32>,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(code) => write!(f, "CSPRNG unavailable (error code {})", code),
            None => write!(f, "CSPRNG unavailable"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<getrandom::Error> for CryptoError {
    fn from(err: getrandom::Error) -> Self {
        Self { code: Some(err.code().get()) }
    }
}

pub fn generate_session_id() -> Result<[u8; 16], CryptoError> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id)?;
    Ok(id)
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ForwarderSession {
    pub session_id: [u8; 16],
    pub peer_a_identity: Identity,
    pub peer_b_identity: Identity,
    pub peer_a_addr: SocketAddr,
    pub peer_b_addr: Option<SocketAddr>,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub bytes_forwarded: u64,
    pub packets_forwarded: u64,
    pub completion_locked: bool,
}

impl ForwarderSession {
    pub fn new_pending(
        session_id: [u8; 16],
        peer_a_identity: Identity,
        peer_b_identity: Identity,
        peer_a_addr: SocketAddr,
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            peer_a_identity,
            peer_b_identity,
            peer_a_addr,
            peer_b_addr: None,
            created_at: now,
            last_activity: now,
            bytes_forwarded: 0,
            packets_forwarded: 0,
            completion_locked: false,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.peer_b_addr.is_some()
    }

    pub fn is_expired(&self) -> bool {
        if self.is_complete() {
            self.last_activity.elapsed() > SESSION_TIMEOUT
        } else {
            self.last_activity.elapsed() > PENDING_SESSION_TIMEOUT
        }
    }

    pub fn get_destination(&self, from: SocketAddr) -> Option<SocketAddr> {
        if from == self.peer_a_addr {
            self.peer_b_addr
        } else if self.peer_b_addr == Some(from) {
            Some(self.peer_a_addr)
        } else {
            None
        }
    }

    pub fn record_forward(&mut self, bytes: usize) {
        self.last_activity = Instant::now();
        self.bytes_forwarded += bytes as u64;
        self.packets_forwarded += 1;
    }
}

#[derive(Debug)]
pub struct UdpRelayForwarder {
    socket: Arc<UdpSocket>,
    sessions: RwLock<HashMap<[u8; 16], ForwarderSession>>,
    addr_to_session: RwLock<HashMap<SocketAddr, [u8; 16]>>,
}

impl UdpRelayForwarder {
    #[allow(dead_code)]
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        info!(addr = %socket.local_addr()?, "UDP relay forwarder started");
        
        Ok(Self {
            socket: Arc::new(socket),
            sessions: RwLock::new(HashMap::new()),
            addr_to_session: RwLock::new(HashMap::new()),
        })
    }

    pub fn with_socket(socket: Arc<UdpSocket>) -> Arc<Self> {
        let forwarder = Arc::new(Self {
            socket,
            sessions: RwLock::new(HashMap::new()),
            addr_to_session: RwLock::new(HashMap::new()),
        });
        forwarder.clone().spawn_cleanup();
        forwarder
    }

    #[allow(dead_code)]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn register_session(
        &self,
        session_id: [u8; 16],
        peer_a_addr: SocketAddr,
        peer_a_identity: Identity,
        peer_b_identity: Identity,
    ) -> Result<(), &'static str> {
        let mut sessions = self.sessions.write().await;
        
        if sessions.len() >= MAX_SESSIONS {
            return Err("max sessions reached");
        }
        
        if sessions.contains_key(&session_id) {
            return Err("session already exists");
        }
        
        let session = ForwarderSession::new_pending(
            session_id,
            peer_a_identity,
            peer_b_identity,
            peer_a_addr,
        );
        sessions.insert(session_id, session);
        
        let mut addr_map = self.addr_to_session.write().await;
        addr_map.insert(peer_a_addr, session_id);
        
        debug!(
            session = hex::encode(session_id),
            peer_a = %peer_a_addr,
            "registered relay session (waiting for peer B)"
        );
        
        Ok(())
    }

    pub async fn complete_session(
        &self,
        session_id: [u8; 16],
        peer_b_addr: SocketAddr,
        from_peer: Identity,
        target_peer: Identity,
    ) -> Result<(), &'static str> {
        let mut sessions = self.sessions.write().await;
        
        let session = sessions.get_mut(&session_id)
            .ok_or("session not found")?;

        if session.peer_b_identity != from_peer || session.peer_a_identity != target_peer {
            return Err("peer identity mismatch");
        }
        
        if session.peer_b_addr.is_some() {
            return Err("session already complete");
        }
        
        session.completion_locked = true;
        session.peer_b_addr = Some(peer_b_addr);
        session.last_activity = Instant::now();
        
        let mut addr_map = self.addr_to_session.write().await;
        addr_map.insert(peer_b_addr, session_id);
        
        debug!(
            session = hex::encode(session_id),
            peer_a = %session.peer_a_addr,
            peer_b = %peer_b_addr,
            "relay session complete"
        );
        
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn remove_session(&self, session_id: &[u8; 16]) {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.remove(session_id) {
            let mut addr_map = self.addr_to_session.write().await;
            addr_map.remove(&session.peer_a_addr);
            if let Some(peer_b) = session.peer_b_addr {
                addr_map.remove(&peer_b);
            }
            
            debug!(
                session = hex::encode(session_id),
                packets = session.packets_forwarded,
                bytes = session.bytes_forwarded,
                "removed relay session"
            );
        }
    }

    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let mut addr_map = self.addr_to_session.write().await;
        
        let before = sessions.len();
        
        sessions.retain(|session_id, session| {
            if session.is_expired() {
                addr_map.remove(&session.peer_a_addr);
                if let Some(peer_b) = session.peer_b_addr {
                    addr_map.remove(&peer_b);
                }
                trace!(
                    session = hex::encode(session_id),
                    "expired relay session"
                );
                false
            } else {
                true
            }
        });
        
        let removed = before - sessions.len();
        if removed > 0 {
            debug!(removed = removed, remaining = sessions.len(), "cleaned up expired sessions");
        }
        removed
    }

    pub async fn process_packet(&self, data: &[u8], from: SocketAddr) -> usize {
        if data.len() < RELAY_HEADER_SIZE {
            trace!(from = %from, len = data.len(), "dropping undersized packet");
            return 0;
        }
        
        if data[0..4] != RELAY_MAGIC {
            trace!(from = %from, "dropping non-CRLY packet");
            return 0;
        }
        
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[4..20]);
        
        let dest = {
            let mut sessions = self.sessions.write().await;
            
            let session = match sessions.get_mut(&session_id) {
                Some(s) => s,
                None => {
                    trace!(
                        session = hex::encode(session_id),
                        from = %from,
                        "dropping packet for unknown session"
                    );
                    return 0;
                }
            };
            
            if !session.is_complete() && !session.completion_locked && from != session.peer_a_addr {
                session.completion_locked = true;
                session.peer_b_addr = Some(from);

                let dest = session.get_destination(from);
                if dest.is_some() {
                    session.record_forward(data.len());
                }
                
                drop(sessions);
                let mut addr_map = self.addr_to_session.write().await;
                addr_map.insert(from, session_id);

                dest
            } else {
                let dest = session.get_destination(from);
                if dest.is_some() {
                    session.record_forward(data.len());
                }
                dest
            }
        };
        
        let dest = match dest {
            Some(d) => d,
            None => {
                trace!(
                    session = hex::encode(session_id),
                    from = %from,
                    "dropping packet from non-participant"
                );
                return 0;
            }
        };
        
        match self.socket.send_to(data, dest).await {
            Ok(sent) => {
                trace!(
                    session = hex::encode(&session_id[..4]),
                    from = %from,
                    to = %dest,
                    len = sent,
                    "forwarded relay packet"
                );
                sent
            }
            Err(e) => {
                warn!(
                    session = hex::encode(session_id),
                    dest = %dest,
                    error = %e,
                    "failed to forward relay packet"
                );
                0
            }
        }
    }

    pub async fn run_cleanup(&self) {
        let mut cleanup_interval = tokio::time::interval(CLEANUP_INTERVAL);
        
        loop {
            cleanup_interval.tick().await;
            self.cleanup_expired().await;
        }
    }

    pub fn spawn_cleanup(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run_cleanup().await;
        })
    }
}

pub async fn handle_relay_request(
    request: RelayRequest,
    remote_addr: SocketAddr,
    forwarder: Option<&UdpRelayForwarder>,
    forwarder_addr: Option<SocketAddr>,
) -> RelayResponse {
    match request {
        RelayRequest::Connect {
            from_peer,
            target_peer,
            session_id,
        } => {
            debug!(
                from = ?from_peer,
                target = ?target_peer,
                session = hex::encode(session_id),
                "handling RELAY_CONNECT request"
            );

            let forwarder = match forwarder {
                Some(f) => f,
                None => {
                    return RelayResponse::Rejected {
                        reason: "relay not available".to_string(),
                    };
                }
            };

            let relay_data_addr = match forwarder_addr {
                Some(addr) => addr.to_string(),
                None => {
                    return RelayResponse::Rejected {
                        reason: "relay address not configured".to_string(),
                    };
                }
            };

            let session_count = forwarder.session_count().await;
            if session_count >= MAX_SESSIONS {
                return RelayResponse::Rejected {
                    reason: "relay server at capacity".to_string(),
                };
            }

            match forwarder
                .register_session(session_id, remote_addr, from_peer, target_peer)
                .await
            {
                Ok(()) => {
                    debug!(
                        session = hex::encode(session_id),
                        peer = %remote_addr,
                        "relay session pending (waiting for peer B)"
                    );
                    RelayResponse::Accepted {
                        session_id,
                        relay_data_addr,
                    }
                }
                Err("session already exists") => {
                    match forwarder
                        .complete_session(session_id, remote_addr, from_peer, target_peer)
                        .await
                    {
                        Ok(()) => {
                            debug!(
                                session = hex::encode(session_id),
                                peer = %remote_addr,
                                "relay session established"
                            );
                            RelayResponse::Connected {
                                session_id,
                                relay_data_addr,
                            }
                        }
                        Err(e) => {
                            warn!(
                                session = hex::encode(session_id),
                                error = e,
                                "failed to complete relay session"
                            );
                            RelayResponse::Rejected {
                                reason: e.to_string(),
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        session = hex::encode(session_id),
                        error = e,
                        "failed to register relay session"
                    );
                    RelayResponse::Rejected {
                        reason: e.to_string(),
                    }
                }
            }
        }
    }
}


#[derive(Debug, Clone)]
pub struct RelayTunnel {
    pub session_id: [u8; 16],
    pub relay_addr: SocketAddr,
    #[allow(dead_code)]
    pub peer_identity: Identity,
    #[allow(dead_code)]
    pub established_at: Instant,
    #[allow(dead_code)]
    pub last_activity: Instant,
}

impl RelayTunnel {
    pub fn new(session_id: [u8; 16], relay_addr: SocketAddr, peer_identity: Identity) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            relay_addr,
            peer_identity,
            established_at: now,
            last_activity: now,
        }
    }
    
    pub fn encode_frame(&self, quic_packet: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(RELAY_HEADER_SIZE + quic_packet.len());
        frame.extend_from_slice(&RELAY_MAGIC);
        frame.extend_from_slice(&self.session_id);
        frame.extend_from_slice(quic_packet);
        frame
    }
    
    pub fn decode_frame(data: &[u8]) -> Option<([u8; 16], &[u8])> {
        if data.len() < RELAY_HEADER_SIZE {
            return None;
        }
        
        if data[0..4] != RELAY_MAGIC {
            return None;
        }
        
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[4..20]);
        
        let payload = &data[RELAY_HEADER_SIZE..];
        
        Some((session_id, payload))
    }
}

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
    #[allow(dead_code)]
    pub last_send: Option<Instant>,
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
        
        let mut counter_bytes = [0u8; 8];
        getrandom::getrandom(&mut counter_bytes)
            .expect("CSPRNG failure: system random number generator unavailable");
        let next_probe_counter = u64::from_le_bytes(counter_bytes);
        
        Self {
            identity,
            direct_addrs: Vec::new(),
            relay_tunnels: HashMap::new(),
            active_path: None,
            last_send: None,
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

    #[allow(dead_code)]
    pub fn active_tunnel(&self) -> Option<&RelayTunnel> {
        match &self.active_path {
            Some(PathChoice::Relay { session_id, .. }) => {
                self.relay_tunnels.get(session_id)
            }
            _ => None,
        }
    }

    #[allow(dead_code)]
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

    forwarder: StdRwLock<Option<Arc<UdpRelayForwarder>>>,
    
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
            forwarder: StdRwLock::new(None),
            path_event_handler: RwLock::new(None),
        })
    }

    pub fn set_forwarder(&self, forwarder: Arc<UdpRelayForwarder>) {
        if let Ok(mut guard) = self.forwarder.write() {
            *guard = Some(forwarder);
        }
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
        
        // Parse primary address
        if let Ok(addr) = contact.addr.parse::<SocketAddr>() {
            addrs.push(addr);
        }
        
        // Parse additional addresses
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
        let primary_addr = state.direct_addrs.first()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let addrs: Vec<String> = state.direct_addrs.iter()
            .skip(1)
            .map(|a| a.to_string())
            .collect();
        
        Some(Contact {
            identity: state.identity,
            addr: primary_addr,
            addrs,
        })
    }
    
    /// Get contact information for a peer from SmartSock's peer registry (async version).
    pub async fn get_peer_contact(&self, identity: &Identity) -> Option<Contact> {
        let smart_addr = SmartAddr::from_identity(identity);
        let peers = self.peers.read().await;
        let state = peers.get(&smart_addr)?;
        
        // Build contact from peer state
        let primary_addr = state.direct_addrs.first()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let addrs: Vec<String> = state.direct_addrs.iter()
            .skip(1)
            .map(|a| a.to_string())
            .collect();
        
        Some(Contact {
            identity: state.identity,
            addr: primary_addr,
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
                
                // Dispatch relay packets to forwarder (multiplexing)
                if received.len() >= 4 && received[0..4] == RELAY_MAGIC {
                    if let Ok(guard) = self.forwarder.read() {
                        if let Some(forwarder) = guard.as_ref() {
                            let forwarder = forwarder.clone();
                            let data = received.to_vec();
                            tokio::spawn(async move {
                                forwarder.process_packet(&data, src_addr).await;
                            });
                            
                            // Packet handled by forwarder, skip for Quinn
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
                
                let (payload, translated_addr) = if let Some((session_id, payload)) = RelayTunnel::decode_frame(received) {
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
                            Err(_) => Some(sa),                        }
                    });
                    
                    let addr = verified_smart_addr
                        .map(|sa| sa.0)
                        .unwrap_or(src_addr);
                    
                    (payload, addr)
                } else {
                    let translated = match self.reverse_map.try_read() {
                        Ok(guard) => guard.get(&src_addr).map(|sa| sa.0).unwrap_or(src_addr),
                        Err(_) => src_addr,
                    };
                    (received, translated)
                };
                
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
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))
    }

    fn test_identity(seed: u8) -> Identity {
        Identity::from([seed; 32])
    }

    #[test]
    fn test_forwarder_session_pending() {
        let session_id = [0xAB; 16];
        let session = ForwarderSession::new_pending(
            session_id,
            test_identity(1),
            test_identity(2),
            test_addr(1000),
        );
        
        assert!(!session.is_complete());
        assert_eq!(session.peer_a_addr.port(), 1000);
        assert!(session.peer_b_addr.is_none());
    }

    #[test]
    fn test_forwarder_session_destination() {
        let session_id = [0xAB; 16];
        let mut session = ForwarderSession::new_pending(
            session_id,
            test_identity(1),
            test_identity(2),
            test_addr(1000),
        );
        session.peer_b_addr = Some(test_addr(2000));
        
        assert!(session.is_complete());
        
        assert_eq!(session.get_destination(test_addr(1000)), Some(test_addr(2000)));
        
        assert_eq!(session.get_destination(test_addr(2000)), Some(test_addr(1000)));
        
        assert_eq!(session.get_destination(test_addr(9999)), None);
    }

    #[tokio::test]
    async fn test_register_and_complete_session() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarder = UdpRelayForwarder::with_socket(Arc::new(socket));
        
        let session_id = [0xCD; 16];
        let peer_a = test_addr(3000);
        let peer_b = test_addr(4000);

        let peer_a_id = test_identity(10);
        let peer_b_id = test_identity(20);
        
        forwarder
            .register_session(session_id, peer_a, peer_a_id, peer_b_id)
            .await
            .unwrap();
        assert_eq!(forwarder.session_count().await, 1);
        
        forwarder
            .complete_session(session_id, peer_b, peer_b_id, peer_a_id)
            .await
            .unwrap();
        
        let sessions = forwarder.sessions.read().await;
        let session = sessions.get(&session_id).unwrap();
        assert!(session.is_complete());
        assert_eq!(session.peer_b_addr, Some(peer_b));
    }

    #[tokio::test]
    async fn test_remove_session() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarder = UdpRelayForwarder::with_socket(Arc::new(socket));
        
        let session_id = [0xEF; 16];
        forwarder
            .register_session(session_id, test_addr(5000), test_identity(10), test_identity(20))
            .await
            .unwrap();
        assert_eq!(forwarder.session_count().await, 1);
        
        forwarder.remove_session(&session_id).await;
        assert_eq!(forwarder.session_count().await, 0);
    }

    #[test]
    fn test_crly_frame_format() {
        assert_eq!(RELAY_MAGIC, *b"CRLY");
        assert_eq!(RELAY_HEADER_SIZE, 20);
    }

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
    fn forwarder_session_fields() {
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let session = ForwarderSession::new_pending(
            [0u8; 16],
            Identity::from_bytes([1u8; 32]),
            Identity::from_bytes([2u8; 32]),
            addr,
        );
        
        assert_eq!(session.session_id, [0u8; 16]);
        let _ = session.peer_a_identity;
        let _ = session.peer_b_identity;
        let _ = session.peer_a_addr;
        assert!(session.peer_b_addr.is_none());
        let _ = session.created_at;
        let _ = session.last_activity;
        assert_eq!(session.bytes_forwarded, 0);
        assert_eq!(session.packets_forwarded, 0);
        assert!(!session.completion_locked);
        
        let cloned = session.clone();
        let _debug = format!("{:?}", cloned);
    }

    #[test]
    fn peer_path_state_new_and_fields() {
        let id = Identity::from_bytes([1u8; 32]);
        let state = PeerPathState::new(id);
        
        assert_eq!(state.identity, id);
        assert!(state.direct_addrs.is_empty());
        assert!(state.relay_tunnels.is_empty());
        assert!(state.active_path.is_none());
        assert!(state.last_send.is_none());
        assert!(state.last_recv.is_none());
        assert!(state.candidates.is_empty());
        assert!(state.pending_probes.is_empty());
        
        let _debug = format!("{:?}", state);
    }
}
