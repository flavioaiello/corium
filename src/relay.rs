use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::identity::Identity;

pub const RELAY_MAGIC: [u8; 4] = *b"CRLY";

pub const RELAY_HEADER_SIZE: usize = 20;

pub const MAX_FRAME_SIZE: usize = 1500;

pub const MAX_SESSIONS: usize = 10_000;

pub const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    None,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct NatReport {
    pub nat_type: NatType,
    pub mapped_addr_1: Option<SocketAddr>,
    pub mapped_addr_2: Option<SocketAddr>,
    pub has_public_ip: bool,
    pub udp_blocked: bool,
}

impl Default for NatReport {
    fn default() -> Self {
        Self {
            nat_type: NatType::Unknown,
            mapped_addr_1: None,
            mapped_addr_2: None,
            has_public_ip: false,
            udp_blocked: false,
        }
    }
}

pub fn detect_nat_type(
    mapped_1: Option<SocketAddr>,
    mapped_2: Option<SocketAddr>,
    local_addr: SocketAddr,
) -> NatReport {
    let mut report = NatReport::default();

    match (mapped_1, mapped_2) {
        (None, None) => {
            report.udp_blocked = true;
            report.nat_type = NatType::Unknown;
        }
        (Some(addr1), None) | (None, Some(addr1)) => {
            report.mapped_addr_1 = Some(addr1);
            if addr1.ip() == local_addr.ip() {
                report.has_public_ip = true;
                report.nat_type = NatType::None;
            } else {
                report.nat_type = NatType::Unknown;
            }
        }
        (Some(addr1), Some(addr2)) => {
            report.mapped_addr_1 = Some(addr1);
            report.mapped_addr_2 = Some(addr2);

            if addr1.ip() == local_addr.ip() {
                report.has_public_ip = true;
                report.nat_type = NatType::None;
            } else if addr1 == addr2 {
                report.nat_type = NatType::FullCone;
            } else {
                report.nat_type = NatType::Symmetric;
            }
        }
    }

    report
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)] // Relay infrastructure - used when relay discovery is enabled
pub struct RelayInfo {
    pub relay_peer: Identity,
    pub relay_addrs: Vec<String>,
    pub load: f32,
    pub accepting: bool,
    #[serde(default)]
    pub rtt_ms: Option<f32>,
    #[serde(default)]
    pub tier: Option<u8>,
}

#[allow(dead_code)] // Relay infrastructure
impl RelayInfo {
    pub fn selection_score(&self) -> f32 {
        let rtt_score = self.rtt_ms.unwrap_or(200.0);
        let load_penalty = self.load * 100.0;
        let tier_penalty = self.tier.map(|t| t as f32 * 20.0).unwrap_or(40.0);
        rtt_score + load_penalty + tier_penalty
    }

    pub fn has_latency_info(&self) -> bool {
        self.rtt_ms.is_some() || self.tier.is_some()
    }
}

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
#[allow(dead_code)] // Relay infrastructure - session tracking
pub struct ForwarderSession {
    pub session_id: [u8; 16],
    pub peer_a_addr: SocketAddr,
    pub peer_b_addr: Option<SocketAddr>,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub bytes_forwarded: u64,
    pub packets_forwarded: u64,
}

impl ForwarderSession {
    pub fn new_pending(session_id: [u8; 16], peer_a_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            peer_a_addr,
            peer_b_addr: None,
            created_at: now,
            last_activity: now,
            bytes_forwarded: 0,
            packets_forwarded: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.peer_b_addr.is_some()
    }

    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TIMEOUT
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

#[allow(dead_code)] // Relay infrastructure
impl UdpRelayForwarder {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        info!(addr = %socket.local_addr()?, "UDP relay forwarder started");
        
        Ok(Self {
            socket: Arc::new(socket),
            sessions: RwLock::new(HashMap::new()),
            addr_to_session: RwLock::new(HashMap::new()),
        })
    }

    pub fn with_socket(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            sessions: RwLock::new(HashMap::new()),
            addr_to_session: RwLock::new(HashMap::new()),
        }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn register_session(
        &self,
        session_id: [u8; 16],
        peer_a_addr: SocketAddr,
    ) -> Result<(), &'static str> {
        let mut sessions = self.sessions.write().await;
        
        if sessions.len() >= MAX_SESSIONS {
            return Err("max sessions reached");
        }
        
        if sessions.contains_key(&session_id) {
            return Err("session already exists");
        }
        
        let session = ForwarderSession::new_pending(session_id, peer_a_addr);
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
    ) -> Result<(), &'static str> {
        let mut sessions = self.sessions.write().await;
        
        let session = sessions.get_mut(&session_id)
            .ok_or("session not found")?;
        
        if session.peer_b_addr.is_some() {
            return Err("session already complete");
        }
        
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

    async fn process_packet(&self, data: &[u8], from: SocketAddr) -> usize {
        if data.len() < RELAY_HEADER_SIZE {
            trace!(from = %from, len = data.len(), "dropping undersized packet");
            return 0;
        }
        
        if &data[0..4] != &RELAY_MAGIC {
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
            
            if !session.is_complete() && from != session.peer_a_addr {
                session.peer_b_addr = Some(from);
                
                drop(sessions);
                let mut addr_map = self.addr_to_session.write().await;
                addr_map.insert(from, session_id);
                
                let sessions = self.sessions.read().await;
                let session = sessions.get(&session_id).unwrap();
                session.get_destination(from)
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

    pub async fn run(&self) {
        let mut buf = [0u8; MAX_FRAME_SIZE];
        let mut cleanup_interval = tokio::time::interval(CLEANUP_INTERVAL);
        
        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from)) => {
                            self.process_packet(&buf[..len], from).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "relay socket recv error");
                        }
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup_expired().await;
                }
            }
        }
    }

    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }
}

// ============================================================================
// Relay Request Handler
// ============================================================================

use crate::messages::{RelayRequest, RelayResponse};

/// Handle an incoming relay request.
/// 
/// This function processes `RelayRequest::Connect` messages, managing session
/// registration and completion on the `UdpRelayForwarder`.
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

            match forwarder.register_session(session_id, remote_addr).await {
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
                    match forwarder.complete_session(session_id, remote_addr).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))
    }

    #[test]
    fn test_forwarder_session_pending() {
        let session_id = [0xAB; 16];
        let session = ForwarderSession::new_pending(session_id, test_addr(1000));
        
        assert!(!session.is_complete());
        assert_eq!(session.peer_a_addr.port(), 1000);
        assert!(session.peer_b_addr.is_none());
    }

    #[test]
    fn test_forwarder_session_destination() {
        let session_id = [0xAB; 16];
        let mut session = ForwarderSession::new_pending(session_id, test_addr(1000));
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
        
        forwarder.register_session(session_id, peer_a).await.unwrap();
        assert_eq!(forwarder.session_count().await, 1);
        
        forwarder.complete_session(session_id, peer_b).await.unwrap();
        
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
        forwarder.register_session(session_id, test_addr(5000)).await.unwrap();
        assert_eq!(forwarder.session_count().await, 1);
        
        forwarder.remove_session(&session_id).await;
        assert_eq!(forwarder.session_count().await, 0);
    }

    #[test]
    fn test_crly_frame_format() {
        assert_eq!(RELAY_MAGIC, *b"CRLY");
        assert_eq!(RELAY_HEADER_SIZE, 20);
    }
}
