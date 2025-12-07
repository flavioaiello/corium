use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use crate::identity::Identity;
use crate::relay::protocol::{NatType, NatReport, TransportProtocol};

// ============================================================================
// ICE Candidate Types
// ============================================================================

/// ICE candidate type per RFC 8445.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CandidateType {
    /// Host candidate: local interface address.
    Host,
    /// Server-reflexive candidate: public address from STUN.
    ServerReflexive,
    /// Peer-reflexive candidate: discovered during connectivity check.
    PeerReflexive,
    /// Relay candidate: allocated address on TURN server.
    Relay,
}

impl CandidateType {
    /// Get the priority type preference (higher is better).
    /// Per RFC 8445: host=126, srflx=100, prflx=110, relay=0
    pub fn type_preference(&self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::ServerReflexive => 100,
            CandidateType::PeerReflexive => 110,
            CandidateType::Relay => 0,
        }
    }
}

/// An ICE candidate representing a potential path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Unique identifier for this candidate.
    pub foundation: String,
    /// Component ID (1 for RTP, 2 for RTCP; we use 1 for QUIC).
    pub component: u8,
    /// Transport protocol.
    pub transport: TransportProtocol,
    /// Priority (higher is better).
    pub priority: u32,
    /// The address of this candidate.
    pub addr: SocketAddr,
    /// Type of candidate.
    pub candidate_type: CandidateType,
    /// Related address (base for srflx/prflx, relay for relay).
    pub related_addr: Option<SocketAddr>,
    /// For relay candidates: the relay server's Identity.
    pub relay_peer: Option<Identity>,
}

impl IceCandidate {
    /// Create a host candidate.
    pub fn host(addr: SocketAddr, component: u8) -> Self {
        let priority = Self::compute_priority(CandidateType::Host, 0, component);
        Self {
            foundation: format!("host-{}", addr),
            component,
            transport: TransportProtocol::Udp,
            priority,
            addr,
            candidate_type: CandidateType::Host,
            related_addr: None,
            relay_peer: None,
        }
    }

    /// Create a server-reflexive candidate from STUN response.
    pub fn server_reflexive(public_addr: SocketAddr, base_addr: SocketAddr, component: u8) -> Self {
        let priority = Self::compute_priority(CandidateType::ServerReflexive, 0, component);
        Self {
            foundation: format!("srflx-{}", public_addr),
            component,
            transport: TransportProtocol::Udp,
            priority,
            addr: public_addr,
            candidate_type: CandidateType::ServerReflexive,
            related_addr: Some(base_addr),
            relay_peer: None,
        }
    }

    /// Create a relay candidate from TURN allocation.
    pub fn relay(
        relay_addr: SocketAddr,
        base_addr: SocketAddr,
        relay_peer: Identity,
        component: u8,
    ) -> Self {
        let priority = Self::compute_priority(CandidateType::Relay, 0, component);
        Self {
            foundation: format!("relay-{}", relay_addr),
            component,
            transport: TransportProtocol::Udp,
            priority,
            addr: relay_addr,
            candidate_type: CandidateType::Relay,
            related_addr: Some(base_addr),
            relay_peer: Some(relay_peer),
        }
    }

    /// Compute candidate priority per RFC 8445.
    /// priority = (2^24) * type_preference + (2^8) * local_preference + (256 - component)
    pub fn compute_priority(candidate_type: CandidateType, local_preference: u32, component: u8) -> u32 {
        let type_pref = candidate_type.type_preference();
        let local_pref = local_preference.min(65535);
        let comp = (256 - component as u32).min(255);
        (type_pref << 24) + (local_pref << 8) + comp
    }
}

// ============================================================================
// ICE Candidate Pair
// ============================================================================

/// State of an ICE candidate pair check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckState {
    /// Waiting to be checked.
    Waiting,
    /// Check is in progress.
    InProgress,
    /// Check succeeded.
    Succeeded,
    /// Check failed.
    Failed,
    /// This pair was nominated.
    Nominated,
}

/// A pair of local and remote candidates for connectivity checking.
#[derive(Clone, Debug)]
pub struct CandidatePair {
    /// Local candidate.
    pub local: IceCandidate,
    /// Remote candidate.
    pub remote: IceCandidate,
    /// Combined priority for pair ordering.
    pub priority: u64,
    /// Current check state.
    pub state: CheckState,
    /// Measured RTT if check succeeded.
    pub rtt_ms: Option<f32>,
    /// Number of check attempts.
    pub attempts: u32,
    /// Last check timestamp.
    pub last_check: Option<Instant>,
}

impl CandidatePair {
    /// Create a new candidate pair.
    pub fn new(local: IceCandidate, remote: IceCandidate, is_controlling: bool) -> Self {
        let priority = Self::compute_pair_priority(
            local.priority as u64,
            remote.priority as u64,
            is_controlling,
        );
        Self {
            local,
            remote,
            priority,
            state: CheckState::Waiting,
            rtt_ms: None,
            attempts: 0,
            last_check: None,
        }
    }

    /// Compute pair priority per RFC 8445.
    /// For controlling: 2^32 * MIN(G,D) + 2 * MAX(G,D) + 1
    /// For controlled:  2^32 * MIN(G,D) + 2 * MAX(G,D)
    fn compute_pair_priority(g: u64, d: u64, is_controlling: bool) -> u64 {
        let min = g.min(d);
        let max = g.max(d);
        let base = (min << 32) + (max << 1);
        if is_controlling { base + 1 } else { base }
    }
}

// ============================================================================
// TURN Allocation State
// ============================================================================

/// Maximum permissions per TURN allocation.
const MAX_PERMISSIONS_PER_ALLOCATION: usize = 64;

/// Maximum channel bindings per TURN allocation.
const MAX_CHANNELS_PER_ALLOCATION: usize = 32;

/// State of a TURN allocation.
#[derive(Clone, Debug)]
pub struct TurnAllocation {
    /// The relay server's Identity.
    pub relay_peer: Identity,
    /// Allocated relay address (where peers send to reach us).
    pub relay_addr: SocketAddr,
    /// Lifetime of the allocation.
    pub lifetime: Duration,
    /// When the allocation was created.
    pub created_at: Instant,
    /// When the allocation expires.
    pub expires_at: Instant,
    /// Permissions granted to remote peers.
    pub permissions: HashMap<SocketAddr, Instant>,
    /// Channel bindings for optimized forwarding.
    pub channels: HashMap<u16, SocketAddr>,
}

impl TurnAllocation {
    /// Create a new TURN allocation.
    pub fn new(relay_peer: Identity, relay_addr: SocketAddr, lifetime: Duration) -> Self {
        let now = Instant::now();
        Self {
            relay_peer,
            relay_addr,
            lifetime,
            created_at: now,
            expires_at: now + lifetime,
            permissions: HashMap::new(),
            channels: HashMap::new(),
        }
    }

    /// Check if the allocation is expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Refresh the allocation with a new lifetime.
    pub fn refresh(&mut self, lifetime: Duration) {
        self.lifetime = lifetime;
        self.expires_at = Instant::now() + lifetime;
    }

    /// Add a permission for a remote address.
    /// Returns false if the permission limit is reached.
    pub fn add_permission(&mut self, addr: SocketAddr) -> bool {
        // Clean expired permissions first
        let now = Instant::now();
        self.permissions.retain(|_, expires| *expires > now);
        
        // Check limit
        if self.permissions.len() >= MAX_PERMISSIONS_PER_ALLOCATION {
            return false;
        }
        
        self.permissions.insert(addr, Instant::now() + Duration::from_secs(300));
        true
    }

    /// Bind a channel number to a remote address.
    /// Returns false if the channel limit is reached.
    pub fn bind_channel(&mut self, channel: u16, addr: SocketAddr) -> bool {
        // Check limit (but allow replacing existing binding)
        if !self.channels.contains_key(&channel) 
            && self.channels.len() >= MAX_CHANNELS_PER_ALLOCATION 
        {
            return false;
        }
        
        self.channels.insert(channel, addr);
        true
    }
}

// ============================================================================
// ICE Agent
// ============================================================================

/// ICE agent role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceRole {
    /// Controlling agent (makes final decisions).
    Controlling,
    /// Controlled agent (follows controlling agent's decisions).
    Controlled,
}

/// ICE connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceState {
    /// Initial state, gathering candidates.
    New,
    /// Candidates gathered, checking connectivity.
    Checking,
    /// At least one candidate pair succeeded.
    Connected,
    /// All checks completed, best pair selected.
    Completed,
    /// All checks failed.
    Failed,
    /// ICE agent was closed.
    Closed,
}

/// Maximum TURN allocations per server.
const MAX_TURN_ALLOCATIONS: usize = 1000;

/// ICE agent managing candidate gathering and connectivity checks.
#[derive(Debug)]
pub struct IceAgent {
    /// Our role in the ICE negotiation.
    role: IceRole,
    /// Current ICE state.
    state: IceState,
    /// Local candidates gathered.
    local_candidates: Vec<IceCandidate>,
    /// Remote candidates received.
    remote_candidates: Vec<IceCandidate>,
    /// Candidate pairs sorted by priority.
    check_list: Vec<CandidatePair>,
    /// The nominated pair (if any).
    nominated_pair: Option<usize>,
    /// TURN allocations.
    turn_allocations: HashMap<Identity, TurnAllocation>,
    /// NAT detection results.
    nat_report: NatReport,
}

impl IceAgent {
    /// Create a new ICE agent.
    pub fn new(role: IceRole) -> Self {
        Self {
            role,
            state: IceState::New,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            check_list: Vec::new(),
            nominated_pair: None,
            turn_allocations: HashMap::new(),
            nat_report: NatReport::default(),
        }
    }

    /// Add a local candidate.
    pub fn add_local_candidate(&mut self, candidate: IceCandidate) {
        self.local_candidates.push(candidate);
    }

    /// Add a remote candidate and form pairs.
    pub fn add_remote_candidate(&mut self, candidate: IceCandidate) {
        // Form pairs with all local candidates
        for local in &self.local_candidates {
            // Only pair compatible candidates (same component, transport)
            if local.component == candidate.component && local.transport == candidate.transport {
                let pair = CandidatePair::new(
                    local.clone(),
                    candidate.clone(),
                    self.role == IceRole::Controlling,
                );
                self.check_list.push(pair);
            }
        }
        self.remote_candidates.push(candidate);
        
        // Sort check list by priority (highest first)
        self.check_list.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Get the next pair to check.
    pub fn next_check(&mut self) -> Option<&mut CandidatePair> {
        self.check_list
            .iter_mut()
            .find(|p| p.state == CheckState::Waiting)
    }

    /// Mark a check as succeeded.
    pub fn check_succeeded(&mut self, pair_index: usize, rtt_ms: f32) {
        if let Some(pair) = self.check_list.get_mut(pair_index) {
            pair.state = CheckState::Succeeded;
            pair.rtt_ms = Some(rtt_ms);
            
            if self.state == IceState::Checking {
                self.state = IceState::Connected;
            }
        }
    }

    /// Mark a check as failed.
    pub fn check_failed(&mut self, pair_index: usize) {
        if let Some(pair) = self.check_list.get_mut(pair_index) {
            pair.state = CheckState::Failed;
        }
        
        // If all checks failed, transition to Failed state
        if self.check_list.iter().all(|p| p.state == CheckState::Failed) {
            self.state = IceState::Failed;
        }
    }

    /// Nominate the best succeeded pair.
    pub fn nominate_best(&mut self) -> Option<&CandidatePair> {
        // Find best succeeded pair by priority
        let best_idx = self.check_list
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == CheckState::Succeeded)
            .max_by_key(|(_, p)| p.priority)
            .map(|(i, _)| i);
        
        if let Some(idx) = best_idx {
            self.check_list[idx].state = CheckState::Nominated;
            self.nominated_pair = Some(idx);
            self.state = IceState::Completed;
            Some(&self.check_list[idx])
        } else {
            None
        }
    }

    /// Get the nominated pair.
    pub fn get_nominated(&self) -> Option<&CandidatePair> {
        self.nominated_pair.map(|i| &self.check_list[i])
    }

    /// Get current ICE state.
    pub fn state(&self) -> IceState {
        self.state
    }

    /// Start checking phase.
    pub fn start_checks(&mut self) {
        if !self.check_list.is_empty() {
            self.state = IceState::Checking;
        }
    }

    /// Add a TURN allocation.
    /// Returns false if the allocation limit is reached.
    pub fn add_turn_allocation(&mut self, allocation: TurnAllocation) -> bool {
        // Clean expired allocations first
        self.turn_allocations.retain(|_, a| !a.is_expired());
        
        // Check limit
        if self.turn_allocations.len() >= MAX_TURN_ALLOCATIONS {
            return false;
        }
        
        self.turn_allocations.insert(allocation.relay_peer, allocation);
        true
    }

    /// Get active TURN allocations.
    pub fn get_allocations(&self) -> &HashMap<Identity, TurnAllocation> {
        &self.turn_allocations
    }

    /// Set NAT report from STUN discovery.
    pub fn set_nat_report(&mut self, report: NatReport) {
        self.nat_report = report;
    }

    /// Get NAT report.
    pub fn nat_report(&self) -> &NatReport {
        &self.nat_report
    }
}

// ============================================================================
// ICE Candidate Gathering
// ============================================================================

/// Gather all local host candidates from system interfaces.
pub fn gather_host_candidates(local_addrs: &[SocketAddr], component: u8) -> Vec<IceCandidate> {
    local_addrs
        .iter()
        .map(|addr| IceCandidate::host(*addr, component))
        .collect()
}

/// Detect NAT type by comparing STUN responses from multiple servers.
pub fn detect_nat_type(
    mapped_addr_1: Option<SocketAddr>,
    mapped_addr_2: Option<SocketAddr>,
    local_addr: SocketAddr,
) -> NatReport {
    let mut report = NatReport::default();

    match (mapped_addr_1, mapped_addr_2) {
        (None, None) => {
            // No responses - UDP blocked
            report.nat_type = NatType::Unknown;
            report.udp_blocked = true;
        }
        (Some(addr1), None) | (None, Some(addr1)) => {
            // Only one response - might be firewall or partial UDP blocking
            report.mapped_addr_1 = Some(addr1);
            report.nat_type = NatType::Unknown;
            report.behind_firewall = true;
            report.has_public_ip = addr1.ip() == local_addr.ip();
        }
        (Some(addr1), Some(addr2)) => {
            report.mapped_addr_1 = Some(addr1);
            report.mapped_addr_2 = Some(addr2);
            report.has_public_ip = addr1.ip() == local_addr.ip();

            if addr1.ip() == local_addr.ip() && addr2.ip() == local_addr.ip() {
                // We have a public IP
                report.nat_type = NatType::None;
            } else if addr1 == addr2 {
                // Same mapping from both servers - likely Cone NAT
                report.nat_type = NatType::FullCone; // Assume best case
            } else if addr1.ip() == addr2.ip() && addr1.port() != addr2.port() {
                // Same IP but different ports - Symmetric NAT
                report.nat_type = NatType::Symmetric;
            } else {
                // Different IPs - unusual, but could be multi-homed NAT
                report.nat_type = NatType::Symmetric;
            }
        }
    }

    report
}

/// Determine best connection strategy using ICE-like candidate selection.
pub fn ice_connection_strategy(
    local_candidates: &[IceCandidate],
    remote_candidates: &[IceCandidate],
    nat_report: &NatReport,
) -> Vec<CandidatePair> {
    let mut pairs = Vec::new();

    // Form all valid pairs
    for local in local_candidates {
        for remote in remote_candidates {
            // Only pair compatible candidates
            if local.component == remote.component && local.transport == remote.transport {
                let pair = CandidatePair::new(local.clone(), remote.clone(), true);
                pairs.push(pair);
            }
        }
    }

    // Sort by priority (higher first)
    pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

    // For symmetric NAT, prioritize relay candidates
    if nat_report.nat_type == NatType::Symmetric {
        pairs.sort_by(|a, b| {
            let a_is_relay = a.local.candidate_type == CandidateType::Relay
                || a.remote.candidate_type == CandidateType::Relay;
            let b_is_relay = b.local.candidate_type == CandidateType::Relay
                || b.remote.candidate_type == CandidateType::Relay;
            
            // Put relay pairs first for symmetric NAT
            match (a_is_relay, b_is_relay) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b.priority.cmp(&a.priority),
            }
        });
    }

    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn test_ice_candidate_priority() {
        // Host should have highest type preference
        let host = IceCandidate::host("192.168.1.1:4433".parse().unwrap(), 1);
        let srflx = IceCandidate::server_reflexive(
            "1.2.3.4:5678".parse().unwrap(),
            "192.168.1.1:4433".parse().unwrap(),
            1,
        );
        let relay = IceCandidate::relay(
            "5.6.7.8:9999".parse().unwrap(),
            "192.168.1.1:4433".parse().unwrap(),
            Identity::from_bytes([1u8; 32]),
            1,
        );
        
        assert!(host.priority > srflx.priority);
        assert!(srflx.priority > relay.priority);
    }

    #[test]
    fn test_ice_candidate_types() {
        assert_eq!(CandidateType::Host.type_preference(), 126);
        assert_eq!(CandidateType::ServerReflexive.type_preference(), 100);
        assert_eq!(CandidateType::PeerReflexive.type_preference(), 110);
        assert_eq!(CandidateType::Relay.type_preference(), 0);
    }

    #[test]
    fn test_nat_type_detection() {
        let local: SocketAddr = "192.168.1.1:4433".parse().unwrap();
        
        // No responses - UDP blocked
        let report = detect_nat_type(None, None, local);
        assert_eq!(report.nat_type, NatType::Unknown);
        assert!(report.udp_blocked);
        
        // Same address from both servers - Cone NAT
        let public: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let report = detect_nat_type(Some(public), Some(public), local);
        assert_eq!(report.nat_type, NatType::FullCone);
        
        // Different ports - Symmetric NAT
        let public1: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let public2: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let report = detect_nat_type(Some(public1), Some(public2), local);
        assert_eq!(report.nat_type, NatType::Symmetric);
        
        // Public IP matches local - No NAT
        let public: SocketAddr = "192.168.1.1:4433".parse().unwrap();
        let report = detect_nat_type(Some(public), Some(public), local);
        assert_eq!(report.nat_type, NatType::None);
    }

    #[test]
    fn test_ice_agent_candidate_pairing() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        let local = IceCandidate::host("192.168.1.1:4433".parse().unwrap(), 1);
        agent.add_local_candidate(local);
        
        let remote = IceCandidate::host("192.168.2.1:4433".parse().unwrap(), 1);
        agent.add_remote_candidate(remote);
        
        assert_eq!(agent.check_list.len(), 1);
        assert_eq!(agent.check_list[0].state, CheckState::Waiting);
    }

    #[test]
    fn test_ice_agent_check_flow() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        agent.add_local_candidate(IceCandidate::host("192.168.1.1:4433".parse().unwrap(), 1));
        agent.add_remote_candidate(IceCandidate::host("192.168.2.1:4433".parse().unwrap(), 1));
        
        agent.start_checks();
        assert_eq!(agent.state(), IceState::Checking);
        
        // Simulate successful check
        agent.check_succeeded(0, 25.0);
        assert_eq!(agent.state(), IceState::Connected);
        assert_eq!(agent.check_list[0].rtt_ms, Some(25.0));
        
        // Nominate
        let nominated = agent.nominate_best();
        assert!(nominated.is_some());
        assert_eq!(agent.state(), IceState::Completed);
    }

    #[test]
    fn test_turn_allocation() {
        let mut alloc = TurnAllocation::new(
            Identity::from_bytes([1u8; 32]),
            "1.2.3.4:5678".parse().unwrap(),
            Duration::from_secs(300),
        );
        
        assert!(!alloc.is_expired());
        
        // Add permission
        alloc.add_permission("5.6.7.8:9999".parse().unwrap());
        assert_eq!(alloc.permissions.len(), 1);
        
        // Bind channel
        alloc.bind_channel(0x4000, "5.6.7.8:9999".parse().unwrap());
        assert_eq!(alloc.channels.len(), 1);
    }

    #[test]
    fn test_gather_host_candidates() {
        let addrs: Vec<SocketAddr> = vec![
            "192.168.1.1:4433".parse().unwrap(),
            "10.0.0.1:4433".parse().unwrap(),
        ];
        
        let candidates = gather_host_candidates(&addrs, 1);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().all(|c| c.candidate_type == CandidateType::Host));
    }

    #[test]
    fn test_ice_connection_strategy_symmetric_nat() {
        let local_host = IceCandidate::host("192.168.1.1:4433".parse().unwrap(), 1);
        let local_relay = IceCandidate::relay(
            "1.2.3.4:5678".parse().unwrap(),
            "192.168.1.1:4433".parse().unwrap(),
            Identity::from_bytes([1u8; 32]),
            1,
        );
        
        let remote_host = IceCandidate::host("192.168.2.1:4433".parse().unwrap(), 1);
        
        let local_candidates = vec![local_host, local_relay];
        let remote_candidates = vec![remote_host];
        
        // With symmetric NAT, relay pairs should be prioritized
        let symmetric_report = NatReport {
            nat_type: NatType::Symmetric,
            ..Default::default()
        };
        
        let pairs = ice_connection_strategy(&local_candidates, &remote_candidates, &symmetric_report);
        assert!(!pairs.is_empty());
        
        // First pair should involve relay for symmetric NAT
        assert!(
            pairs[0].local.candidate_type == CandidateType::Relay
            || pairs[0].remote.candidate_type == CandidateType::Relay
        );
    }
}
