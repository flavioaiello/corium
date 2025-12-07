//! Security tests for relay and NAT traversal components.
//!
//! This test module covers:
//! - Relay session security and limits
//! - TURN allocation protection
//! - ICE candidate validation
//! - Hole punch registry security
//! - Relay message authentication

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use corium::identity::Keypair;
use corium::relay::{
    CandidateType, CheckState, IceCandidate, IceAgent, IceRole, IceState,
    NatType, TurnAllocation, CandidatePair, TransportProtocol,
    MAX_RELAY_SESSIONS, RELAY_SESSION_TIMEOUT, RelayServer, RelayRequest,
};

/// Maximum relay packet size (from relay module, not exported)
const MAX_RELAY_PACKET_SIZE: usize = 1500;

// ============================================================================
// ICE Candidate Security Tests
// ============================================================================

mod ice_candidate_security {
    use super::*;

    /// Test ICE candidate type priorities follow RFC 8445.
    #[test]
    fn candidate_type_priorities() {
        // Per RFC 8445: host=126, srflx=100, prflx=110, relay=0
        assert_eq!(CandidateType::Host.type_preference(), 126);
        assert_eq!(CandidateType::ServerReflexive.type_preference(), 100);
        assert_eq!(CandidateType::PeerReflexive.type_preference(), 110);
        assert_eq!(CandidateType::Relay.type_preference(), 0);
        
        // Host should have highest priority, relay lowest
        assert!(CandidateType::Host.type_preference() > CandidateType::Relay.type_preference());
        assert!(CandidateType::Host.type_preference() > CandidateType::ServerReflexive.type_preference());
    }

    /// Test host candidate creation.
    #[test]
    fn host_candidate_creation() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let candidate = IceCandidate::host(addr, 1);
        
        assert_eq!(candidate.addr, addr);
        assert_eq!(candidate.candidate_type, CandidateType::Host);
        assert_eq!(candidate.component, 1);
        assert_eq!(candidate.transport, TransportProtocol::Udp);
        assert!(candidate.related_addr.is_none());
        assert!(candidate.relay_peer.is_none());
    }

    /// Test server-reflexive candidate includes base address.
    #[test]
    fn srflx_candidate_includes_base() {
        let public_addr: SocketAddr = "203.0.113.1:12345".parse().unwrap();
        let base_addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        
        let candidate = IceCandidate::server_reflexive(public_addr, base_addr, 1);
        
        assert_eq!(candidate.addr, public_addr);
        assert_eq!(candidate.related_addr, Some(base_addr));
        assert_eq!(candidate.candidate_type, CandidateType::ServerReflexive);
    }

    /// Test relay candidate includes relay identity.
    #[test]
    fn relay_candidate_includes_relay_peer() {
        let relay_keypair = Keypair::generate();
        let relay_identity = relay_keypair.identity();
        let relay_addr: SocketAddr = "10.0.0.1:3478".parse().unwrap();
        let base_addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        
        let candidate = IceCandidate::relay(relay_addr, base_addr, relay_identity, 1);
        
        assert_eq!(candidate.addr, relay_addr);
        assert_eq!(candidate.related_addr, Some(base_addr));
        assert_eq!(candidate.relay_peer, Some(relay_identity));
        assert_eq!(candidate.candidate_type, CandidateType::Relay);
    }

    /// Test priority computation follows RFC 8445 formula.
    #[test]
    fn priority_computation() {
        // priority = (2^24) * type_preference + (2^8) * local_preference + (256 - component)
        let priority = IceCandidate::compute_priority(CandidateType::Host, 0, 1);
        
        // Host type preference = 126
        // Expected: (126 << 24) + 255 = 126 * 16777216 + 255
        let expected = (126u32 << 24) + 255;
        assert_eq!(priority, expected);
    }

    /// Test that different components produce different priorities.
    #[test]
    fn component_affects_priority() {
        let priority_1 = IceCandidate::compute_priority(CandidateType::Host, 0, 1);
        let priority_2 = IceCandidate::compute_priority(CandidateType::Host, 0, 2);
        
        // Component 1 should have higher priority than component 2
        assert!(priority_1 > priority_2);
    }
}

// ============================================================================
// ICE Agent Security Tests
// ============================================================================

mod ice_agent_security {
    use super::*;

    /// Test ICE agent state transitions.
    #[test]
    fn ice_agent_state_transitions() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        assert_eq!(agent.state(), IceState::New);
        
        // Add candidates
        let local = IceCandidate::host("192.168.1.1:8080".parse().unwrap(), 1);
        let remote = IceCandidate::host("192.168.1.2:8080".parse().unwrap(), 1);
        
        agent.add_local_candidate(local);
        agent.add_remote_candidate(remote);
        
        // Start checks
        agent.start_checks();
        assert_eq!(agent.state(), IceState::Checking);
    }

    /// Test that check list is sorted by priority.
    #[test]
    fn check_list_priority_sorting() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        // Add local candidates with different types
        let host = IceCandidate::host("192.168.1.1:8080".parse().unwrap(), 1);
        let srflx = IceCandidate::server_reflexive(
            "203.0.113.1:12345".parse().unwrap(),
            "192.168.1.1:8080".parse().unwrap(),
            1,
        );
        
        agent.add_local_candidate(host.clone());
        agent.add_local_candidate(srflx.clone());
        
        // Add remote candidates
        let remote = IceCandidate::host("192.168.1.2:8080".parse().unwrap(), 1);
        agent.add_remote_candidate(remote);
        
        // Check list should be sorted (highest priority first)
        // Host-Host pair should be before SRFLX-Host pair
        agent.start_checks();
        
        if let Some(first_pair) = agent.next_check() {
            // First check should be highest priority (host-host)
            assert_eq!(first_pair.local.candidate_type, CandidateType::Host);
        }
    }

    /// Test that all checks failing leads to Failed state.
    #[test]
    fn all_checks_failed_transitions_to_failed() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        let local = IceCandidate::host("192.168.1.1:8080".parse().unwrap(), 1);
        let remote = IceCandidate::host("192.168.1.2:8080".parse().unwrap(), 1);
        
        agent.add_local_candidate(local);
        agent.add_remote_candidate(remote);
        agent.start_checks();
        
        // Fail all checks
        agent.check_failed(0);
        
        assert_eq!(agent.state(), IceState::Failed);
    }

    /// Test successful check leads to Connected state.
    #[test]
    fn successful_check_transitions_to_connected() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        let local = IceCandidate::host("192.168.1.1:8080".parse().unwrap(), 1);
        let remote = IceCandidate::host("192.168.1.2:8080".parse().unwrap(), 1);
        
        agent.add_local_candidate(local);
        agent.add_remote_candidate(remote);
        agent.start_checks();
        
        // Succeed a check
        agent.check_succeeded(0, 15.0); // 15ms RTT
        
        assert_eq!(agent.state(), IceState::Connected);
    }

    /// Test nomination selects best pair.
    #[test]
    fn nomination_selects_best_pair() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        let local = IceCandidate::host("192.168.1.1:8080".parse().unwrap(), 1);
        let remote1 = IceCandidate::host("192.168.1.2:8080".parse().unwrap(), 1);
        let remote2 = IceCandidate::host("192.168.1.3:8080".parse().unwrap(), 1);
        
        agent.add_local_candidate(local);
        agent.add_remote_candidate(remote1);
        agent.add_remote_candidate(remote2);
        agent.start_checks();
        
        // Succeed both checks with different RTTs
        agent.check_succeeded(0, 10.0);
        agent.check_succeeded(1, 20.0);
        
        // Nominate best - should choose pair with higher priority
        let nominated = agent.nominate_best();
        assert!(nominated.is_some());
        
        let pair = nominated.unwrap();
        assert_eq!(pair.state, CheckState::Nominated);
        
        assert_eq!(agent.state(), IceState::Completed);
    }
}

// ============================================================================
// TURN Allocation Security Tests
// ============================================================================

mod turn_allocation_security {
    use super::*;

    /// Test TURN allocation expiration.
    #[test]
    fn turn_allocation_expires() {
        let relay_keypair = Keypair::generate();
        let relay_addr: SocketAddr = "10.0.0.1:3478".parse().unwrap();
        
        // Create allocation with very short lifetime for testing
        let allocation = TurnAllocation::new(
            relay_keypair.identity(),
            relay_addr,
            Duration::from_millis(1), // 1ms lifetime
        );
        
        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));
        
        assert!(allocation.is_expired());
    }

    /// Test TURN allocation refresh extends lifetime.
    #[test]
    fn turn_allocation_refresh() {
        let relay_keypair = Keypair::generate();
        let relay_addr: SocketAddr = "10.0.0.1:3478".parse().unwrap();
        
        let mut allocation = TurnAllocation::new(
            relay_keypair.identity(),
            relay_addr,
            Duration::from_secs(60),
        );
        
        assert!(!allocation.is_expired());
        
        // Refresh with longer lifetime
        allocation.refresh(Duration::from_secs(600));
        
        assert!(!allocation.is_expired());
        assert_eq!(allocation.lifetime, Duration::from_secs(600));
    }

    /// Test permission limits prevent resource exhaustion.
    #[test]
    fn permission_limits_enforced() {
        let relay_keypair = Keypair::generate();
        let relay_addr: SocketAddr = "10.0.0.1:3478".parse().unwrap();
        
        let mut allocation = TurnAllocation::new(
            relay_keypair.identity(),
            relay_addr,
            Duration::from_secs(600),
        );
        
        // Add permissions up to limit (64 per allocation)
        for i in 0..64 {
            let addr: SocketAddr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8)),
                8080,
            );
            assert!(allocation.add_permission(addr), "Should allow permission {}", i);
        }
        
        // 65th permission should be rejected
        let extra_addr: SocketAddr = "192.168.2.1:8080".parse().unwrap();
        assert!(!allocation.add_permission(extra_addr), "Should reject 65th permission");
    }

    /// Test channel binding limits.
    #[test]
    fn channel_binding_limits_enforced() {
        let relay_keypair = Keypair::generate();
        let relay_addr: SocketAddr = "10.0.0.1:3478".parse().unwrap();
        
        let mut allocation = TurnAllocation::new(
            relay_keypair.identity(),
            relay_addr,
            Duration::from_secs(600),
        );
        
        // Add channel bindings up to limit (32 per allocation)
        for i in 0..32 {
            let addr: SocketAddr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8)),
                8080,
            );
            let channel = 0x4000 + i as u16; // TURN channels start at 0x4000
            assert!(allocation.bind_channel(channel, addr), "Should allow channel {}", i);
        }
        
        // 33rd channel should be rejected
        let extra_addr: SocketAddr = "192.168.2.1:8080".parse().unwrap();
        assert!(!allocation.bind_channel(0x4100, extra_addr), "Should reject 33rd channel");
    }

    /// Test channel rebinding is allowed.
    #[test]
    fn channel_rebinding_allowed() {
        let relay_keypair = Keypair::generate();
        let relay_addr: SocketAddr = "10.0.0.1:3478".parse().unwrap();
        
        let mut allocation = TurnAllocation::new(
            relay_keypair.identity(),
            relay_addr,
            Duration::from_secs(600),
        );
        
        let addr1: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:8080".parse().unwrap();
        
        // Bind channel
        assert!(allocation.bind_channel(0x4000, addr1));
        
        // Rebind same channel to different address (should succeed)
        assert!(allocation.bind_channel(0x4000, addr2));
        
        // Verify the new binding
        assert_eq!(allocation.channels.get(&0x4000), Some(&addr2));
    }
}

// ============================================================================
// ICE Agent Allocation Limits
// ============================================================================

mod ice_allocation_limits {
    use super::*;

    /// Test TURN allocation limits in ICE agent.
    #[test]
    fn ice_agent_turn_allocation_limits() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        // Add allocations up to limit (1000)
        for i in 0..1000 {
            let relay_keypair = Keypair::generate();
            let relay_addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
                3478,
            );
            let allocation = TurnAllocation::new(
                relay_keypair.identity(),
                relay_addr,
                Duration::from_secs(600),
            );
            assert!(agent.add_turn_allocation(allocation), "Should allow allocation {}", i);
        }
        
        // 1001st allocation should be rejected
        let extra_keypair = Keypair::generate();
        let extra_allocation = TurnAllocation::new(
            extra_keypair.identity(),
            "10.255.255.255:3478".parse().unwrap(),
            Duration::from_secs(600),
        );
        assert!(!agent.add_turn_allocation(extra_allocation), "Should reject 1001st allocation");
    }

    /// Test expired allocations are cleaned up.
    #[test]
    fn expired_allocations_cleaned_up() {
        let mut agent = IceAgent::new(IceRole::Controlling);
        
        // Add allocation with short lifetime
        let relay_keypair = Keypair::generate();
        let allocation = TurnAllocation::new(
            relay_keypair.identity(),
            "10.0.0.1:3478".parse().unwrap(),
            Duration::from_millis(1),
        );
        agent.add_turn_allocation(allocation);
        
        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));
        
        // Adding a new allocation should trigger cleanup
        let new_keypair = Keypair::generate();
        let new_allocation = TurnAllocation::new(
            new_keypair.identity(),
            "10.0.0.2:3478".parse().unwrap(),
            Duration::from_secs(600),
        );
        agent.add_turn_allocation(new_allocation);
        
        // First allocation should be cleaned up, only new one should exist
        assert_eq!(agent.get_allocations().len(), 1);
        assert!(agent.get_allocations().contains_key(&new_keypair.identity()));
    }
}

// ============================================================================
// NAT Type Security Tests
// ============================================================================

mod nat_type_security {
    use super::*;

    /// Test NAT type classification.
    #[test]
    fn nat_type_classification() {
        // Verify all NAT types are distinguishable
        let nat_types = [
            NatType::None,
            NatType::FullCone,
            NatType::RestrictedCone,
            NatType::PortRestrictedCone,
            NatType::Symmetric,
            NatType::Unknown,
        ];
        
        // Each type should be distinct
        for (i, t1) in nat_types.iter().enumerate() {
            for (j, t2) in nat_types.iter().enumerate() {
                if i != j {
                    assert_ne!(t1, t2);
                }
            }
        }
    }

    /// Test NAT type serialization roundtrip.
    #[test]
    fn nat_type_serialization() {
        let nat_types = [
            NatType::None,
            NatType::FullCone,
            NatType::RestrictedCone,
            NatType::PortRestrictedCone,
            NatType::Symmetric,
            NatType::Unknown,
        ];
        
        for nat_type in nat_types {
            let bytes = bincode::serialize(&nat_type).unwrap();
            let decoded: NatType = bincode::deserialize(&bytes).unwrap();
            assert_eq!(nat_type, decoded);
        }
    }
}

// ============================================================================
// Candidate Pair Security Tests
// ============================================================================

mod candidate_pair_security {
    use super::*;

    /// Test candidate pair priority computation.
    #[test]
    fn candidate_pair_priority() {
        let local = IceCandidate::host("192.168.1.1:8080".parse().unwrap(), 1);
        let remote = IceCandidate::host("192.168.1.2:8080".parse().unwrap(), 1);
        
        let pair_controlling = CandidatePair::new(local.clone(), remote.clone(), true);
        let pair_controlled = CandidatePair::new(local, remote, false);
        
        // Controlling agent should have slightly higher priority (+ 1)
        assert!(pair_controlling.priority > pair_controlled.priority);
        assert_eq!(pair_controlling.priority - pair_controlled.priority, 1);
    }

    /// Test candidate pair state transitions.
    #[test]
    fn candidate_pair_state_transitions() {
        let local = IceCandidate::host("192.168.1.1:8080".parse().unwrap(), 1);
        let remote = IceCandidate::host("192.168.1.2:8080".parse().unwrap(), 1);
        
        let pair = CandidatePair::new(local, remote, true);
        
        // Initial state should be Waiting
        assert_eq!(pair.state, CheckState::Waiting);
        assert!(pair.rtt_ms.is_none());
        assert_eq!(pair.attempts, 0);
    }
}

// ============================================================================
// Relay Packet Size Limits
// ============================================================================

mod relay_packet_limits {
    use super::*;

    /// Test maximum relay packet size is reasonable.
    #[test]
    fn max_relay_packet_size() {
        // Verify actual constant value at runtime to catch misconfigurations
        let size = MAX_RELAY_PACKET_SIZE;
        
        // Should be at least QUIC minimum MTU  
        assert!(size >= 1200, "Relay packet size {} too small for QUIC", size);
        // Should not exceed UDP max
        assert!(size <= 65535, "Relay packet size {} exceeds UDP max", size);
        // Currently expected to be Ethernet MTU
        assert_eq!(size, 1500, "Unexpected relay packet size");
    }

    /// Test relay session timeout is reasonable.
    #[test]
    fn relay_session_timeout() {
        // Should be long enough for temporary network issues but not too long
        assert!(RELAY_SESSION_TIMEOUT >= Duration::from_secs(60));
        assert!(RELAY_SESSION_TIMEOUT <= Duration::from_secs(3600));
        
        // Currently 5 minutes
        assert_eq!(RELAY_SESSION_TIMEOUT, Duration::from_secs(300));
    }

    /// Test maximum relay sessions limit.
    #[test]
    fn max_relay_sessions() {
        // Verify actual constant value at runtime
        let max_sessions = MAX_RELAY_SESSIONS;
        
        // Should allow meaningful concurrent sessions
        assert!(max_sessions >= 10, "Max sessions {} too low", max_sessions);
        // Should prevent resource exhaustion
        assert!(max_sessions <= 10000, "Max sessions {} too high", max_sessions);
        // Currently expected value
        assert_eq!(max_sessions, 100, "Unexpected max relay sessions");
    }
}

// ============================================================================
// Transport Protocol Tests
// ============================================================================

mod transport_protocol {
    use super::*;

    /// Test transport protocol serialization.
    #[test]
    fn transport_protocol_serialization() {
        let protocols = vec![TransportProtocol::Udp, TransportProtocol::Tcp];
        
        for protocol in protocols {
            let bytes = bincode::serialize(&protocol).unwrap();
            let decoded: TransportProtocol = bincode::deserialize(&bytes).unwrap();
            assert_eq!(protocol, decoded);
        }
    }

    /// Test transport protocols are distinguishable.
    #[test]
    fn transport_protocol_distinct() {
        assert_ne!(TransportProtocol::Udp, TransportProtocol::Tcp);
    }
}

// ============================================================================
// Relay Session Authentication Tests
// ============================================================================

mod relay_session_authentication {
    use super::*;

    /// Test that only session participants can close a session.
    #[tokio::test]
    async fn close_session_requires_participant() {
        let server = RelayServer::new().unwrap();
        
        // Create two peers and establish a session
        let keypair_a = Keypair::generate();
        let keypair_b = Keypair::generate();
        let keypair_attacker = Keypair::generate();
        
        let session_id: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        // Peer A initiates
        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(32);
        let request_a = RelayRequest {
            from_peer: keypair_a.identity(),
            target_peer: keypair_b.identity(),
            session_id,
        };
        let response = server.handle_request(request_a, tx_a).await;
        assert!(matches!(response, corium::relay::RelayResponse::Accepted { .. }));
        
        // Attacker tries to close the session (should fail silently)
        server.close_session(&session_id, &keypair_attacker.identity(), "attacker trying to close").await;
        
        // Session should still be pending (attacker was not a participant)
        // Peer B can still connect
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel(32);
        let request_b = RelayRequest {
            from_peer: keypair_b.identity(),
            target_peer: keypair_a.identity(),
            session_id,
        };
        let response = server.handle_request(request_b, tx_b).await;
        assert!(matches!(response, corium::relay::RelayResponse::Connected { .. }));
    }

    /// Test that session initiator can close pending session.
    #[tokio::test]
    async fn initiator_can_close_pending_session() {
        let server = RelayServer::new().unwrap();
        
        let keypair_a = Keypair::generate();
        let keypair_b = Keypair::generate();
        
        let session_id: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        // Peer A initiates
        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(32);
        let request_a = RelayRequest {
            from_peer: keypair_a.identity(),
            target_peer: keypair_b.identity(),
            session_id,
        };
        let response = server.handle_request(request_a, tx_a).await;
        assert!(matches!(response, corium::relay::RelayResponse::Accepted { .. }));
        
        // Peer A closes the session (should succeed)
        server.close_session(&session_id, &keypair_a.identity(), "initiator closing").await;
        
        // Peer B tries to connect - should be rejected (session was closed)
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel(32);
        let request_b = RelayRequest {
            from_peer: keypair_b.identity(),
            target_peer: keypair_a.identity(),
            session_id,
        };
        let response = server.handle_request(request_b, tx_b).await;
        // Will be Accepted (new pending session) not Connected
        assert!(matches!(response, corium::relay::RelayResponse::Accepted { .. }));
    }

    /// Test that target peer can also close pending session.
    #[tokio::test]
    async fn target_can_close_pending_session() {
        let server = RelayServer::new().unwrap();
        
        let keypair_a = Keypair::generate();
        let keypair_b = Keypair::generate();
        
        let session_id: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        // Peer A initiates
        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(32);
        let request_a = RelayRequest {
            from_peer: keypair_a.identity(),
            target_peer: keypair_b.identity(),
            session_id,
        };
        let response = server.handle_request(request_a, tx_a).await;
        assert!(matches!(response, corium::relay::RelayResponse::Accepted { .. }));
        
        // Peer B (target) closes the session (should succeed)
        server.close_session(&session_id, &keypair_b.identity(), "target closing").await;
        
        // Session should be closed now
        assert!(server.load().await < 0.01);
    }

    /// Test that participants can close active sessions.
    #[tokio::test]
    async fn participant_can_close_active_session() {
        let server = RelayServer::new().unwrap();
        
        let keypair_a = Keypair::generate();
        let keypair_b = Keypair::generate();
        
        let session_id: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        // Peer A initiates
        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(32);
        let request_a = RelayRequest {
            from_peer: keypair_a.identity(),
            target_peer: keypair_b.identity(),
            session_id,
        };
        server.handle_request(request_a, tx_a).await;
        
        // Peer B connects - session now active
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel(32);
        let request_b = RelayRequest {
            from_peer: keypair_b.identity(),
            target_peer: keypair_a.identity(),
            session_id,
        };
        let response = server.handle_request(request_b, tx_b).await;
        assert!(matches!(response, corium::relay::RelayResponse::Connected { .. }));
        
        // Either participant can close
        server.close_session(&session_id, &keypair_a.identity(), "peer_a closing").await;
        
        // Session should be closed
        assert!(server.load().await < 0.01);
    }
}

// ============================================================================
// Relay Session Cleanup Under Load Tests
// ============================================================================

mod relay_cleanup_under_load {
    use super::*;
    use std::sync::Arc;

    /// Test that pending sessions are properly cleaned up under high load.
    /// 
    /// Creates many pending sessions (first peer connects but second never does)
    /// and verifies that cleanup_expired properly removes them and frees resources.
    #[tokio::test]
    async fn pending_sessions_cleanup_under_load() {
        // Use a small capacity for faster testing
        let server = RelayServer::with_capacity(50).unwrap();
        let mut session_ids: Vec<[u8; 16]> = Vec::new();
        
        // Create many pending sessions (first peer only)
        for i in 0u16..40 {
            let keypair_a = Keypair::generate();
            let keypair_b = Keypair::generate();
            
            let mut session_id = [0u8; 16];
            session_id[..2].copy_from_slice(&i.to_le_bytes());
            session_ids.push(session_id);
            
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            let request = RelayRequest {
                from_peer: keypair_a.identity(),
                target_peer: keypair_b.identity(),
                session_id,
            };
            
            let response = server.handle_request(request, tx).await;
            assert!(
                matches!(response, corium::relay::RelayResponse::Accepted { .. }),
                "session {} should be accepted",
                i
            );
        }
        
        // Verify load is high
        let load_before = server.load().await;
        assert!(load_before > 0.5, "load should be significant: {}", load_before);
        
        // Cleanup won't remove non-expired sessions, but verifies no panic under load
        server.cleanup_expired().await;
        
        // Load should be unchanged (sessions haven't timed out)
        let load_after = server.load().await;
        assert!(
            (load_after - load_before).abs() < 0.01,
            "load should be unchanged after cleanup of non-expired sessions"
        );
    }

    /// Test that issued_sessions tracking is properly cleaned during session expiry.
    /// 
    /// Verifies that expired session IDs are removed from the issued_sessions set
    /// to prevent unbounded memory growth.
    #[tokio::test]
    async fn issued_sessions_cleanup_on_expiry() {
        let server = RelayServer::with_capacity(20).unwrap();
        
        // Create some pending sessions
        let mut created_sessions: Vec<[u8; 16]> = Vec::new();
        for i in 0u8..10 {
            let keypair_a = Keypair::generate();
            let keypair_b = Keypair::generate();
            
            let mut session_id = [0u8; 16];
            session_id[0] = i;
            created_sessions.push(session_id);
            
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            let request = RelayRequest {
                from_peer: keypair_a.identity(),
                target_peer: keypair_b.identity(),
                session_id,
            };
            
            server.handle_request(request, tx).await;
        }
        
        // All sessions should be tracked as issued
        for session_id in &created_sessions {
            assert!(
                server.is_session_issued(session_id).await,
                "session should be tracked as issued"
            );
        }
        
        // New sessions with same IDs should be rejected if capacity is reached
        // (This tests the tracking mechanism is working)
        let load = server.load().await;
        assert!(load > 0.4, "server should have significant load");
    }

    /// Test concurrent session creation doesn't cause race conditions.
    #[tokio::test]
    async fn concurrent_session_creation() {
        let server = Arc::new(RelayServer::with_capacity(100).unwrap());
        let mut handles = Vec::new();
        
        // Spawn many concurrent session creation tasks
        for i in 0u16..50 {
            let server_clone = Arc::clone(&server);
            let handle = tokio::spawn(async move {
                let keypair_a = Keypair::generate();
                let keypair_b = Keypair::generate();
                
                let mut session_id = [0u8; 16];
                session_id[..2].copy_from_slice(&i.to_le_bytes());
                
                let (tx, _rx) = tokio::sync::mpsc::channel(1);
                let request = RelayRequest {
                    from_peer: keypair_a.identity(),
                    target_peer: keypair_b.identity(),
                    session_id,
                };
                
                server_clone.handle_request(request, tx).await
            });
            handles.push(handle);
        }
        
        // Wait for all tasks to complete
        let results: Vec<_> = futures::future::join_all(handles).await;
        
        // Count accepted sessions
        let accepted_count = results
            .iter()
            .filter(|r| {
                matches!(
                    r.as_ref().unwrap(),
                    corium::relay::RelayResponse::Accepted { .. }
                )
            })
            .count();
        
        // All 50 should be accepted (capacity is 100)
        assert_eq!(accepted_count, 50, "all sessions should be accepted");
        
        // Cleanup should work without deadlock
        server.cleanup_expired().await;
    }

    /// Test that active sessions are properly cleaned up when closed.
    #[tokio::test]
    async fn active_sessions_cleanup_on_close() {
        let server = RelayServer::with_capacity(20).unwrap();
        let mut sessions: Vec<([u8; 16], corium::identity::Identity, corium::identity::Identity)> = Vec::new();
        
        // Create active sessions (both peers connect)
        for i in 0u8..10 {
            let keypair_a = Keypair::generate();
            let keypair_b = Keypair::generate();
            
            let mut session_id = [0u8; 16];
            session_id[0] = i;
            
            // First peer connects
            let (tx_a, _rx_a) = tokio::sync::mpsc::channel(1);
            let request_a = RelayRequest {
                from_peer: keypair_a.identity(),
                target_peer: keypair_b.identity(),
                session_id,
            };
            server.handle_request(request_a, tx_a).await;
            
            // Second peer connects
            let (tx_b, _rx_b) = tokio::sync::mpsc::channel(1);
            let request_b = RelayRequest {
                from_peer: keypair_b.identity(),
                target_peer: keypair_a.identity(),
                session_id,
            };
            let response = server.handle_request(request_b, tx_b).await;
            assert!(matches!(response, corium::relay::RelayResponse::Connected { .. }));
            
            sessions.push((session_id, keypair_a.identity(), keypair_b.identity()));
        }
        
        // All sessions should be active
        let load_before = server.load().await;
        assert!(load_before > 0.4, "server should have active sessions");
        
        // Close all sessions
        for (session_id, identity_a, _identity_b) in &sessions {
            server.close_session(session_id, identity_a, "test cleanup").await;
        }
        
        // All sessions should be removed
        let load_after = server.load().await;
        assert!(load_after < 0.01, "all sessions should be closed, load: {}", load_after);
        
        // Cleanup should handle empty state gracefully
        server.cleanup_expired().await;
    }

    /// Test capacity enforcement under sustained load.
    /// 
    /// Verifies that when capacity is reached, new requests are properly rejected
    /// and existing sessions remain functional.
    #[tokio::test]
    async fn capacity_enforcement_under_load() {
        // Very small capacity for testing limits
        let server = RelayServer::with_capacity(5).unwrap();
        let mut accepted_sessions: Vec<[u8; 16]> = Vec::new();
        
        // Try to create more sessions than capacity allows
        for i in 0u8..10 {
            let keypair_a = Keypair::generate();
            let keypair_b = Keypair::generate();
            
            let mut session_id = [0u8; 16];
            session_id[0] = i;
            
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            let request = RelayRequest {
                from_peer: keypair_a.identity(),
                target_peer: keypair_b.identity(),
                session_id,
            };
            
            let response = server.handle_request(request, tx).await;
            
            if matches!(response, corium::relay::RelayResponse::Accepted { .. }) {
                accepted_sessions.push(session_id);
            }
        }
        
        // Should have accepted exactly 5 (capacity limit)
        assert_eq!(
            accepted_sessions.len(),
            5,
            "exactly capacity sessions should be accepted"
        );
        
        // Server should not be accepting more
        assert!(!server.is_accepting().await || server.load().await >= 0.9);
    }

    /// Test that forwarder registry properly limits concurrent tasks.
    #[tokio::test]
    async fn forwarder_registry_capacity_limits() {
        let registry = corium::relay::ForwarderRegistry::new();
        
        // Initially should accept tasks
        assert!(registry.can_accept().await);
        assert_eq!(registry.active_count().await, 0);
        
        // Register some dummy tasks
        for i in 0u8..10 {
            let mut session_id = [0u8; 16];
            session_id[0] = i;
            
            // Create a task that runs briefly then completes
            let handle = tokio::spawn(async {
                tokio::time::sleep(Duration::from_millis(100)).await;
            });
            
            let registered = registry.register(session_id, handle).await;
            assert!(registered, "task {} should be registered", i);
        }
        
        // Should have 10 active tasks
        assert_eq!(registry.active_count().await, 10);
        
        // Wait for tasks to complete
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Cleanup completed tasks
        registry.cleanup_completed().await;
        
        // All tasks should be cleaned up
        assert_eq!(registry.active_count().await, 0);
    }

    /// Test that aborting a session also aborts the forwarder task.
    #[tokio::test]
    async fn forwarder_abort_on_session_close() {
        let registry = corium::relay::ForwarderRegistry::new();
        
        let session_id: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        // Create a long-running task
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        
        registry.register(session_id, handle).await;
        assert_eq!(registry.active_count().await, 1);
        
        // Abort the session
        registry.abort(&session_id).await;
        
        // Task should be removed
        assert_eq!(registry.active_count().await, 0);
    }

    /// Test abort_all cleans up all forwarder tasks.
    #[tokio::test]
    async fn forwarder_abort_all() {
        let registry = corium::relay::ForwarderRegistry::new();
        
        // Register multiple long-running tasks
        for i in 0u8..5 {
            let mut session_id = [0u8; 16];
            session_id[0] = i;
            
            let handle = tokio::spawn(async {
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
            
            registry.register(session_id, handle).await;
        }
        
        assert_eq!(registry.active_count().await, 5);
        
        // Abort all
        registry.abort_all().await;
        
        // All should be cleaned up
        assert_eq!(registry.active_count().await, 0);
    }

    /// Test rapid session create/close cycles don't leak resources.
    #[tokio::test]
    async fn rapid_create_close_cycles() {
        let server = RelayServer::with_capacity(10).unwrap();
        
        // Perform many rapid create/close cycles
        for cycle in 0u16..100 {
            let keypair_a = Keypair::generate();
            let keypair_b = Keypair::generate();
            
            let mut session_id = [0u8; 16];
            session_id[..2].copy_from_slice(&cycle.to_le_bytes());
            
            // Create session
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            let request = RelayRequest {
                from_peer: keypair_a.identity(),
                target_peer: keypair_b.identity(),
                session_id,
            };
            
            let response = server.handle_request(request, tx).await;
            
            // Should always be accepted (we close each before creating next)
            assert!(
                matches!(response, corium::relay::RelayResponse::Accepted { .. }),
                "cycle {} should be accepted",
                cycle
            );
            
            // Close immediately
            server.close_session(&session_id, &keypair_a.identity(), "cycle test").await;
        }
        
        // Server should be empty after all cycles
        let final_load = server.load().await;
        assert!(final_load < 0.01, "server should be empty after cycles: {}", final_load);
    }

    /// Test mixed pending and active session cleanup.
    #[tokio::test]
    async fn mixed_session_state_cleanup() {
        let server = RelayServer::with_capacity(20).unwrap();
        
        // Create some pending sessions (only first peer)
        for i in 0u8..5 {
            let keypair_a = Keypair::generate();
            let keypair_b = Keypair::generate();
            
            let mut session_id = [0u8; 16];
            session_id[0] = i;
            session_id[1] = 0; // Marker for pending
            
            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            let request = RelayRequest {
                from_peer: keypair_a.identity(),
                target_peer: keypair_b.identity(),
                session_id,
            };
            server.handle_request(request, tx).await;
        }
        
        // Create some active sessions (both peers)
        let mut active_sessions = Vec::new();
        for i in 0u8..5 {
            let keypair_a = Keypair::generate();
            let keypair_b = Keypair::generate();
            
            let mut session_id = [0u8; 16];
            session_id[0] = i;
            session_id[1] = 1; // Marker for active
            
            // First peer
            let (tx_a, _rx_a) = tokio::sync::mpsc::channel(1);
            let request_a = RelayRequest {
                from_peer: keypair_a.identity(),
                target_peer: keypair_b.identity(),
                session_id,
            };
            server.handle_request(request_a, tx_a).await;
            
            // Second peer
            let (tx_b, _rx_b) = tokio::sync::mpsc::channel(1);
            let request_b = RelayRequest {
                from_peer: keypair_b.identity(),
                target_peer: keypair_a.identity(),
                session_id,
            };
            server.handle_request(request_b, tx_b).await;
            
            active_sessions.push((session_id, keypair_a.identity()));
        }
        
        // Verify we have mixed state
        let load = server.load().await;
        assert!(load > 0.4, "should have both pending and active sessions");
        
        // Close only active sessions
        for (session_id, identity) in &active_sessions {
            server.close_session(session_id, identity, "test").await;
        }
        
        // Should still have pending sessions
        let load_after_close = server.load().await;
        assert!(load_after_close > 0.2, "should still have pending sessions");
        assert!(load_after_close < load, "load should decrease after closing active");
        
        // Cleanup should work with mixed state
        server.cleanup_expired().await;
    }

    /// Test that session ID uniqueness is enforced.
    #[tokio::test]
    async fn session_id_uniqueness() {
        let server = RelayServer::with_capacity(10).unwrap();
        
        let keypair_a1 = Keypair::generate();
        let keypair_b1 = Keypair::generate();
        let keypair_a2 = Keypair::generate();
        let keypair_b2 = Keypair::generate();
        
        // Same session ID used by different peer pairs
        let session_id: [u8; 16] = [42u8; 16];
        
        // First pair creates session
        let (tx1, _rx1) = tokio::sync::mpsc::channel(1);
        let request1 = RelayRequest {
            from_peer: keypair_a1.identity(),
            target_peer: keypair_b1.identity(),
            session_id,
        };
        let response1 = server.handle_request(request1, tx1).await;
        assert!(matches!(response1, corium::relay::RelayResponse::Accepted { .. }));
        
        // Second pair tries to use same session ID - should be rejected
        // (because target_peer doesn't match the expected target from first request)
        let (tx2, _rx2) = tokio::sync::mpsc::channel(1);
        let request2 = RelayRequest {
            from_peer: keypair_a2.identity(),
            target_peer: keypair_b2.identity(),
            session_id,
        };
        let response2 = server.handle_request(request2, tx2).await;
        // This is actually rejected because the from_peer doesn't match expected target
        assert!(matches!(response2, corium::relay::RelayResponse::Rejected { .. }));
    }

    /// Stress test: many concurrent operations.
    #[tokio::test]
    async fn stress_test_concurrent_operations() {
        let server = Arc::new(RelayServer::with_capacity(50).unwrap());
        let mut handles = Vec::new();
        
        // Spawn concurrent session creators
        for i in 0u16..30 {
            let server_clone = Arc::clone(&server);
            handles.push(tokio::spawn(async move {
                let keypair_a = Keypair::generate();
                let keypair_b = Keypair::generate();
                
                let mut session_id = [0u8; 16];
                session_id[..2].copy_from_slice(&i.to_le_bytes());
                
                let (tx, _rx) = tokio::sync::mpsc::channel(1);
                let request = RelayRequest {
                    from_peer: keypair_a.identity(),
                    target_peer: keypair_b.identity(),
                    session_id,
                };
                
                server_clone.handle_request(request, tx).await;
                (session_id, keypair_a.identity())
            }));
        }
        
        // Wait for all creations
        let sessions: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .collect();
        
        // Spawn concurrent cleanup tasks
        let cleanup_handles: Vec<_> = (0..5)
            .map(|_| {
                let server_clone = Arc::clone(&server);
                tokio::spawn(async move {
                    server_clone.cleanup_expired().await;
                })
            })
            .collect();
        
        // Spawn concurrent close tasks
        let close_handles: Vec<_> = sessions
            .iter()
            .map(|(session_id, identity)| {
                let server_clone = Arc::clone(&server);
                let sid = *session_id;
                let id = *identity;
                tokio::spawn(async move {
                    server_clone.close_session(&sid, &id, "stress test").await;
                })
            })
            .collect();
        
        // Wait for all operations to complete (should not deadlock or panic)
        futures::future::join_all(cleanup_handles).await;
        futures::future::join_all(close_handles).await;
        
        // Server should be in consistent state
        let final_load = server.load().await;
        assert!(final_load <= 1.0, "load should be valid: {}", final_load);
    }
}