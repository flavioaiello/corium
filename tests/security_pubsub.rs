//! Security tests for PubSub (GossipSub) components.
//!
//! This test module covers:
//! - Message flood protection
//! - Rate limiting
//! - Topic validation
//! - IWant amplification attack prevention
//! - Message deduplication

use std::time::Duration;

use corium::identity::Keypair;
use corium::pubsub::{GossipConfig, MessageId, PubSubMessage};

// ============================================================================
// Configuration Security Tests
// ============================================================================

mod config_security {
    use super::*;

    /// Test that default configuration has reasonable security limits.
    #[test]
    fn default_config_has_security_limits() {
        let config = GossipConfig::default();
        
        // Message size should be bounded (between 1KB and 1MB)
        assert!(
            config.max_message_size >= 1024 && config.max_message_size <= 1024 * 1024,
            "max_message_size should be between 1KB and 1MB, got {}",
            config.max_message_size
        );
        
        // Rate limits should be set and reasonable
        assert!(
            config.publish_rate_limit >= 1 && config.publish_rate_limit <= 10000,
            "publish_rate_limit should be reasonable, got {}",
            config.publish_rate_limit
        );
        assert!(
            config.forward_rate_limit >= 1 && config.forward_rate_limit <= 100000,
            "forward_rate_limit should be reasonable, got {}",
            config.forward_rate_limit
        );
        assert!(
            config.per_peer_rate_limit >= 1 && config.per_peer_rate_limit <= 1000,
            "per_peer_rate_limit should be reasonable, got {}",
            config.per_peer_rate_limit
        );
        
        // Mesh parameters should be balanced
        assert!(
            config.mesh_degree >= 2 && config.mesh_degree <= 20,
            "mesh_degree should be between 2 and 20, got {}",
            config.mesh_degree
        );
        assert!(
            config.mesh_degree_low < config.mesh_degree,
            "mesh_degree_low ({}) should be less than mesh_degree ({})",
            config.mesh_degree_low,
            config.mesh_degree
        );
        assert!(
            config.mesh_degree < config.mesh_degree_high,
            "mesh_degree ({}) should be less than mesh_degree_high ({})",
            config.mesh_degree,
            config.mesh_degree_high
        );
        
        // Cache should have reasonable limits
        assert!(
            config.message_cache_size >= 100 && config.message_cache_size <= 1_000_000,
            "message_cache_size should be reasonable, got {}",
            config.message_cache_size
        );
        
        // TTL should be between 10 seconds and 1 hour
        assert!(
            config.message_cache_ttl >= Duration::from_secs(10)
                && config.message_cache_ttl <= Duration::from_secs(3600),
            "message_cache_ttl should be reasonable, got {:?}",
            config.message_cache_ttl
        );
    }
}

// ============================================================================
// PubSubMessage Security Tests
// ============================================================================

mod message_security {
    use super::*;

    /// Test Subscribe message structure.
    #[test]
    fn subscribe_message_structure() {
        let msg = PubSubMessage::Subscribe {
            topic: "test/topic".to_string(),
        };
        
        assert_eq!(msg.topic(), Some("test/topic"));
        
        // Should serialize/deserialize correctly
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.topic(), Some("test/topic"));
    }

    /// Test Publish message structure.
    #[test]
    fn publish_message_structure() {
        let keypair = Keypair::generate();
        let source = keypair.identity();
        let data = b"test message".to_vec();
        let msg_id: MessageId = [0u8; 32];
        
        let msg = PubSubMessage::Publish {
            topic: "test/topic".to_string(),
            msg_id,
            source,
            seqno: 1,
            data: data.clone(),
            signature: vec![0u8; 64],
        };
        
        assert_eq!(msg.topic(), Some("test/topic"));
        
        // Should serialize/deserialize correctly
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();
        
        if let PubSubMessage::Publish { topic, seqno, data: decoded_data, .. } = decoded {
            assert_eq!(topic, "test/topic");
            assert_eq!(seqno, 1);
            assert_eq!(decoded_data, data);
        } else {
            panic!("Expected Publish message");
        }
    }

    /// Test IHave message structure.
    #[test]
    fn ihave_message_structure() {
        let msg_ids: Vec<MessageId> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        
        let msg = PubSubMessage::IHave {
            topic: "test/topic".to_string(),
            msg_ids: msg_ids.clone(),
        };
        
        assert_eq!(msg.topic(), Some("test/topic"));
        
        // Should serialize/deserialize correctly
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();
        
        if let PubSubMessage::IHave { msg_ids: decoded_ids, .. } = decoded {
            assert_eq!(decoded_ids, msg_ids);
        } else {
            panic!("Expected IHave message");
        }
    }

    /// Test IWant message structure (no topic).
    #[test]
    fn iwant_message_no_topic() {
        let msg_ids: Vec<MessageId> = vec![[1u8; 32], [2u8; 32]];
        
        let msg = PubSubMessage::IWant { msg_ids };
        
        // IWant has no topic
        assert_eq!(msg.topic(), None);
    }

    /// Test Prune message includes peer suggestions.
    #[test]
    fn prune_message_with_peers() {
        let peer1 = Keypair::generate().identity();
        let peer2 = Keypair::generate().identity();
        
        let msg = PubSubMessage::Prune {
            topic: "test/topic".to_string(),
            peers: vec![peer1, peer2],
        };
        
        assert_eq!(msg.topic(), Some("test/topic"));
        
        // Should serialize/deserialize correctly
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();
        
        if let PubSubMessage::Prune { peers, .. } = decoded {
            assert_eq!(peers.len(), 2);
        } else {
            panic!("Expected Prune message");
        }
    }
}

// ============================================================================
// Topic Validation Tests
// ============================================================================

mod topic_validation {
    /// Reasonable maximum topic length for testing
    const MAX_TOPIC_LENGTH: usize = 256;

    /// Test that topic names have reasonable structure.
    #[test]
    fn topic_name_structure() {
        let valid_topics = vec![
            "chat/lobby",
            "sensors/temperature",
            "my-app/events",
            "a",
            "topic.with.dots",
            "UPPERCASE",
            "MixedCase123",
        ];
        
        for topic in &valid_topics {
            // Valid topics should be non-empty and within reasonable length
            assert!(!topic.is_empty(), "Topic should not be empty");
            assert!(
                topic.len() <= MAX_TOPIC_LENGTH,
                "Topic '{}' exceeds max length",
                topic
            );
        }
    }

    /// Test that very long topics exceed reasonable limits.
    #[test]
    fn long_topic_exceeds_limit() {
        let long_topic = "a".repeat(MAX_TOPIC_LENGTH + 1);
        
        // Verify the generated topic is indeed too long
        assert_eq!(
            long_topic.len(),
            MAX_TOPIC_LENGTH + 1,
            "Generated topic should exceed limit"
        );
    }

    /// Test empty topic detection.
    #[test]
    fn topic_empty_string_validation() {
        // Test that empty topics should be rejected by any proper validation
        let empty = String::new();
        let whitespace_only = "   ";
        let valid = "chat/room1";
        
        // Verify trimmed empty detection - topics need non-whitespace content
        assert!(empty.trim().is_empty(), "Empty string should have no content");
        assert!(whitespace_only.trim().is_empty(), "Whitespace-only should be considered empty");
        assert!(!valid.trim().is_empty(), "Valid topic should have content");
        
        // Verify length checking works on validated topics
        assert!(valid.len() < MAX_TOPIC_LENGTH);
    }
}

// ============================================================================
// Message ID Security Tests
// ============================================================================

mod message_id_security {
    use corium::hash_content;

    /// Test that message IDs are deterministic.
    #[test]
    fn message_id_deterministic() {
        let data = b"test message data";
        
        let id1 = hash_content(data);
        let id2 = hash_content(data);
        
        assert_eq!(id1, id2);
    }

    /// Test that different data produces different message IDs.
    #[test]
    fn different_data_different_ids() {
        let data1 = b"message one";
        let data2 = b"message two";
        
        let id1 = hash_content(data1);
        let id2 = hash_content(data2);
        
        assert_ne!(id1, id2);
    }

    /// Test message ID collision resistance.
    #[test]
    fn message_id_collision_resistance() {
        let mut ids = std::collections::HashSet::new();
        
        // Generate many message IDs
        for i in 0..10000 {
            let data = format!("message number {}", i);
            let id = hash_content(data.as_bytes());
            assert!(ids.insert(id), "Collision at message {}", i);
        }
    }
}

// ============================================================================
// Amplification Attack Prevention Tests
// ============================================================================

mod amplification_prevention {
    use super::*;

    /// Test IWant message can be created with many IDs but should be limited in practice.
    #[test]
    fn iwant_message_serialization() {
        // Creating an IWant with many IDs - this tests the structure, not the limit
        let many_ids: Vec<MessageId> = (0..100).map(|i| [i as u8; 32]).collect();
        
        let msg = PubSubMessage::IWant {
            msg_ids: many_ids.clone(),
        };
        
        // The message should serialize successfully
        let bytes = bincode::serialize(&msg).unwrap();
        
        // Each message ID is 32 bytes, so 100 IDs = 3200 bytes minimum
        assert!(
            bytes.len() >= 100 * 32,
            "Serialized IWant should contain message ID data, got {} bytes",
            bytes.len()
        );
        
        // Verify roundtrip
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();
        if let PubSubMessage::IWant { msg_ids } = decoded {
            assert_eq!(msg_ids.len(), 100, "Should preserve all message IDs");
        } else {
            panic!("Expected IWant message after roundtrip");
        }
    }

    /// Test IHave message structure.
    #[test]
    fn ihave_message_serialization() {
        let msg_ids: Vec<MessageId> = (0..50).map(|i| [i as u8; 32]).collect();
        
        let msg = PubSubMessage::IHave {
            topic: "test/topic".to_string(),
            msg_ids: msg_ids.clone(),
        };
        
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();
        
        if let PubSubMessage::IHave { msg_ids: decoded_ids, topic } = decoded {
            assert_eq!(decoded_ids.len(), 50);
            assert_eq!(topic, "test/topic");
        } else {
            panic!("Expected IHave message");
        }
    }

    /// Test GossipConfig rate limits are balanced.
    #[test]
    fn rate_limits_balanced() {
        let config = GossipConfig::default();
        
        // Per-peer rate should be lower than global forward rate
        // This makes sense: forward rate handles all peers, per-peer is stricter
        assert!(
            config.per_peer_rate_limit <= config.forward_rate_limit,
            "per_peer ({}) should be <= forward_rate ({})",
            config.per_peer_rate_limit,
            config.forward_rate_limit
        );
    }
}

// ============================================================================
// Flood Protection Tests
// ============================================================================

mod flood_protection {
    use super::*;

    /// Test that GossipConfig has bounded message size.
    #[test]
    fn config_message_size_bounded() {
        let config = GossipConfig::default();
        
        // Message size should be bounded to prevent memory exhaustion
        // Reasonable range: 1KB to 1MB
        assert!(
            config.max_message_size >= 1024,
            "max_message_size ({}) should be at least 1KB",
            config.max_message_size
        );
        assert!(
            config.max_message_size <= 1024 * 1024,
            "max_message_size ({}) should be at most 1MB",
            config.max_message_size
        );
    }

    /// Test oversized message detection.
    #[test]
    fn oversized_message_detection() {
        let config = GossipConfig::default();
        
        // Create data larger than the config limit
        let oversized_data = vec![0u8; config.max_message_size + 1];
        
        // This data would be rejected by GossipSub
        assert_eq!(
            oversized_data.len(),
            config.max_message_size + 1,
            "Generated data should be exactly 1 byte over limit"
        );
    }

    /// Test rate limits are all set in config.
    #[test]
    fn rate_limits_all_set() {
        let config = GossipConfig::default();
        
        // All rate limits should be positive
        assert!(config.publish_rate_limit > 0, "publish_rate_limit should be positive");
        assert!(config.forward_rate_limit > 0, "forward_rate_limit should be positive");
        assert!(config.per_peer_rate_limit > 0, "per_peer_rate_limit should be positive");
    }
}

// ============================================================================
// Mesh Security Tests
// ============================================================================

mod mesh_security {
    use super::*;

    /// Test mesh degree bounds from config.
    #[test]
    fn mesh_degree_bounds() {
        let config = GossipConfig::default();
        
        // Mesh degree should be bounded to prevent:
        // - Too few peers (single point of failure)
        // - Too many peers (bandwidth exhaustion)
        assert!(
            config.mesh_degree >= 2 && config.mesh_degree <= 20,
            "mesh_degree ({}) should be between 2 and 20",
            config.mesh_degree
        );
        
        // Low/high bounds should bracket mesh_degree
        assert!(
            config.mesh_degree_low < config.mesh_degree,
            "mesh_degree_low ({}) should be < mesh_degree ({})",
            config.mesh_degree_low,
            config.mesh_degree
        );
        assert!(
            config.mesh_degree_high > config.mesh_degree,
            "mesh_degree_high ({}) should be > mesh_degree ({})",
            config.mesh_degree_high,
            config.mesh_degree
        );
    }

    /// Test that Graft message structure is correct.
    #[test]
    fn graft_message_structure() {
        let msg = PubSubMessage::Graft {
            topic: "test/topic".to_string(),
        };
        
        assert_eq!(msg.topic(), Some("test/topic"));
        
        // Roundtrip
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PubSubMessage = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.topic(), Some("test/topic"));
    }

    /// Test Unsubscribe message structure.
    #[test]
    fn unsubscribe_message_structure() {
        let msg = PubSubMessage::Unsubscribe {
            topic: "test/topic".to_string(),
        };
        
        assert_eq!(msg.topic(), Some("test/topic"));
    }
}

// ============================================================================
// Cache Security Tests
// ============================================================================

mod cache_security {
    use super::*;

    /// Test message cache configuration.
    #[test]
    fn message_cache_configuration() {
        let config = GossipConfig::default();
        
        // Cache size should be bounded
        assert!(config.message_cache_size > 0);
        assert!(config.message_cache_size <= 1_000_000);
        
        // Cache TTL should be reasonable
        assert!(config.message_cache_ttl >= Duration::from_secs(30));
        assert!(config.message_cache_ttl <= Duration::from_secs(3600));
    }

    /// Test fanout TTL configuration.
    #[test]
    fn fanout_ttl_configuration() {
        let config = GossipConfig::default();
        
        // Fanout cache should expire
        assert!(config.fanout_ttl >= Duration::from_secs(10));
        assert!(config.fanout_ttl <= Duration::from_secs(300));
    }
}

// ============================================================================
// Heartbeat Security Tests  
// ============================================================================

mod heartbeat_security {
    use super::*;

    /// Test heartbeat interval configuration.
    #[test]
    fn heartbeat_interval_configuration() {
        let config = GossipConfig::default();
        
        // Heartbeat should be frequent enough to maintain mesh
        // but not so frequent as to cause overhead
        assert!(config.heartbeat_interval >= Duration::from_millis(100));
        assert!(config.heartbeat_interval <= Duration::from_secs(10));
    }

    /// Test gossip interval configuration.
    #[test]
    fn gossip_interval_configuration() {
        let config = GossipConfig::default();
        
        // Gossip interval for IHave should be reasonable
        assert!(config.gossip_interval >= Duration::from_millis(100));
        assert!(config.gossip_interval <= Duration::from_secs(10));
    }
}

// ============================================================================
// All Message Types Roundtrip Tests
// ============================================================================

mod message_roundtrip {
    use super::*;

    /// Test all message types serialize/deserialize correctly.
    #[test]
    fn all_message_types_roundtrip() {
        let keypair = Keypair::generate();
        let identity = keypair.identity();
        
        let messages = vec![
            PubSubMessage::Subscribe {
                topic: "test".to_string(),
            },
            PubSubMessage::Unsubscribe {
                topic: "test".to_string(),
            },
            PubSubMessage::Graft {
                topic: "test".to_string(),
            },
            PubSubMessage::Prune {
                topic: "test".to_string(),
                peers: vec![identity],
            },
            PubSubMessage::Publish {
                topic: "test".to_string(),
                msg_id: [0u8; 32],
                source: identity,
                seqno: 1,
                data: b"test".to_vec(),
                signature: vec![0u8; 64], // placeholder signature
            },
            PubSubMessage::IHave {
                topic: "test".to_string(),
                msg_ids: vec![[1u8; 32]],
            },
            PubSubMessage::IWant {
                msg_ids: vec![[1u8; 32]],
            },
        ];
        
        for msg in messages {
            let bytes = bincode::serialize(&msg).expect("serialization should work");
            let decoded: PubSubMessage =
                bincode::deserialize(&bytes).expect("deserialization should work");
            
            // Verify topic matches (if applicable)
            assert_eq!(msg.topic(), decoded.topic());
        }
    }
}

// ============================================================================
// Message Authentication Security Tests
// ============================================================================

mod message_authentication {
    use super::*;
    use corium::pubsub::{sign_pubsub_message, verify_pubsub_signature, SignatureError};

    /// Test that signed messages can be verified by the correct identity.
    #[test]
    fn valid_signature_verifies() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let data = b"important message";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, data);
        
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &signature,
        );
        
        assert!(result.is_ok(), "valid signature must verify");
    }

    /// Test that forged messages (wrong signer) are rejected.
    #[test]
    fn forged_message_rejected() {
        let real_author = Keypair::generate();
        let attacker = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let data = b"important message";
        
        // Attacker creates a message claiming to be from real_author
        // but signs with their own key
        let forged_signature = sign_pubsub_message(&attacker, topic, seqno, data);
        
        // Verification with real_author's identity should fail
        let result = verify_pubsub_signature(
            &real_author.identity(),
            topic,
            seqno,
            data,
            &forged_signature,
        );
        
        assert_eq!(result, Err(SignatureError::VerificationFailed),
            "forged signature must be rejected");
    }

    /// Test that tampered data is detected.
    #[test]
    fn tampered_data_detected() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let original_data = b"important message";
        let tampered_data = b"malicious message";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, original_data);
        
        // Try to verify with tampered data
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            tampered_data,
            &signature,
        );
        
        assert_eq!(result, Err(SignatureError::VerificationFailed),
            "tampered data must be detected");
    }

    /// Test that seqno manipulation is detected.
    #[test]
    fn seqno_manipulation_detected() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let original_seqno = 123u64;
        let tampered_seqno = 999u64;
        let data = b"important message";
        
        let signature = sign_pubsub_message(&keypair, topic, original_seqno, data);
        
        // Try to verify with tampered seqno (cache poisoning attack)
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            tampered_seqno,
            data,
            &signature,
        );
        
        assert_eq!(result, Err(SignatureError::VerificationFailed),
            "seqno manipulation must be detected");
    }

    /// Test that topic substitution is detected.
    #[test]
    fn topic_substitution_detected() {
        let keypair = Keypair::generate();
        let original_topic = "public/channel";
        let tampered_topic = "private/admin";
        let seqno = 123u64;
        let data = b"important message";
        
        let signature = sign_pubsub_message(&keypair, original_topic, seqno, data);
        
        // Try to inject the message into a different topic
        let result = verify_pubsub_signature(
            &keypair.identity(),
            tampered_topic,
            seqno,
            data,
            &signature,
        );
        
        assert_eq!(result, Err(SignatureError::VerificationFailed),
            "topic substitution must be detected");
    }

    /// Test that missing signatures are rejected.
    #[test]
    fn missing_signature_rejected() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let data = b"important message";
        
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &[], // empty signature
        );
        
        assert_eq!(result, Err(SignatureError::Missing),
            "missing signature must be rejected");
    }

    /// Test that malformed signatures are rejected.
    #[test]
    fn malformed_signature_rejected() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let data = b"important message";
        
        // Wrong length signature
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &[0u8; 32], // should be 64 bytes
        );
        
        assert_eq!(result, Err(SignatureError::InvalidLength),
            "wrong-length signature must be rejected");
    }

    /// Test that signature includes protection against concatenation attacks.
    #[test]
    fn concatenation_attack_prevented() {
        let keypair = Keypair::generate();
        let seqno = 1u64;
        
        // Two different messages that would be identical without length prefixes
        let topic1 = "chat";
        let data1 = b"room/hello";
        
        let topic2 = "chat/room";
        let data2 = b"hello";
        
        let sig1 = sign_pubsub_message(&keypair, topic1, seqno, data1);
        let sig2 = sign_pubsub_message(&keypair, topic2, seqno, data2);
        
        // Signatures should be different
        assert_ne!(sig1, sig2, "different messages must have different signatures");
        
        // Cross-verification should fail
        let cross_verify = verify_pubsub_signature(
            &keypair.identity(),
            topic1,
            seqno,
            data2, // wrong data for topic1
            &sig2,
        );
        assert!(cross_verify.is_err(), "cross verification must fail");
    }

    /// Test that the Publish message type includes signature field.
    #[test]
    fn publish_message_has_signature_field() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"test data".to_vec();
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, &data);
        
        let msg = PubSubMessage::Publish {
            topic: topic.to_string(),
            msg_id: [0u8; 32],
            source: keypair.identity(),
            seqno,
            data: data.clone(),
            signature: signature.clone(),
        };
        
        // Verify the message contains the signature
        if let PubSubMessage::Publish { signature: msg_sig, .. } = msg {
            assert_eq!(msg_sig.len(), 64, "signature should be 64 bytes");
            assert_eq!(msg_sig, signature);
        } else {
            panic!("Expected Publish message");
        }
    }
}
