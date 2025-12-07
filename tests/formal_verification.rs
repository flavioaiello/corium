//! Formal Verification Tests for Cryptographic Identity Flow
//!
//! This test module provides comprehensive verification of the security properties
//! documented in `identity.rs`. Each test corresponds to a formal property (P1-P4)
//! and verifies it holds under various conditions.
//!
//! # Zero-Hash Architecture
//!
//! In the zero-hash model, Identity IS the Ed25519 public key directly.
//! There is no BLAKE3 hashing of the public key - the 32-byte public key
//! bytes are used directly as the DHT routing key.
//!
//! # Security Properties Verified
//!
//! - **P1**: Identity = PublicKey (exact byte equality, zero transformation)
//! - **P2**: XOR Distance operates directly on Identity bytes
//! - **P3**: SNI Identity Pinning (certificate public key matches SNI)
//! - **P4**: Sybil Protection (Identity cryptographically bound to public key)
//! - **P5**: EndpointRecord Authentication (signature binds all fields)
//!
//! # Chain of Trust
//!
//! ```text
//! Ed25519 Secret Key
//!        │
//!        ├──► Ed25519 Public Key = Identity (P1) (DIRECT EQUALITY)
//!        │           │
//!        │           ├──► DHT Routing Key = Identity bytes (zero-hash)
//!        │           │
//!        │           ├──► TLS Certificate (SPKI contains public key)
//!        │           │           │
//!        │           │           └──► SNI = hex(Identity) (P3)
//!        │           │
//!        │           └──► EndpointRecord (signed by secret key) (P5)
//!        │
//!        └──► Sybil Protection: verify_identity(identity, cert.pk) (P4)
//! ```

use corium::{Keypair, Identity, RelayEndpoint};
use corium::advanced::{
    verify_identity,
    extract_public_key_from_cert, generate_ed25519_cert,
};
use std::collections::HashSet;

// ============================================================================
// P1: Identity = PublicKey (Exact Byte Equality, Zero Transformation)
// ============================================================================

mod p1_identity_binding {
    use super::*;

    /// P1: Identity bytes must exactly equal public key bytes.
    #[test]
    fn identity_equals_public_key() {
        for _ in 0..100 {
            let keypair = Keypair::generate();
            let public_key = keypair.public_key_bytes();
            let identity = keypair.identity();
            
            assert_eq!(
                *identity.as_bytes(),
                public_key,
                "P1 violation: Identity bytes differ from public key"
            );
        }
    }

    /// P1: Identity construction is reversible.
    #[test]
    fn identity_roundtrip() {
        for _ in 0..100 {
            let keypair = Keypair::generate();
            let original_bytes = keypair.public_key_bytes();
            
            let identity = Identity::from_bytes(original_bytes);
            let recovered_bytes = *identity.as_bytes();
            
            assert_eq!(
                original_bytes, recovered_bytes,
                "P1 violation: Identity::from_bytes -> as_bytes not lossless"
            );
        }
    }

    /// P1: No information loss in Identity.
    #[test]
    fn no_information_loss() {
        // Two different keypairs must produce different identities
        let mut identities = HashSet::new();
        
        for _ in 0..1000 {
            let keypair = Keypair::generate();
            let identity = keypair.identity();
            
            assert!(
                identities.insert(*identity.as_bytes()),
                "P1 violation: Identity collision (information loss)"
            );
        }
    }
}

// ============================================================================
// P2: XOR Distance operates directly on Identity bytes (Zero-Hash Property)
// ============================================================================

mod p2_xor_distance {
    use super::*;

    /// P2: XOR distance is symmetric.
    #[test]
    fn xor_distance_symmetric() {
        for _ in 0..100 {
            let a = Keypair::generate().identity();
            let b = Keypair::generate().identity();
            
            let dist_ab = a.xor_distance(&b);
            let dist_ba = b.xor_distance(&a);
            
            assert_eq!(dist_ab, dist_ba, "XOR distance must be symmetric");
        }
    }

    /// P2: XOR distance with self is zero.
    #[test]
    fn xor_distance_self_is_zero() {
        for _ in 0..100 {
            let identity = Keypair::generate().identity();
            let dist = identity.xor_distance(&identity);
            
            assert_eq!(dist, [0u8; 32], "XOR distance with self must be zero");
        }
    }

    /// P2: XOR distance is computed on raw Identity bytes.
    #[test]
    fn xor_distance_uses_raw_bytes() {
        let a = Keypair::generate().identity();
        let b = Keypair::generate().identity();
        
        // Compute expected XOR distance manually
        let mut expected = [0u8; 32];
        for i in 0..32 {
            expected[i] = a.as_bytes()[i] ^ b.as_bytes()[i];
        }
        
        let actual = a.xor_distance(&b);
        
        assert_eq!(actual, expected, "XOR distance must operate on raw Identity bytes");
    }

    /// P2: No collision in XOR distance metric.
    #[test]
    fn xor_distance_no_collision() {
        // Verify that XOR distance preserves identity uniqueness
        let base = Keypair::generate().identity();
        let mut distances = HashSet::new();
        
        for _ in 0..1000 {
            let other = Keypair::generate().identity();
            let dist = base.xor_distance(&other);
            
            // Each random identity should produce a unique distance
            // (with overwhelming probability for 256-bit space)
            distances.insert(dist);
        }
        
        // All distances should be unique
        assert_eq!(distances.len(), 1000, "XOR distances should be unique for random identities");
    }
}

// ============================================================================
// P3: SNI Identity Pinning
// ============================================================================

mod p3_sni_pinning {
    use super::*;

    /// P3: Certificate contains the same public key as Identity.
    #[test]
    fn certificate_contains_identity_public_key() {
        for _ in 0..50 {
            let keypair = Keypair::generate();
            let identity = keypair.identity();
            
            let (certs, _key) = generate_ed25519_cert(&keypair)
                .expect("cert generation must succeed");
            
            let cert_der = certs[0].as_ref();
            let extracted_pk = extract_public_key_from_cert(cert_der)
                .expect("public key extraction must succeed");
            
            assert_eq!(
                extracted_pk,
                *identity.as_bytes(),
                "P3 violation: Certificate public key differs from Identity"
            );
        }
    }

    /// P3: verify_identity accepts matching certificate.
    #[test]
    fn verify_identity_accepts_matching_cert() {
        for _ in 0..50 {
            let keypair = Keypair::generate();
            let identity = keypair.identity();
            let public_key = keypair.public_key_bytes();
            
            assert!(
                verify_identity(&identity, &public_key),
                "P3 violation: verify_identity rejected matching public key"
            );
        }
    }

    /// P3: verify_identity rejects mismatched certificate.
    #[test]
    fn verify_identity_rejects_mismatched_cert() {
        for _ in 0..50 {
            let keypair1 = Keypair::generate();
            let keypair2 = Keypair::generate();
            
            let identity1 = keypair1.identity();
            let public_key2 = keypair2.public_key_bytes();
            
            assert!(
                !verify_identity(&identity1, &public_key2),
                "P3 violation: verify_identity accepted mismatched public key"
            );
        }
    }
}

// ============================================================================
// P4: Sybil Protection (Identity bound to public key)
// ============================================================================

mod p4_sybil_protection {
    use super::*;

    /// P4: Cannot construct arbitrary Identity without corresponding private key.
    /// 
    /// In the zero-hash model, an attacker cannot claim an arbitrary Identity
    /// because they cannot produce a TLS certificate with the matching public key.
    #[test]
    fn arbitrary_identity_rejected() {
        // Create an attacker's keypair
        let attacker_keypair = Keypair::generate();
        let attacker_public_key = attacker_keypair.public_key_bytes();
        
        // Create a "victim" identity (some other peer's identity)
        let victim_identity = Keypair::generate().identity();
        
        // Attacker cannot verify victim's identity with attacker's public key
        assert!(
            !verify_identity(&victim_identity, &attacker_public_key),
            "P4 violation: Attacker can claim arbitrary identity"
        );
    }

    /// P4: Identity is cryptographically bound to the keypair.
    #[test]
    fn identity_bound_to_keypair() {
        for _ in 0..100 {
            let keypair = Keypair::generate();
            let identity = keypair.identity();
            
            // The only way to prove ownership of an Identity is to have
            // the corresponding private key, which produces a matching certificate
            let (certs, _) = generate_ed25519_cert(&keypair)
                .expect("cert generation must succeed");
            
            let cert_pk = extract_public_key_from_cert(certs[0].as_ref())
                .expect("pk extraction must succeed");
            
            assert!(
                verify_identity(&identity, &cert_pk),
                "P4 violation: Identity not bound to keypair"
            );
        }
    }

    /// P4: Different keypairs produce different identities.
    #[test]
    fn different_keypairs_different_identities() {
        let mut identities = HashSet::new();
        
        for _ in 0..1000 {
            let keypair = Keypair::generate();
            let identity = keypair.identity();
            
            assert!(
                identities.insert(*identity.as_bytes()),
                "P4 violation: Identity collision between different keypairs"
            );
        }
    }
}

// ============================================================================
// P5: EndpointRecord Authentication
// ============================================================================

mod p5_endpoint_record {
    use super::*;

    /// P5: EndpointRecord signature is valid.
    #[test]
    fn endpoint_record_signature_valid() {
        for _ in 0..50 {
            let keypair = Keypair::generate();
            let addresses = vec!["127.0.0.1:9000".to_string()];
            
            let record = keypair.create_endpoint_record(addresses);
            
            assert!(
                record.verify(),
                "P5 violation: EndpointRecord signature is invalid"
            );
        }
    }

    /// P5: EndpointRecord with wrong signature is rejected.
    #[test]
    fn endpoint_record_wrong_signature_rejected() {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        
        let mut record = keypair1.create_endpoint_record(vec!["127.0.0.1:9000".to_string()]);
        
        // Tamper with the identity to simulate forgery
        record.identity = keypair2.identity();
        
        assert!(
            !record.verify(),
            "P5 violation: Tampered EndpointRecord signature was accepted"
        );
    }

    /// P5: EndpointRecord with tampered addresses is rejected.
    #[test]
    fn endpoint_record_tampered_addresses_rejected() {
        let keypair = Keypair::generate();
        
        let mut record = keypair.create_endpoint_record(vec!["127.0.0.1:9000".to_string()]);
        
        // Tamper with the addresses
        record.addrs.push("10.0.0.1:9000".to_string());
        
        assert!(
            !record.verify(),
            "P5 violation: Tampered EndpointRecord addresses were accepted"
        );
    }

    /// P5: EndpointRecord with relay endpoints verifies correctly.
    #[test]
    fn endpoint_record_with_relays() {
        let keypair = Keypair::generate();
        let relay_identity = Keypair::generate().identity();
        
        let relays = vec![RelayEndpoint {
            relay_identity,
            relay_addrs: vec!["relay.example.com:9000".to_string()],
        }];
        
        let record = keypair.create_endpoint_record_with_relays(
            vec!["127.0.0.1:9000".to_string()],
            relays,
        );
        
        assert!(
            record.verify(),
            "P5 violation: EndpointRecord with relays has invalid signature"
        );
    }
}
