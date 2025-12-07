//! Cryptographic identity management for DHT nodes.
//!
//! This module provides Ed25519 keypair generation and cryptographic identity
//! for mesh addressing. Each node has a stable identity based on its
//! public key, independent of network address.
//!
//! # Design (Zero-Hash Architecture)
//!
//! ```text
//! Keypair (Ed25519 signing key)
//!    │
//!    └── Identity (32-byte Ed25519 public key) = DHT routing key
//!           │
//!           ├── DHT Routing: XOR distance on Identity bytes directly
//!           │
//!           ├── DHT Lookup: Identity → addr  → Network address resolution
//!           │
//!           └── TLS Certificate            → Connection authentication
//! ```
//!
//! # Formal Security Properties
//!
//! The cryptographic identity flow provides the following formally verifiable properties:
//!
//! ## P1: Identity Binding (Ed25519 → Identity)
//! - **Invariant**: `Identity = PublicKey` (exact byte equality)
//! - **Property**: One-to-one mapping, no hash collision possible
//! - **Verification**: Constant-time comparison of 32-byte arrays
//!
//! ## P2: Zero-Hash Property (Identity = DHT Key)
//! - **Invariant**: `Identity = PublicKey` (no hash transformation)
//! - **Property**: The Ed25519 public key IS the DHT routing key
//! - **Verification**: `verify_identity(identity, public_key)` returns true iff
//!   `identity.as_bytes() == public_key`
//!
//! ## P3: SNI Identity Pinning (Identity → TLS Certificate)
//! - **Invariant**: SNI hostname = `hex(Identity)` = `hex(PublicKey)`
//! - **Property**: Certificate verification extracts public key from SPKI,
//!   compares to expected Identity from SNI
//! - **Verification**: `Ed25519CertVerifier::verify_server_cert` enforces
//!   `Identity::from_hex(SNI) == Identity::from_bytes(cert.public_key)`
//!
//! ## P4: Sybil Protection Chain
//! - **Invariant**: `verify_identity(claimed_identity, cert.public_key)` must hold
//! - **Property**: A peer cannot claim an Identity that doesn't match their
//!   TLS certificate's public key
//! - **Verification**: `extract_verified_identity(connection)` derives Identity
//!   from certificate, not from claimed Contact
//!
//! ## P5: EndpointRecord Authentication
//! - **Invariant**: `signature = Ed25519.sign(sk, identity || addrs || relays || timestamp)`
//! - **Property**: Only the holder of the secret key can create valid records
//! - **Verification**: `EndpointRecord::verify()` reconstructs signed data
//!   with length prefixes and verifies Ed25519 signature
//!
//! # Example
//!
//! ```ignore
//! use corium::internals::Keypair;
//!
//! // Generate a new random keypair
//! let keypair = Keypair::generate();
//!
//! // Get the cryptographic identity (public key) - this IS the DHT routing key
//! let identity = keypair.identity();
//!
//! // Identity bytes equal public key bytes (zero-hash property)
//! assert_eq!(identity.as_bytes(), &keypair.public_key_bytes());
//!
//! // Access the public key bytes directly
//! let public_key_bytes = keypair.public_key_bytes();
//! ```

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

// ============================================================================
// Keypair
// ============================================================================

/// An Ed25519 keypair for node identity.
///
/// The keypair consists of:
/// - A 32-byte secret key (signing key)
/// - A 32-byte public key (verifying key)
///
/// The Identity is the public key itself (zero-hash architecture).
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a keypair from a 32-byte secret key.
    ///
    /// # Panics
    ///
    /// Panics if the secret key bytes are invalid.
    pub fn from_secret_key_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Get the secret key bytes (32 bytes).
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the cryptographic identity (public key).
    ///
    /// This is the primary identifier for addressing peers in the network.
    /// In the zero-hash architecture, the Identity IS the DHT routing key.
    pub fn identity(&self) -> Identity {
        Identity::from_bytes(self.public_key_bytes())
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a message with the secret key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against the public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.signing_key.verifying_key().verify(message, signature).is_ok()
    }

    /// Create a signed endpoint record announcing our network addresses.
    ///
    /// This record can be published to the DHT so other peers can find us.
    pub fn create_endpoint_record(&self, addrs: Vec<String>) -> EndpointRecord {
        self.create_endpoint_record_with_relays(addrs, vec![])
    }

    /// Create a signed endpoint record with relay information.
    ///
    /// Use this when behind NAT to advertise relay nodes that can forward traffic.
    pub fn create_endpoint_record_with_relays(
        &self,
        addrs: Vec<String>,
        relays: Vec<RelayEndpoint>,
    ) -> EndpointRecord {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let identity = self.identity();
        // Use unwrap_or_default for robustness against clock issues
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        // Sign (identity, addrs, relays, timestamp) with length prefixes to prevent malleability
        let mut data = Vec::new();
        data.extend_from_slice(identity.as_bytes());
        // Length-prefix addresses to prevent concatenation attacks
        // e.g., ["192.168.1.1", ":8080"] vs ["192.168.1.1:", "8080"]
        data.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
        for addr in &addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        // Include relays in signature with length prefixes
        data.extend_from_slice(&(relays.len() as u32).to_le_bytes());
        for relay in &relays {
            data.extend_from_slice(relay.relay_identity.as_bytes());
            data.extend_from_slice(&(relay.relay_addrs.len() as u32).to_le_bytes());
            for addr in &relay.relay_addrs {
                let addr_bytes = addr.as_bytes();
                data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
                data.extend_from_slice(addr_bytes);
            }
        }
        data.extend_from_slice(&timestamp.to_le_bytes());
        
        let signature = self.sign(&data);
        
        EndpointRecord {
            identity,
            addrs,
            relays,
            timestamp,
            signature: signature.to_bytes().to_vec(),
        }
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("identity", &hex::encode(self.identity().as_bytes()))
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Identity
// ============================================================================

/// A peer's cryptographic identity (Ed25519 public key).
///
/// This is the primary way to identify and address peers in the network.
/// Unlike IP addresses, an Identity is:
/// - **Stable**: Doesn't change when the peer moves networks
/// - **Verifiable**: Can be authenticated via TLS certificate
/// - **Self-certifying**: The identity is the public key itself
///
/// The Identity is used for:
/// 1. **Addressing**: "Connect to this identity"
/// 2. **Routing**: Derive NodeId for DHT lookups
/// 3. **Authentication**: Verify TLS certificate matches
///
/// # Formal Property (P1)
///
/// `Identity = PublicKey` (exact 32-byte equality, no transformation)
///
/// This one-to-one mapping ensures no information loss and no collision
/// risk during the Identity ↔ PublicKey conversion.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identity([u8; 32]);

impl Identity {
    /// Create an Identity from raw bytes.
    ///
    /// # Formal Invariant
    /// `∀ bytes. Identity::from_bytes(bytes).as_bytes() == &bytes`
    #[inline]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let identity = Self(bytes);
        
        // Formal assertion: Identity preserves bytes exactly (P1)
        debug_assert_eq!(
            identity.0, bytes,
            "P1 violation: Identity must preserve bytes exactly"
        );
        
        identity
    }

    /// Get the raw bytes of the Identity.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute the XOR distance between this Identity and another.
    ///
    /// # Zero-Hash Property
    /// In the zero-hash architecture, XOR distance is computed directly
    /// on Identity bytes (which ARE the public key bytes).
    ///
    /// This is the core distance metric for Kademlia-style DHT routing.
    #[inline]
    pub fn xor_distance(&self, other: &Identity) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = self.0[i] ^ other.0[i];
        }
        out
    }

    /// Encode as hex string.
    ///
    /// # Formal Invariant
    /// `∀ id. Identity::from_hex(id.to_hex()) == Ok(id)`
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decode from hex string.
    ///
    /// # Formal Invariant
    /// Roundtrip: `Identity::from_hex(id.to_hex())` recovers the original.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Check if this Identity is valid (not a placeholder or reserved value).
    ///
    /// # Security
    ///
    /// Used to prevent routing table pollution from placeholder IDs.
    /// Returns false for:
    /// - All-zeros (placeholder for unknown peers)
    /// - All-ones (reserved/invalid)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corium::internals::Identity;
    ///
    /// let valid = Identity::from_bytes([1u8; 32]);
    /// assert!(valid.is_valid());
    ///
    /// let placeholder = Identity::from_bytes([0u8; 32]);
    /// assert!(!placeholder.is_valid());
    /// ```
    #[inline]
    pub fn is_valid(&self) -> bool {
        // Check for all-zeros (placeholder)
        if self.0.iter().all(|&b| b == 0) {
            return false;
        }
        // Check for all-ones (reserved/invalid)
        if self.0.iter().all(|&b| b == 0xFF) {
            return false;
        }
        true
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 32]> for Identity {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Identity> for [u8; 32] {
    fn from(identity: Identity) -> Self {
        identity.0
    }
}

impl AsRef<[u8]> for Identity {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ============================================================================
// Endpoint Records
// ============================================================================

/// An endpoint address record stored in the DHT.
///
/// Maps an Identity to its current network location(s). When a node is behind NAT,
/// it can also advertise relay nodes that can forward traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointRecord {
    /// The peer's cryptographic identity (public key).
    pub identity: Identity,
    /// Current network addresses (may have multiple for NAT traversal).
    /// These are direct addresses; may be empty if fully behind NAT.
    pub addrs: Vec<String>,
    /// Relay nodes that can forward traffic to this peer.
    /// Used when direct connection fails or peer is behind NAT.
    pub relays: Vec<RelayEndpoint>,
    /// Timestamp when this record was published (Unix millis).
    pub timestamp: u64,
    /// Signature over (identity, addrs, relays, timestamp) using the peer's private key.
    /// This proves the record was published by the owner of the Identity.
    pub signature: Vec<u8>,
}

/// A relay endpoint that can forward traffic to a peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayEndpoint {
    /// The relay node's identity.
    pub relay_identity: Identity,
    /// Addresses where the relay can be reached.
    pub relay_addrs: Vec<String>,
}

impl EndpointRecord {
    /// Verify the signature on this record.
    ///
    /// Returns true if the signature is valid and was made by the Identity owner.
    pub fn verify(&self) -> bool {
        // Reconstruct the signed data with length prefixes to prevent malleability
        let mut data = Vec::new();
        data.extend_from_slice(self.identity.as_bytes());
        // Length-prefix addresses to prevent concatenation attacks
        data.extend_from_slice(&(self.addrs.len() as u32).to_le_bytes());
        for addr in &self.addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        // Include relays in signature with length prefixes
        data.extend_from_slice(&(self.relays.len() as u32).to_le_bytes());
        for relay in &self.relays {
            data.extend_from_slice(relay.relay_identity.as_bytes());
            data.extend_from_slice(&(relay.relay_addrs.len() as u32).to_le_bytes());
            for addr in &relay.relay_addrs {
                let addr_bytes = addr.as_bytes();
                data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
                data.extend_from_slice(addr_bytes);
            }
        }
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        
        // Parse public key and signature
        let Ok(verifying_key) = VerifyingKey::try_from(self.identity.as_bytes().as_slice()) else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = self.signature.clone().try_into() else {
            return false;
        };
        let signature = Signature::from_bytes(&sig_bytes);
        
        // Verify
        verifying_key.verify_strict(&data, &signature).is_ok()
    }

    /// Verify the signature and check that the timestamp is recent.
    ///
    /// This prevents replay attacks where an attacker re-publishes an old
    /// EndpointRecord to redirect traffic to stale addresses.
    ///
    /// # Arguments
    /// * `max_age_secs` - Maximum allowed age of the record in seconds
    ///
    /// # Returns
    /// * `true` if signature is valid AND timestamp is within max_age_secs of now
    /// * `false` otherwise
    pub fn verify_fresh(&self, max_age_secs: u64) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // First verify the cryptographic signature
        if !self.verify() {
            return false;
        }
        
        // Check timestamp freshness to prevent replay attacks
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        
        let max_age_ms = max_age_secs * 1000;
        
        // Record must not be from the future (clock skew tolerance: 60 seconds)
        if self.timestamp > now_ms + 60_000 {
            return false;
        }
        
        // Record must not be too old
        if now_ms.saturating_sub(self.timestamp) > max_age_ms {
            return false;
        }
        
        true
    }

    /// Check if this peer has relay endpoints available.
    pub fn has_relays(&self) -> bool {
        !self.relays.is_empty()
    }

    /// Check if direct addresses are available.
    pub fn has_direct_addrs(&self) -> bool {
        !self.addrs.is_empty()
    }

    /// Validate the structure of the record without verifying the signature.
    ///
    /// This checks for reasonable limits on array sizes and address formats
    /// to prevent resource exhaustion attacks.
    pub fn validate_structure(&self) -> bool {
        // Limit number of addresses to prevent memory exhaustion
        const MAX_ADDRS: usize = 16;
        const MAX_RELAYS: usize = 8;
        const MAX_ADDR_LEN: usize = 256;
        
        if self.addrs.len() > MAX_ADDRS {
            return false;
        }
        
        if self.relays.len() > MAX_RELAYS {
            return false;
        }
        
        // Check address string lengths
        for addr in &self.addrs {
            if addr.len() > MAX_ADDR_LEN || addr.is_empty() {
                return false;
            }
        }
        
        // Check relay addresses
        for relay in &self.relays {
            if relay.relay_addrs.len() > MAX_ADDRS {
                return false;
            }
            for addr in &relay.relay_addrs {
                if addr.len() > MAX_ADDR_LEN || addr.is_empty() {
                    return false;
                }
            }
        }
        
        // Signature must be exactly 64 bytes (Ed25519)
        if self.signature.len() != 64 {
            return false;
        }
        
        true
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Verify that a claimed Identity matches a public key.
///
/// Returns `true` if the Identity bytes equal the public key bytes.
///
/// # Formal Property (P4 - Sybil Protection, Zero-Hash)
///
/// `verify_identity(id, pk) ⟺ id.as_bytes() == pk`
///
/// This is the core primitive for Sybil protection: a peer can only
/// claim an Identity that exactly matches their TLS certificate's public key.
///
/// # Constant-Time Comparison
///
/// Uses constant-time comparison to prevent timing side-channels that
/// could leak information about valid Identities.
#[inline]
pub fn verify_identity(identity: &Identity, public_key: &[u8; 32]) -> bool {
    // Zero-hash: Identity bytes must exactly equal public key bytes
    constant_time_eq(identity.as_bytes(), public_key)
}

/// Constant-time byte array comparison.
///
/// Prevents timing side-channels by always comparing all bytes,
/// regardless of where the first difference occurs.
#[inline]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        
        // Different keypairs should have different identities
        assert_ne!(kp1.identity(), kp2.identity());
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_keypair_from_secret_key() {
        let kp1 = Keypair::generate();
        let secret = kp1.secret_key_bytes();
        
        let kp2 = Keypair::from_secret_key_bytes(&secret);
        
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
        assert_eq!(kp1.identity(), kp2.identity());
    }

    #[test]
    fn test_identity_verification() {
        let kp = Keypair::generate();
        let identity = kp.identity();
        let public_key = kp.public_key_bytes();
        
        // Zero-hash model: Identity IS the public key
        assert!(verify_identity(&identity, &public_key));
        
        // Wrong public key should fail verification
        let other_kp = Keypair::generate();
        assert!(!verify_identity(&identity, &other_kp.public_key_bytes()));
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = Keypair::generate();
        let message = b"hello world";
        
        let signature = kp.sign(message);
        assert!(kp.verify(message, &signature));
        
        // Wrong message should fail
        assert!(!kp.verify(b"wrong message", &signature));
    }

    #[test]
    fn test_identity_from_keypair() {
        let kp = Keypair::generate();
        let identity = kp.identity();
        
        // Zero-hash model: Identity IS the public key bytes
        assert_eq!(*identity.as_bytes(), kp.public_key_bytes());
    }

    #[test]
    fn test_identity_hex_roundtrip() {
        let identity = Identity::from_bytes([42u8; 32]);
        let hex = identity.to_hex();
        let parsed = Identity::from_hex(&hex).unwrap();
        assert_eq!(identity, parsed);
    }

    #[test]
    fn test_identity_xor_distance() {
        let a = Identity::from_bytes([0xFF; 32]);
        let b = Identity::from_bytes([0x00; 32]);
        let c = Identity::from_bytes([0xFF; 32]);
        
        // XOR distance with itself is zero
        assert_eq!(a.xor_distance(&a), [0u8; 32]);
        
        // XOR distance is symmetric
        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));
        
        // XOR with all 0s and all 1s produces all 1s
        assert_eq!(a.xor_distance(&b), [0xFF; 32]);
        
        // XOR with identical is zero
        assert_eq!(a.xor_distance(&c), [0u8; 32]);
    }

    #[test]
    fn test_endpoint_record_verify_fresh_accepts_recent() {
        let kp = Keypair::generate();
        let record = kp.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);
        
        // Should accept a fresh record
        assert!(record.verify_fresh(3600)); // 1 hour
    }

    #[test]
    fn test_endpoint_record_verify_fresh_rejects_old() {
        let kp = Keypair::generate();
        let mut record = kp.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);
        
        // Set timestamp to 2 hours ago
        record.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 - (2 * 60 * 60 * 1000);
        
        // This test verifies the logic by checking that old records fail
        assert!(!record.verify_fresh(3600)); // 1 hour max age, record is 2 hours old
    }

    #[test]
    fn test_endpoint_record_verify_fresh_rejects_future() {
        let kp = Keypair::generate();
        let mut record = kp.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);
        
        // Set timestamp to 5 minutes in the future (beyond 60s tolerance)
        record.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 + (5 * 60 * 1000);
        
        // Should reject record from the future
        assert!(!record.verify_fresh(3600));
    }

    #[test]
    fn test_endpoint_record_validate_structure_valid() {
        let kp = Keypair::generate();
        let record = kp.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);
        
        assert!(record.validate_structure());
    }

    #[test]
    fn test_endpoint_record_validate_structure_too_many_addrs() {
        let kp = Keypair::generate();
        // Create record with too many addresses
        let addrs: Vec<String> = (0..20).map(|i| format!("192.168.1.{}:8080", i)).collect();
        let record = kp.create_endpoint_record(addrs);
        
        assert!(!record.validate_structure());
    }

    #[test]
    fn test_endpoint_record_validate_structure_empty_addr() {
        let kp = Keypair::generate();
        let record = kp.create_endpoint_record(vec!["".to_string()]);
        
        assert!(!record.validate_structure());
    }

    #[test]
    fn test_endpoint_record_validate_structure_addr_too_long() {
        let kp = Keypair::generate();
        let long_addr = "x".repeat(300);
        let record = kp.create_endpoint_record(vec![long_addr]);
        
        assert!(!record.validate_structure());
    }

    #[test]
    fn test_endpoint_record_validate_structure_bad_signature_length() {
        let kp = Keypair::generate();
        let mut record = kp.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);
        
        // Corrupt signature length
        record.signature = vec![0u8; 32]; // Wrong size (should be 64)
        
        assert!(!record.validate_structure());
    }

    #[test]
    fn test_signature_not_malleable_address_concatenation() {
        // Prove that ["192.168.1.1", ":8080"] and ["192.168.1.1:", "8080"] 
        // produce different signatures due to length prefixes
        let kp = Keypair::generate();
        
        let record1 = kp.create_endpoint_record(vec![
            "192.168.1.1".to_string(),
            ":8080".to_string(),
        ]);
        
        let record2 = kp.create_endpoint_record(vec![
            "192.168.1.1:".to_string(),
            "8080".to_string(),
        ]);
        
        // Both should verify (they're validly signed)
        assert!(record1.verify());
        assert!(record2.verify());
        
        // But signatures must be different
        assert_ne!(record1.signature, record2.signature, 
            "Signatures should differ due to length prefixes preventing malleability");
    }

    // ========================================================================
    // Formal Verification Tests - Zero-Hash Model
    // ========================================================================
    
    /// P1: Identity = PublicKey (exact byte equality, zero transformation)
    #[test]
    fn test_p1_identity_equals_public_key() {
        for _ in 0..100 {
            let kp = Keypair::generate();
            let public_key = kp.public_key_bytes();
            let identity = kp.identity();
            
            // P1: Identity bytes must equal public key bytes exactly (ZERO transformation)
            assert_eq!(
                *identity.as_bytes(),
                public_key,
                "P1 violation: Identity must equal PublicKey exactly"
            );
            
            // Roundtrip: Identity -> bytes -> Identity
            let recovered = Identity::from_bytes(*identity.as_bytes());
            assert_eq!(
                recovered, identity,
                "P1 violation: Identity roundtrip must be lossless"
            );
        }
    }
    
    /// P2: XOR distance operates directly on Identity bytes
    #[test]
    fn test_p2_xor_distance_on_raw_bytes() {
        for _ in 0..100 {
            let a = Keypair::generate().identity();
            let b = Keypair::generate().identity();
            
            // Compute XOR manually on raw bytes
            let mut expected = [0u8; 32];
            for i in 0..32 {
                expected[i] = a.as_bytes()[i] ^ b.as_bytes()[i];
            }
            
            // P2: xor_distance must match manual XOR on raw bytes
            assert_eq!(
                a.xor_distance(&b),
                expected,
                "P2 violation: XOR distance must operate on raw Identity bytes"
            );
        }
    }
    
    /// P2: XOR distance properties
    #[test]
    fn test_p2_xor_distance_properties() {
        let a = Keypair::generate().identity();
        let b = Keypair::generate().identity();
        
        // Symmetric: d(a,b) == d(b,a)
        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));
        
        // Identity: d(a,a) == 0
        assert_eq!(a.xor_distance(&a), [0u8; 32]);
    }
    
    /// P4: Sybil protection - verify_identity rejects mismatched pairs
    #[test]
    fn test_p4_sybil_protection() {
        for _ in 0..100 {
            let kp1 = Keypair::generate();
            let kp2 = Keypair::generate();
            
            let identity_1 = kp1.identity();
            let public_key_1 = kp1.public_key_bytes();
            let public_key_2 = kp2.public_key_bytes();
            
            // P4: Correct binding verifies
            assert!(
                verify_identity(&identity_1, &public_key_1),
                "P4 violation: valid Identity-PublicKey binding rejected"
            );
            
            // P4: Attacker cannot claim victim's Identity with their own key
            assert!(
                !verify_identity(&identity_1, &public_key_2),
                "P4 violation: Sybil attack - wrong public key accepted for Identity"
            );
        }
    }
    
    /// Constant-time comparison test
    #[test]
    fn test_constant_time_eq() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        let c = [1u8; 32];
        let mut d = [0u8; 32];
        d[31] = 1; // Differ only in last byte
        
        assert!(constant_time_eq(&a, &b), "Equal arrays should compare equal");
        assert!(!constant_time_eq(&a, &c), "Different arrays should not compare equal");
        assert!(!constant_time_eq(&a, &d), "Arrays differing in last byte should not compare equal");
    }
    
    /// Hex roundtrip invariant
    #[test]
    fn test_identity_hex_roundtrip_formal() {
        for _ in 0..100 {
            let kp = Keypair::generate();
            let identity = kp.identity();
            
            // Roundtrip: Identity -> hex -> Identity
            let hex = identity.to_hex();
            let recovered = Identity::from_hex(&hex).expect("hex decode failed");
            
            assert_eq!(
                identity, recovered,
                "Hex roundtrip invariant violated: from_hex(to_hex(id)) != id"
            );
            
            // Verify hex is lowercase and correct length
            assert_eq!(hex.len(), 64, "Hex encoding should be 64 characters");
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "Hex should be valid hex");
        }
    }
    
    /// P5: EndpointRecord signature binds all fields
    #[test]
    fn test_p5_endpoint_record_binding() {
        let kp = Keypair::generate();
        let addrs = vec!["192.168.1.1:8080".to_string()];
        let record = kp.create_endpoint_record(addrs);
        
        // P5: Valid signature verifies
        assert!(record.verify(), "P5 violation: valid record rejected");
        
        // P5: Modifying identity breaks signature
        let mut tampered = record.clone();
        let mut tampered_bytes = *tampered.identity.as_bytes();
        tampered_bytes[0] ^= 1;
        tampered.identity = Identity::from_bytes(tampered_bytes);
        assert!(!tampered.verify(), "P5 violation: identity tampering not detected");
        
        // P5: Modifying addresses breaks signature
        let mut tampered = record.clone();
        tampered.addrs[0] = "10.0.0.1:9999".to_string();
        assert!(!tampered.verify(), "P5 violation: address tampering not detected");
        
        // P5: Modifying timestamp breaks signature
        let mut tampered = record.clone();
        tampered.timestamp += 1;
        assert!(!tampered.verify(), "P5 violation: timestamp tampering not detected");
        
        // P5: Modifying signature invalidates
        let mut tampered = record.clone();
        tampered.signature[0] ^= 1;
        assert!(!tampered.verify(), "P5 violation: signature tampering not detected");
    }

    // ========================================================================
    // Identity Security Tests (from tests/security.rs)
    // ========================================================================

    /// Test that different keypairs produce different Identities (collision resistance).
    #[test]
    fn keypair_collision_resistance() {
        use std::collections::HashSet;
        let mut identities = HashSet::new();

        for _ in 0..1000 {
            let keypair = Keypair::generate();
            let identity = keypair.identity();
            assert!(
                identities.insert(identity),
                "Identity collision detected - this should be astronomically unlikely"
            );
        }
    }

    /// Test that Identity is deterministically derived from public key.
    #[test]
    fn identity_deterministic_derivation() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key_bytes();

        let identity_1 = keypair.identity();
        let identity_2 = keypair.identity();

        // In zero-hash model, Identity bytes ARE the public key
        assert_eq!(identity_1, identity_2);
        assert_eq!(identity_1.as_bytes(), &public_key);
    }

    /// Test that keypair reconstruction from secret key preserves identity.
    #[test]
    fn keypair_reconstruction_preserves_identity() {
        let original = Keypair::generate();
        let secret = original.secret_key_bytes();

        let reconstructed = Keypair::from_secret_key_bytes(&secret);

        assert_eq!(original.public_key_bytes(), reconstructed.public_key_bytes());
        assert_eq!(original.identity(), reconstructed.identity());

        // Both should produce identical signatures
        let message = b"test message";
        let sig1 = original.sign(message);
        let sig2 = reconstructed.sign(message);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    /// Test that verify_identity correctly validates Identity-public key binding.
    #[test]
    fn identity_verification_security() {
        let keypair = Keypair::generate();
        let identity = keypair.identity();
        let public_key = keypair.public_key_bytes();

        assert!(verify_identity(&identity, &public_key));

        let other_keypair = Keypair::generate();
        assert!(!verify_identity(&identity, &other_keypair.public_key_bytes()));

        let mut bad_bytes = *identity.as_bytes();
        bad_bytes[0] ^= 0xFF;
        let bad_identity = Identity::from_bytes(bad_bytes);
        assert!(!verify_identity(&bad_identity, &public_key));
    }

    /// Test that signatures cannot be forged.
    #[test]
    fn signature_unforgeability() {
        let keypair = Keypair::generate();
        let message = b"important message";
        let signature = keypair.sign(message);

        assert!(keypair.verify(message, &signature));

        let modified_message = b"modified message";
        assert!(!keypair.verify(modified_message, &signature));

        let other_keypair = Keypair::generate();
        assert!(!other_keypair.verify(message, &signature));
    }

    /// Test Identity hex decoding rejects invalid input.
    #[test]
    fn identity_hex_rejects_invalid() {
        assert!(Identity::from_hex("abcd").is_err());
        let long_hex = "a".repeat(70);
        assert!(Identity::from_hex(&long_hex).is_err());
        assert!(Identity::from_hex(&"g".repeat(64)).is_err());
    }

    // ========================================================================
    // Endpoint Record Security Tests (from tests/security.rs)
    // ========================================================================

    /// Test that valid endpoint records verify successfully.
    #[test]
    fn valid_record_verifies() {
        let keypair = Keypair::generate();
        let addrs = vec!["192.168.1.1:8080".to_string()];

        let record = keypair.create_endpoint_record(addrs);

        assert!(record.verify());
        assert!(record.verify_fresh(3600)); // 1 hour max age
    }

    /// Test that records with relay information verify correctly.
    #[test]
    fn record_with_relays_verifies() {
        let keypair = Keypair::generate();
        let relay_keypair = Keypair::generate();

        let relays = vec![RelayEndpoint {
            relay_identity: relay_keypair.identity(),
            relay_addrs: vec!["10.0.0.1:9000".to_string()],
        }];

        let record =
            keypair.create_endpoint_record_with_relays(vec!["192.168.1.1:8080".to_string()], relays);

        assert!(record.verify());
        assert!(record.has_relays());
        assert!(record.has_direct_addrs());
    }

    /// Test that tampered addresses cause verification failure.
    #[test]
    fn tampered_addresses_fail_verification() {
        let keypair = Keypair::generate();
        let mut record = keypair.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);

        record.addrs = vec!["attacker.com:8080".to_string()];

        assert!(!record.verify());
    }

    /// Test that records signed by wrong key fail verification.
    #[test]
    fn wrong_signer_fails_verification() {
        let keypair = Keypair::generate();
        let attacker_keypair = Keypair::generate();

        let mut record = keypair.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);

        let attacker_record =
            attacker_keypair.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);
        record.signature = attacker_record.signature;

        assert!(!record.verify());
    }

    /// Test replay attack prevention - old records should be rejected.
    #[test]
    fn replay_attack_prevention() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let keypair = Keypair::generate();
        let identity = keypair.identity();
        let addrs = vec!["192.168.1.1:8080".to_string()];

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let old_timestamp = now_ms - (2 * 60 * 60 * 1000); // 2 hours ago

        let mut data = Vec::new();
        data.extend_from_slice(identity.as_bytes());
        data.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
        for addr in &addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        data.extend_from_slice(&(0u32).to_le_bytes()); // no relays
        data.extend_from_slice(&old_timestamp.to_le_bytes());

        let signature = keypair.sign(&data);

        let old_record = EndpointRecord {
            identity,
            addrs,
            relays: vec![],
            timestamp: old_timestamp,
            signature: signature.to_bytes().to_vec(),
        };

        assert!(old_record.verify()); // Signature is valid
        assert!(!old_record.verify_fresh(3600)); // But too old (> 1 hour)
    }

    /// Test that future-dated records are rejected (clock skew attack).
    #[test]
    fn future_dated_records_rejected() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let keypair = Keypair::generate();
        let identity = keypair.identity();
        let addrs = vec!["192.168.1.1:8080".to_string()];

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let future_timestamp = now_ms + (2 * 60 * 60 * 1000); // 2 hours ahead

        let mut data = Vec::new();
        data.extend_from_slice(identity.as_bytes());
        data.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
        for addr in &addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        data.extend_from_slice(&(0u32).to_le_bytes());
        data.extend_from_slice(&future_timestamp.to_le_bytes());

        let signature = keypair.sign(&data);

        let future_record = EndpointRecord {
            identity,
            addrs,
            relays: vec![],
            timestamp: future_timestamp,
            signature: signature.to_bytes().to_vec(),
        };

        assert!(!future_record.verify_fresh(3600)); // Should fail freshness check
    }

    /// Test structure validation limits.
    #[test]
    fn structure_validation_limits() {
        let keypair = Keypair::generate();

        let too_many_addrs: Vec<String> = (0..20).map(|i| format!("10.0.0.{}:8080", i)).collect();
        let record = keypair.create_endpoint_record(too_many_addrs);
        assert!(!record.validate_structure());

        let long_addr = "a".repeat(300);
        let record = keypair.create_endpoint_record(vec![long_addr]);
        assert!(!record.validate_structure());

        let record = keypair.create_endpoint_record(vec!["".to_string()]);
        assert!(!record.validate_structure());
    }

    /// Test that signature length validation works.
    #[test]
    fn invalid_signature_length_rejected() {
        let keypair = Keypair::generate();
        let mut record = keypair.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);

        record.signature = record.signature[..32].to_vec();

        assert!(!record.validate_structure());
        assert!(!record.verify());
    }

    /// Test address concatenation attack prevention.
    #[test]
    fn address_concatenation_attack_prevented() {
        let keypair = Keypair::generate();

        let record1 = keypair.create_endpoint_record(vec![
            "192.168.1.1".to_string(),
            ":8080".to_string(),
        ]);

        let record2 = keypair.create_endpoint_record(vec!["192.168.1.1:8080".to_string()]);

        assert_ne!(record1.signature, record2.signature);

        assert!(record1.verify());
        assert!(record2.verify());
    }

    /// Test that Identity must match cryptographic public key (Sybil prevention).
    #[test]
    fn identity_must_match_public_key() {
        let keypair = Keypair::generate();
        let correct_identity = keypair.identity();
        let public_key = keypair.public_key_bytes();

        let attacker_claimed_id = Identity::from_bytes([0xFF; 32]);

        assert!(!verify_identity(&attacker_claimed_id, &public_key));
        assert!(verify_identity(&correct_identity, &public_key));
    }

    /// Test signature malleability resistance.
    #[test]
    fn signature_malleability_resistance() {
        let keypair = Keypair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        let sig_bytes = signature.to_bytes();

        let mut modified_sig = sig_bytes;
        modified_sig[0] ^= 0x01;

        let modified = ed25519_dalek::Signature::from_bytes(&modified_sig);

        assert_ne!(modified.to_bytes(), sig_bytes);
        assert!(!keypair.verify(message, &modified));
        assert!(keypair.verify(message, &signature));
    }

    /// Test cross-identity replay prevention.
    #[test]
    fn cross_identity_replay_prevention() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let message = b"important transaction";
        let alice_signature = alice.sign(message);

        assert!(!bob.verify(message, &alice_signature));
        assert!(alice.verify(message, &alice_signature));
    }

    /// Test that all-zeros and all-ones Identities don't match real keypairs.
    #[test]
    fn special_identity_edge_cases() {
        let all_zeros = Identity::from_bytes([0u8; 32]);
        let all_ones = Identity::from_bytes([0xFF; 32]);

        let keypair = Keypair::generate();

        assert!(
            !verify_identity(&all_zeros, &keypair.public_key_bytes()),
            "All-zeros Identity should not verify against any real keypair"
        );
        assert!(
            !verify_identity(&all_ones, &keypair.public_key_bytes()),
            "All-ones Identity should not verify against any real keypair"
        );
    }
}
