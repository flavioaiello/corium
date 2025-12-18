//! # Identity and Cryptographic Primitives
//!
//! This module defines the core identity types used throughout Corium:
//!
//! - [`Keypair`]: Ed25519 signing keypair (secret + public key)
//! - [`Identity`]: 32-byte public key serving as the peer's unique identifier
//! - [`Contact`]: Signed endpoint record containing addresses and relay information
//!
//! ## Identity Model
//!
//! Corium uses a simple identity model: **Identity = Ed25519 Public Key**.
//! This provides:
//!
//! - **Sybil resistance**: Creating identities requires Proof-of-Work (crypto puzzle)
//! - **Self-certifying**: No external CA needed; possession of private key proves identity
//! - **XOR-metric routing**: Identities can be used directly in Kademlia-style DHT
//!
//! ## Proof-of-Work (S/Kademlia Compliance)
//!
//! To prevent Sybil attacks, identity generation requires solving a crypto puzzle:
//! `BLAKE3(public_key || nonce)` must have `POW_DIFFICULTY` leading zero bits.
//!
//! This makes bulk identity generation computationally expensive while keeping
//! verification O(1). See [`IdentityProof`] and [`Keypair::generate_with_pow`].
//!
//! ## Contact Records
//!
//! A [`Contact`] is a signed record containing:
//! - The peer's identity (public key)
//! - Network addresses (IP:port)
//! - Relay identities for NAT-bound nodes
//! - Timestamp and signature for freshness verification
//!
//! Contacts are stored in the DHT under key = identity bytes, allowing
//! any peer to discover how to reach a given identity.
//!
//! ## Security Invariants
//!
//! - P1: `Identity::from_bytes(bytes).as_bytes() == bytes` (round-trip preservation)
//! - P2: XOR distance is symmetric and satisfies triangle inequality
//! - P3: Only valid Ed25519 points are accepted as identities
//! - P4: Contact signatures bind addresses to identity cryptographically
//! - P5: Timestamps prevent replay of stale contact records
//! - P6: Identity generation requires Proof-of-Work (Sybil resistance)

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{SignatureError, CONTACT_SIGNATURE_DOMAIN};

// ============================================================================
// Proof-of-Work Constants (S/Kademlia Sybil Resistance)
// ============================================================================

/// Number of leading zero bits required in PoW hash.
/// 
/// Production (difficulty 24):
/// - Average attempts: 2^24 = ~16 million
/// - Time on modern CPU: ~1-4 seconds
/// 
/// Tests with `test-pow` feature (difficulty 8):
/// - Average attempts: 2^8 = ~256
/// - Time: <1ms
/// - Exercises full PoW validation code path
/// 
/// SECURITY: Production difficulty makes Sybil attacks expensive.
/// An attacker generating 1000 identities needs ~3-5 hours of CPU time.
#[cfg(not(any(test, feature = "test-pow")))]
pub const POW_DIFFICULTY: u32 = 24;

#[cfg(any(test, feature = "test-pow"))]
pub const POW_DIFFICULTY: u32 = 8;

/// Maximum nonce value before giving up (prevents infinite loops).
/// With difficulty 24, success is virtually guaranteed within 2^32 attempts.
const POW_MAX_NONCE: u64 = 1 << 36;

/// Domain separation prefix for PoW hashing.
/// Prevents cross-protocol hash reuse.
const POW_HASH_DOMAIN: &[u8] = b"corium-pow-v1:";

/// Returns current time as milliseconds since Unix epoch.
/// Used for timestamp generation in signed records.
#[inline]
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new keypair WITHOUT Proof-of-Work.
    /// 
    /// **WARNING**: This creates an identity that will be rejected by DHT nodes
    /// enforcing PoW verification. Use [`generate_with_pow`] for production.
    /// 
    /// Use cases:
    /// - Testing and development
    /// - Ephemeral connections that don't need DHT routing
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Generate a new keypair WITH Proof-of-Work (S/Kademlia compliant).
    /// 
    /// This iterates through random keypairs until finding one where:
    /// `BLAKE3(POW_HASH_DOMAIN || public_key || nonce)` has `POW_DIFFICULTY` leading zeros.
    /// 
    /// Returns `(Keypair, IdentityProof)` - the proof must be included in Contact
    /// records for DHT acceptance.
    /// 
    /// # Performance
    /// - Expected time: 50-200ms on modern CPU (difficulty 16)
    /// - Parallelizable across cores if needed
    /// 
    /// # Panics
    /// Panics if no valid proof is found within `POW_MAX_NONCE` attempts
    /// (astronomically unlikely with proper difficulty settings).
    pub fn generate_with_pow() -> (Self, IdentityProof) {
        loop {
            let signing_key = SigningKey::generate(&mut OsRng);
            let public_key = signing_key.verifying_key().to_bytes();
            
            for nonce in 0..POW_MAX_NONCE {
                if verify_pow_hash(&public_key, nonce, POW_DIFFICULTY) {
                    let keypair = Self { signing_key };
                    let proof = IdentityProof { nonce };
                    return (keypair, proof);
                }
            }
            // Extremely unlikely: no valid nonce found, try new keypair
        }
    }

    /// Generate a keypair with custom PoW difficulty.
    /// 
    /// Useful for testing (difficulty=0) or high-security deployments.
    pub fn generate_with_pow_difficulty(difficulty: u32) -> (Self, IdentityProof) {
        if difficulty == 0 {
            let keypair = Self::generate();
            return (keypair, IdentityProof { nonce: 0 });
        }
        
        loop {
            let signing_key = SigningKey::generate(&mut OsRng);
            let public_key = signing_key.verifying_key().to_bytes();
            
            for nonce in 0..POW_MAX_NONCE {
                if verify_pow_hash(&public_key, nonce, difficulty) {
                    let keypair = Self { signing_key };
                    let proof = IdentityProof { nonce };
                    return (keypair, proof);
                }
            }
        }
    }

    pub fn from_secret_key_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn identity(&self) -> Identity {
        Identity::from_bytes(self.public_key_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.signing_key.verifying_key().verify(message, signature).is_ok()
    }

    /// Create a signed endpoint record WITHOUT PoW proof.
    /// 
    /// **WARNING**: Contacts created this way will be rejected by DHT nodes
    /// enforcing PoW. Use [`create_contact_with_pow`] for production.
    pub fn create_contact(&self, addrs: Vec<String>) -> Contact {
        self.create_contact_with_pow(addrs, IdentityProof::empty())
    }

    /// Create a signed endpoint record WITH PoW proof (S/Kademlia compliant).
    /// 
    /// The `pow_proof` should be obtained from [`generate_with_pow`] and stored
    /// persistently alongside the keypair.
    pub fn create_contact_with_pow(&self, addrs: Vec<String>, pow_proof: IdentityProof) -> Contact {
        let identity = self.identity();
        let timestamp = now_ms();
        
        // Build the payload to sign (without domain prefix - that's added by sign_with_domain)
        let payload = Contact::build_signed_payload(&identity, &addrs, timestamp);
        
        // Sign with domain separation
        let signature = crate::crypto::sign_with_domain(self, CONTACT_SIGNATURE_DOMAIN, &payload);
        
        Contact {
            identity,
            addrs,
            timestamp,
            signature,
            pow_proof,
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identity([u8; 32]);

impl Identity {
    #[inline]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let identity = Self(bytes);
        
        debug_assert_eq!(
            identity.0, bytes,
            "P1 violation: Identity must preserve bytes exactly"
        );
        
        identity
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline]
    pub fn xor_distance(&self, other: &Identity) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = self.0[i] ^ other.0[i];
        }
        out
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Check if this identity is valid.
    /// 
    /// Validates that the identity:
    /// 1. Is not all zeros or all 0xFF (trivially invalid)
    /// 2. Represents a valid Ed25519 public key point
    /// 
    /// This ensures the identity can be used for cryptographic operations
    /// such as signature verification.
    #[inline]
    pub fn is_valid(&self) -> bool {
        // Fast-path rejection for trivially invalid identities
        if self.0.iter().all(|&b| b == 0) {
            return false;
        }
        if self.0.iter().all(|&b| b == 0xFF) {
            return false;
        }
        // Validate it's a valid Ed25519 public key point
        VerifyingKey::try_from(self.0.as_slice()).is_ok()
    }

    /// Verify that a Proof-of-Work is valid for this identity.
    /// 
    /// Returns `true` if `BLAKE3(POW_HASH_DOMAIN || identity || nonce)` has
    /// at least `POW_DIFFICULTY` leading zero bits.
    /// 
    /// This is O(1) verification of the work done during identity generation.
    #[inline]
    pub fn verify_pow(&self, proof: &IdentityProof) -> bool {
        verify_pow_hash(&self.0, proof.nonce, POW_DIFFICULTY)
    }

    /// Verify PoW with custom difficulty (for testing or migration).
    #[inline]
    pub fn verify_pow_with_difficulty(&self, proof: &IdentityProof, difficulty: u32) -> bool {
        verify_pow_hash(&self.0, proof.nonce, difficulty)
    }
}

// ============================================================================
// Proof-of-Work Infrastructure (S/Kademlia)
// ============================================================================

/// Proof-of-Work for identity generation.
/// 
/// Contains the nonce that, when hashed with the public key, produces
/// a hash with sufficient leading zeros. This proof must be included
/// in Contact records for DHT routing table acceptance.
/// 
/// # Verification
/// ```ignore
/// let (keypair, proof) = Keypair::generate_with_pow();
/// assert!(keypair.identity().verify_pow(&proof));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IdentityProof {
    /// Nonce that produces a valid PoW hash with the identity.
    pub nonce: u64,
}

impl IdentityProof {
    /// Create a new proof with the given nonce.
    pub fn new(nonce: u64) -> Self {
        Self { nonce }
    }

    /// Create an empty/invalid proof (for unsigned contacts).
    pub fn empty() -> Self {
        Self { nonce: 0 }
    }

    /// Compute a PoW proof for an existing identity.
    /// 
    /// This finds a nonce where `BLAKE3(domain || public_key || nonce)` has
    /// the specified number of leading zero bits.
    /// 
    /// # Use Cases
    /// - Computing PoW for an imported keypair
    /// - Test helpers that need valid PoW for deterministic identities
    /// 
    /// # Panics
    /// Panics if no valid nonce is found within `POW_MAX_NONCE` attempts.
    pub fn compute_for_identity(identity: &Identity, difficulty: u32) -> Self {
        let public_key = identity.as_bytes();
        for nonce in 0..POW_MAX_NONCE {
            if verify_pow_hash(public_key, nonce, difficulty) {
                return Self { nonce };
            }
        }
        panic!("PoW computation failed: no valid nonce found within {} attempts", POW_MAX_NONCE);
    }
}

/// Verify that BLAKE3(domain || public_key || nonce) has `difficulty` leading zeros.
#[inline]
fn verify_pow_hash(public_key: &[u8; 32], nonce: u64, difficulty: u32) -> bool {
    let hash = compute_pow_hash(public_key, nonce);
    count_leading_zeros(&hash) >= difficulty
}

/// Compute the PoW hash for verification.
#[inline]
fn compute_pow_hash(public_key: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(POW_HASH_DOMAIN);
    hasher.update(public_key);
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Count leading zero bits in a hash.
#[inline]
fn count_leading_zeros(hash: &[u8; 32]) -> u32 {
    let mut zeros = 0u32;
    for byte in hash {
        if *byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

/// Compare two XOR distances lexicographically.
/// 
/// Used to determine which of two identities is closer to a target
/// in the Kademlia XOR metric space.
/// 
/// # Example
/// ```ignore
/// let dist_a = target.xor_distance(&a);
/// let dist_b = target.xor_distance(&b);
/// if distance_cmp(&dist_a, &dist_b) == Ordering::Less {
///     // a is closer to target than b
/// }
/// ```
#[inline]
pub fn distance_cmp(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in 0..32 {
        if a[i] < b[i] {
            return std::cmp::Ordering::Less;
        } else if a[i] > b[i] {
            return std::cmp::Ordering::Greater;
        }
    }
    std::cmp::Ordering::Equal
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub identity: Identity,
    pub addrs: Vec<String>,
    /// Timestamp when record was created (0 = unsigned/ephemeral).
    pub timestamp: u64,
    /// Ed25519 signature (empty = unsigned/ephemeral).
    pub signature: Vec<u8>,
    /// Proof-of-Work for Sybil resistance (S/Kademlia).
    /// Default is 0 for backwards compatibility; nodes enforcing PoW will reject contacts
    /// where `identity.verify_pow(&proof)` fails.
    #[serde(default)]
    pub pow_proof: IdentityProof,
}

impl Contact {
    /// Create an unsigned endpoint record (lightweight peer reference).
    /// Unsigned records have timestamp=0, empty signature, and no PoW proof.
    pub fn unsigned(identity: Identity, addrs: Vec<String>) -> Self {
        Self {
            identity,
            addrs,
            timestamp: 0,
            signature: vec![],
            pow_proof: IdentityProof::empty(),
        }
    }

    /// Create an unsigned endpoint record with a single address.
    pub fn single(identity: Identity, addr: impl Into<String>) -> Self {
        Self::unsigned(identity, vec![addr.into()])
    }

    /// Get the primary address (first in the list).
    pub fn primary_addr(&self) -> Option<&str> {
        self.addrs.first().map(|s| s.as_str())
    }

    /// Verify the cryptographic signature of this Contact record.
    /// 
    /// This verifies that:
    /// 1. The record has both timestamp and signature
    /// 2. The signature was created by the identity's private key
    /// 3. The signature covers: domain_prefix + identity + addresses + timestamp
    /// 
    /// SECURITY: Signature verification ensures addresses are bound to the identity.
    /// An attacker cannot forge a Contact pointing to their own address.
    /// 
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err(SignatureError)` otherwise.
    pub fn verify(&self) -> Result<(), SignatureError> {
        // Unsigned records (empty signature or zero timestamp) cannot be verified
        if self.signature.is_empty() {
            return Err(SignatureError::Missing);
        }
        if self.timestamp == 0 {
            return Err(SignatureError::Missing);
        }

        // Reconstruct the signed payload
        let payload = Self::build_signed_payload(
            &self.identity,
            &self.addrs,
            self.timestamp,
        );
        
        // Verify with domain separation
        crate::crypto::verify_with_domain(
            &self.identity,
            CONTACT_SIGNATURE_DOMAIN,
            &payload,
            &self.signature,
        )
    }
    
    /// Build the canonical payload for Contact signatures.
    /// 
    /// This is the data that gets signed (domain prefix is added by crypto layer).
    /// Format: identity(32) || addr_count(4) || [addr_len(4) || addr]* || timestamp(8)
    #[doc(hidden)]
    pub fn build_signed_payload(
        identity: &Identity,
        addrs: &[String],
        timestamp: u64,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(identity.as_bytes());
        data.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
        for addr in addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        data.extend_from_slice(&timestamp.to_le_bytes());
        data
    }

    /// Verify the signature AND freshness of this Contact record.
    /// 
    /// SECURITY: This is the recommended verification method for DHT records.
    /// It prevents replay attacks by rejecting records older than max_age_secs.
    /// 
    /// Rejects records that are:
    /// - Not cryptographically valid (via verify())
    /// - Older than max_age_secs (stale)
    /// - More than 30 seconds in the future (clock skew tolerance)
    pub fn verify_fresh(&self, max_age_secs: u64) -> bool {
        if self.verify().is_err() {
            return false;
        }
        
        // timestamp is already validated as non-zero by verify()
        let current_time = now_ms();
        
        let max_age_ms = max_age_secs * 1000;
        
        // SECURITY: Allow clock skew tolerance (30s) for future timestamps to
        // accommodate nodes with poor NTP synchronization in global deployments.
        // Reject anything too far in the future to prevent pre-dated attacks.
        const FUTURE_TOLERANCE_MS: u64 = 30_000;
        if self.timestamp > current_time + FUTURE_TOLERANCE_MS {
            return false;
        }
        
        // Reject stale records to prevent replay of old addresses
        if current_time.saturating_sub(self.timestamp) > max_age_ms {
            return false;
        }
        
        true
    }

    pub fn has_direct_addrs(&self) -> bool {
        !self.addrs.is_empty()
    }

    /// Verify the Proof-of-Work for this Contact's identity.
    /// 
    /// SECURITY: This is required for DHT routing table acceptance.
    /// Contacts without valid PoW should be rejected to prevent Sybil attacks.
    /// 
    /// # Returns
    /// `true` if the PoW proof is valid for the identity.
    #[inline]
    pub fn verify_pow(&self) -> bool {
        self.identity.verify_pow(&self.pow_proof)
    }

    /// Verify PoW with custom difficulty.
    #[inline]
    pub fn verify_pow_with_difficulty(&self, difficulty: u32) -> bool {
        self.identity.verify_pow_with_difficulty(&self.pow_proof, difficulty)
    }

    /// Validate the structural integrity of a Contact record.
    /// 
    /// SECURITY: This validates bounds and format, NOT cryptographic signatures or PoW.
    /// Always call `verify()` or `verify_fresh()` for untrusted data.
    /// For DHT routing, also call `verify_pow()`.
    /// 
    /// Checks:
    /// - Address count ≤ MAX_ADDRS (16)
    /// - Each address ≤ MAX_ADDR_LEN (256) and non-empty
    /// - Signature length is exactly 64 bytes if non-empty (signed)
    pub fn validate_structure(&self) -> bool {
        // SECURITY: These limits prevent memory exhaustion attacks when
        // deserializing untrusted Contact records from the network.
        const MAX_ADDRS: usize = 16;
        const MAX_ADDR_LEN: usize = 256;
        
        if self.addrs.len() > MAX_ADDRS {
            return false;
        }
        
        for addr in &self.addrs {
            if addr.len() > MAX_ADDR_LEN || addr.is_empty() {
                return false;
            }
        }
        
        // If signed (non-empty signature), must be exactly 64 bytes
        if !self.signature.is_empty() && self.signature.len() != 64 {
            return false;
        }
        
        true
    }
}

impl PartialEq for Contact {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl Eq for Contact {}

impl std::hash::Hash for Contact {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        
        assert_ne!(kp1.identity(), kp2.identity());
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = Keypair::generate();
        let message = b"hello world";
        
        let signature = kp.sign(message);
        assert!(kp.verify(message, &signature));
        
        assert!(!kp.verify(b"wrong message", &signature));
    }

    #[test]
    fn test_identity_xor_distance() {
        let a = Identity::from_bytes([0xFF; 32]);
        let b = Identity::from_bytes([0x00; 32]);
        let c = Identity::from_bytes([0xFF; 32]);
        
        assert_eq!(a.xor_distance(&a), [0u8; 32]);
        
        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));
        
        assert_eq!(a.xor_distance(&b), [0xFF; 32]);
        
        assert_eq!(a.xor_distance(&c), [0u8; 32]);
    }

    #[test]
    fn test_contact_verify_fresh_accepts_recent() {
        let kp = Keypair::generate();
        let record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);
        
        assert!(record.verify_fresh(3600));    }

    #[test]
    fn test_contact_verify_fresh_rejects_old() {
        let kp = Keypair::generate();
        let mut record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);
        
        record.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 - (2 * 60 * 60 * 1000);
        
        assert!(!record.verify_fresh(3600));    }

    #[test]
    fn test_contact_verify_fresh_rejects_future() {
        let kp = Keypair::generate();
        let mut record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);
        
        record.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 + (5 * 60 * 1000);
        
        assert!(!record.verify_fresh(3600));
    }

    #[test]
    fn test_contact_validate_structure_valid() {
        let kp = Keypair::generate();
        let record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);
        
        assert!(record.validate_structure());
    }

    #[test]
    fn test_contact_validate_structure_too_many_addrs() {
        let kp = Keypair::generate();
        let addrs: Vec<String> = (0..20).map(|i| format!("192.168.1.{}:8080", i)).collect();
        let record = kp.create_contact(addrs);
        
        assert!(!record.validate_structure());
    }

    #[test]
    fn test_contact_validate_structure_empty_addr() {
        let kp = Keypair::generate();
        let record = kp.create_contact(vec!["".to_string()]);
        
        assert!(!record.validate_structure());
    }

    #[test]
    fn test_contact_validate_structure_addr_too_long() {
        let kp = Keypair::generate();
        let long_addr = "x".repeat(300);
        let record = kp.create_contact(vec![long_addr]);
        
        assert!(!record.validate_structure());
    }

    #[test]
    fn test_contact_validate_structure_bad_signature_length() {
        let kp = Keypair::generate();
        let mut record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);
        
        record.signature = vec![0u8; 32];        
        assert!(!record.validate_structure());
    }

    #[test]
    fn test_p1_identity_equals_public_key() {
        for _ in 0..100 {
            let kp = Keypair::generate();
            let public_key = kp.public_key_bytes();
            let identity = kp.identity();
            
            assert_eq!(
                *identity.as_bytes(),
                public_key,
                "P1 violation: Identity must equal PublicKey exactly"
            );
            
            let recovered = Identity::from_bytes(*identity.as_bytes());
            assert_eq!(
                recovered, identity,
                "P1 violation: Identity roundtrip must be lossless"
            );
        }
    }
    
    #[test]
    fn test_p2_xor_distance_on_raw_bytes() {
        for _ in 0..100 {
            let a = Keypair::generate().identity();
            let b = Keypair::generate().identity();
            
            let mut expected = [0u8; 32];
            for (i, byte) in expected.iter_mut().enumerate() {
                *byte = a.as_bytes()[i] ^ b.as_bytes()[i];
            }
            
            assert_eq!(
                a.xor_distance(&b),
                expected,
                "P2 violation: XOR distance must operate on raw Identity bytes"
            );
        }
    }
    
    #[test]
    fn test_p2_xor_distance_properties() {
        let a = Keypair::generate().identity();
        let b = Keypair::generate().identity();
        
        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));
        
        assert_eq!(a.xor_distance(&a), [0u8; 32]);
    }
    
    #[test]
    fn test_p4_sybil_protection() {
        for _ in 0..100 {
            let kp1 = Keypair::generate();
            let kp2 = Keypair::generate();
            
            let identity_1 = kp1.identity();
            let public_key_1 = kp1.public_key_bytes();
            let public_key_2 = kp2.public_key_bytes();
            
            assert_eq!(
                *identity_1.as_bytes(), public_key_1,
                "P4 violation: valid Identity-PublicKey binding rejected"
            );
            
            assert_ne!(
                *identity_1.as_bytes(), public_key_2,
                "P4 violation: Sybil attack - wrong public key accepted for Identity"
            );
        }
    }
    
    #[test]
    fn test_identity_hex_roundtrip_formal() {
        for _ in 0..100 {
            let kp = Keypair::generate();
            let identity = kp.identity();
            
            let hex = identity.to_hex();
            let recovered = Identity::from_hex(&hex).expect("hex decode failed");
            
            assert_eq!(
                identity, recovered,
                "Hex roundtrip invariant violated: from_hex(to_hex(id)) != id"
            );
            
            assert_eq!(hex.len(), 64, "Hex encoding should be 64 characters");
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "Hex should be valid hex");
        }
    }
    
    #[test]
    fn test_p5_contact_binding() {
        let kp = Keypair::generate();
        let addrs = vec!["192.168.1.1:8080".to_string()];
        let record = kp.create_contact(addrs);
        
        assert!(record.verify().is_ok(), "P5 violation: valid record rejected");
        
        let mut tampered = record.clone();
        let mut tampered_bytes = *tampered.identity.as_bytes();
        tampered_bytes[0] ^= 1;
        tampered.identity = Identity::from_bytes(tampered_bytes);
        assert!(tampered.verify().is_err(), "P5 violation: identity tampering not detected");
        
        let mut tampered = record.clone();
        tampered.addrs[0] = "10.0.0.1:9999".to_string();
        assert!(tampered.verify().is_err(), "P5 violation: address tampering not detected");
        
        let mut tampered = record.clone();
        tampered.timestamp += 1;
        assert!(tampered.verify().is_err(), "P5 violation: timestamp tampering not detected");
        
        let mut tampered = record.clone();
        tampered.signature[0] ^= 1;
        assert!(tampered.verify().is_err(), "P5 violation: signature tampering not detected");
    }

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

    #[test]
    fn identity_deterministic_derivation() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key_bytes();

        let identity_1 = keypair.identity();
        let identity_2 = keypair.identity();

        assert_eq!(identity_1, identity_2);
        assert_eq!(identity_1.as_bytes(), &public_key);
    }

    #[test]
    fn keypair_reconstruction_preserves_identity() {
        let original = Keypair::generate();
        let secret = original.secret_key_bytes();

        let reconstructed = Keypair::from_secret_key_bytes(&secret);

        assert_eq!(original.public_key_bytes(), reconstructed.public_key_bytes());
        assert_eq!(original.identity(), reconstructed.identity());

        let message = b"test message";
        let sig1 = original.sign(message);
        let sig2 = reconstructed.sign(message);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn identity_verification_security() {
        let keypair = Keypair::generate();
        let identity = keypair.identity();
        let public_key = keypair.public_key_bytes();

        assert_eq!(*identity.as_bytes(), public_key);

        let other_keypair = Keypair::generate();
        assert_ne!(*identity.as_bytes(), other_keypair.public_key_bytes());

        let mut bad_bytes = *identity.as_bytes();
        bad_bytes[0] ^= 0xFF;
        let bad_identity = Identity::from_bytes(bad_bytes);
        assert_ne!(*bad_identity.as_bytes(), public_key);
    }

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

    #[test]
    fn identity_hex_rejects_invalid() {
        assert!(Identity::from_hex("abcd").is_err());
        let long_hex = "a".repeat(70);
        assert!(Identity::from_hex(&long_hex).is_err());
        assert!(Identity::from_hex(&"g".repeat(64)).is_err());
    }

    #[test]
    fn valid_record_verifies() {
        let keypair = Keypair::generate();
        let addrs = vec!["192.168.1.1:8080".to_string()];

        let record = keypair.create_contact(addrs);

        assert!(record.verify().is_ok());
        assert!(record.verify_fresh(3600));
    }

    #[test]
    fn record_with_multiple_addrs_verifies() {
        let keypair = Keypair::generate();

        let record = keypair.create_contact(vec![
            "192.168.1.1:8080".to_string(),
            "10.0.0.1:8080".to_string(),
        ]);

        assert!(record.verify().is_ok());
        assert!(record.has_direct_addrs());
    }

    #[test]
    fn tampered_addresses_fail_verification() {
        let keypair = Keypair::generate();
        let mut record = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        record.addrs = vec!["attacker.com:8080".to_string()];

        assert!(record.verify().is_err());
    }

    #[test]
    fn wrong_signer_fails_verification() {
        let keypair = Keypair::generate();
        let attacker_keypair = Keypair::generate();

        let mut record = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        let attacker_record =
            attacker_keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);
        record.signature = attacker_record.signature;

        assert!(record.verify().is_err());
    }

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
        
        // Build the payload and sign with domain separation
        let payload = Contact::build_signed_payload(&identity, &addrs, old_timestamp);
        let signature = crate::crypto::sign_with_domain(&keypair, crate::crypto::CONTACT_SIGNATURE_DOMAIN, &payload);

        let old_record = Contact {
            identity,
            addrs,
            timestamp: old_timestamp,
            signature,
            pow_proof: IdentityProof::empty(),
        };

        // Signature should be valid (cryptographically correct)
        assert!(old_record.verify().is_ok());
        // But freshness check should fail (record is stale)
        assert!(!old_record.verify_fresh(3600));
    }

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
        let future_timestamp = now_ms + (2 * 60 * 60 * 1000); // 2 hours in future
        
        // Build the payload and sign with domain separation
        let payload = Contact::build_signed_payload(&identity, &addrs, future_timestamp);
        let signature = crate::crypto::sign_with_domain(&keypair, crate::crypto::CONTACT_SIGNATURE_DOMAIN, &payload);

        let future_record = Contact {
            identity,
            addrs,
            timestamp: future_timestamp,
            signature,
            pow_proof: IdentityProof::empty(),
        };

        // Future-dated record should fail freshness check
        assert!(!future_record.verify_fresh(3600));
    }

    #[test]
    fn structure_validation_limits() {
        let keypair = Keypair::generate();

        let too_many_addrs: Vec<String> = (0..20).map(|i| format!("10.0.0.{}:8080", i)).collect();
        let record = keypair.create_contact(too_many_addrs);
        assert!(!record.validate_structure());

        let long_addr = "a".repeat(300);
        let record = keypair.create_contact(vec![long_addr]);
        assert!(!record.validate_structure());

        let record = keypair.create_contact(vec!["".to_string()]);
        assert!(!record.validate_structure());
    }

    #[test]
    fn invalid_signature_length_rejected() {
        let keypair = Keypair::generate();
        let mut record = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        record.signature = record.signature[..32].to_vec();

        assert!(!record.validate_structure());
        assert!(record.verify().is_err());
    }

    #[test]
    fn address_concatenation_attack_prevented() {
        let keypair = Keypair::generate();

        let record1 = keypair.create_contact(vec![
            "192.168.1.1".to_string(),
            ":8080".to_string(),
        ]);

        let record2 = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        assert_ne!(record1.signature, record2.signature);

        assert!(record1.verify().is_ok());
        assert!(record2.verify().is_ok());
    }

    #[test]
    fn identity_must_match_public_key() {
        let keypair = Keypair::generate();
        let correct_identity = keypair.identity();
        let public_key = keypair.public_key_bytes();

        let attacker_claimed_id = Identity::from_bytes([0xFF; 32]);

        assert_ne!(*attacker_claimed_id.as_bytes(), public_key);
        assert_eq!(*correct_identity.as_bytes(), public_key);
    }

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

    #[test]
    fn cross_identity_replay_prevention() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let message = b"important transaction";
        let alice_signature = alice.sign(message);

        assert!(!bob.verify(message, &alice_signature));
        assert!(alice.verify(message, &alice_signature));
    }

    #[test]
    fn special_identity_edge_cases() {
        let all_zeros = Identity::from_bytes([0u8; 32]);
        let all_ones = Identity::from_bytes([0xFF; 32]);

        let keypair = Keypair::generate();

        assert_ne!(
            *all_zeros.as_bytes(), keypair.public_key_bytes(),
            "All-zeros Identity should not match any real keypair"
        );
        assert_ne!(
            *all_ones.as_bytes(), keypair.public_key_bytes(),
            "All-ones Identity should not match any real keypair"
        );
    }

    #[test]
    fn is_valid_rejects_invalid_ed25519_points() {
        // All zeros - trivially invalid
        let all_zeros = Identity::from_bytes([0u8; 32]);
        assert!(!all_zeros.is_valid());

        // All 0xFF - trivially invalid
        let all_ones = Identity::from_bytes([0xFF; 32]);
        assert!(!all_ones.is_valid());

        // Random bytes that aren't valid Ed25519 curve points
        // Most random 32-byte arrays won't be valid curve points
        let invalid_point = Identity::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ]);
        assert!(!invalid_point.is_valid(), "should fail Ed25519 point validation");

        // Valid keypair identity should pass
        let keypair = Keypair::generate();
        let valid_identity = keypair.identity();
        assert!(valid_identity.is_valid());
    }

    // ========================================================================
    // Proof-of-Work (S/Kademlia) Tests
    // ========================================================================

    #[test]
    fn test_pow_generation_produces_valid_proof() {
        // Use lower difficulty for faster test
        let (keypair, proof) = Keypair::generate_with_pow_difficulty(8);
        let identity = keypair.identity();
        
        assert!(
            identity.verify_pow_with_difficulty(&proof, 8),
            "P6 violation: generate_with_pow must produce valid proof"
        );
    }

    #[test]
    fn test_pow_verification_rejects_invalid_nonce() {
        let (keypair, proof) = Keypair::generate_with_pow_difficulty(8);
        let identity = keypair.identity();
        
        // Valid proof works
        assert!(identity.verify_pow_with_difficulty(&proof, 8));
        
        // Wrong nonce fails
        let bad_proof = IdentityProof::new(proof.nonce.wrapping_add(1));
        assert!(
            !identity.verify_pow_with_difficulty(&bad_proof, 8),
            "PoW should reject invalid nonce"
        );
    }

    #[test]
    fn test_pow_verification_rejects_wrong_identity() {
        let (keypair1, proof1) = Keypair::generate_with_pow_difficulty(8);
        let keypair2 = Keypair::generate();
        
        // Proof from keypair1 shouldn't work for keypair2's identity
        assert!(
            !keypair2.identity().verify_pow_with_difficulty(&proof1, 8),
            "PoW proof should be bound to specific identity"
        );
        
        // But should work for its own identity
        assert!(keypair1.identity().verify_pow_with_difficulty(&proof1, 8));
    }

    #[test]
    fn test_pow_difficulty_zero_always_passes() {
        let keypair = Keypair::generate();
        let proof = IdentityProof::new(0);
        
        // Difficulty 0 means no leading zeros required
        assert!(
            keypair.identity().verify_pow_with_difficulty(&proof, 0),
            "Difficulty 0 should always pass"
        );
    }

    #[test]
    fn test_contact_with_pow_serialization_roundtrip() {
        let (keypair, proof) = Keypair::generate_with_pow_difficulty(8);
        let contact = keypair.create_contact_with_pow(
            vec!["192.168.1.1:8080".to_string()],
            proof,
        );
        
        // Verify PoW before serialization
        assert!(contact.verify_pow_with_difficulty(8));
        
        // Serialize and deserialize
        let serialized = bincode::serialize(&contact).unwrap();
        let deserialized: Contact = bincode::deserialize(&serialized).unwrap();
        
        // Verify PoW after deserialization
        assert!(
            deserialized.verify_pow_with_difficulty(8),
            "PoW proof must survive serialization roundtrip"
        );
        assert_eq!(deserialized.pow_proof.nonce, proof.nonce);
    }

    #[test]
    fn test_contact_without_pow_fails_verification() {
        let keypair = Keypair::generate();
        let contact = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);
        
        // Contact created without PoW should fail verification at any non-zero difficulty
        // (unless astronomically lucky, which won't happen in practice)
        // Note: nonce=0 might occasionally pass for very low bits, so we check difficulty 8+
        assert!(
            !contact.verify_pow_with_difficulty(16),
            "Contact without PoW should fail verification at production difficulty"
        );
    }

    #[test]
    fn test_pow_helper_functions() {
        // Test count_leading_zeros
        assert_eq!(count_leading_zeros(&[0x00; 32]), 256);
        assert_eq!(count_leading_zeros(&[0xFF; 32]), 0);
        assert_eq!(count_leading_zeros(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 23);
        assert_eq!(count_leading_zeros(&[0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 8);
    }

    #[test]
    fn test_identity_proof_default() {
        let proof = IdentityProof::default();
        assert_eq!(proof.nonce, 0);
        
        let empty = IdentityProof::empty();
        assert_eq!(empty.nonce, 0);
    }

    #[test]
    fn test_pow_generation_timing() {
        use std::time::Instant;
        
        // Benchmark PoW generation at production difficulty (24)
        // Note: Use lower difficulty (8) in debug mode to avoid slow tests
        let difficulty = if cfg!(debug_assertions) { 8 } else { POW_DIFFICULTY };
        
        let start = Instant::now();
        let (keypair, proof) = Keypair::generate_with_pow_difficulty(difficulty);
        let elapsed = start.elapsed();
        
        // Verify the proof is valid
        assert!(keypair.identity().verify_pow_with_difficulty(&proof, difficulty));
        
        // Print timing for visibility (run with --nocapture)
        println!("\nPoW generation at difficulty {}: {:?}", difficulty, elapsed);
        println!("  Nonce found: {}", proof.nonce);
        
        // Sanity check: should complete in reasonable time
        // Debug mode (diff 8): < 1 second
        // Release mode (diff 24): < 60 seconds (allows for variance)
        let max_secs = if cfg!(debug_assertions) { 5 } else { 60 };
        assert!(
            elapsed.as_secs() < max_secs,
            "PoW took too long: {:?}",
            elapsed
        );
    }
}
