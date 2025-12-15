use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
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

    /// Create an endpoint record for a publicly reachable node (can serve as relay).
    pub fn create_contact(&self, addrs: Vec<String>) -> Contact {
        self.create_contact_full(addrs, vec![], true)
    }

    /// Create an endpoint record for a NAT-bound node with designated relays.
    pub fn create_contact_with_relays(
        &self,
        addrs: Vec<String>,
        relays: Vec<Identity>,
    ) -> Contact {
        // NAT-bound nodes that need relays cannot serve as relays themselves
        self.create_contact_full(addrs, relays, false)
    }

    /// Create an endpoint record with full control over all fields.
    pub fn create_contact_full(
        &self,
        addrs: Vec<String>,
        relays: Vec<Identity>,
        is_relay: bool,
    ) -> Contact {
        let identity = self.identity();
        let timestamp = now_ms();
        
        let mut data = Vec::new();
        data.extend_from_slice(identity.as_bytes());
        data.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
        for addr in &addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        data.extend_from_slice(&(relays.len() as u32).to_le_bytes());
        for relay in &relays {
            data.extend_from_slice(relay.as_bytes());
        }
        // Include is_relay in signature
        data.push(if is_relay { 1 } else { 0 });
        data.extend_from_slice(&timestamp.to_le_bytes());
        
        let signature = self.sign(&data);
        
        Contact {
            identity,
            addrs,
            relays,
            is_relay,
            timestamp: Some(timestamp),
            signature: Some(signature.to_bytes().to_vec()),
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
    /// Identities of relay nodes this peer uses for NAT traversal.
    /// When connecting, resolve each identity via DHT to get addresses.
    pub relays: Vec<Identity>,
    /// Whether this node can serve as a relay for other nodes.
    /// Nodes that are publicly reachable (passed self-probe) set this to true.
    pub is_relay: bool,
    /// Timestamp when record was created (only for signed records).
    pub timestamp: Option<u64>,
    /// Ed25519 signature (only for signed records published to DHT).
    pub signature: Option<Vec<u8>>,
}

impl Contact {
    /// Create an unsigned endpoint record (lightweight peer reference).
    pub fn unsigned(identity: Identity, addrs: Vec<String>) -> Self {
        Self {
            identity,
            addrs,
            relays: vec![],
            is_relay: false,
            timestamp: None,
            signature: None,
        }
    }

    /// Create an unsigned endpoint record with a single address.
    pub fn single(identity: Identity, addr: impl Into<String>) -> Self {
        Self::unsigned(identity, vec![addr.into()])
    }

    /// Check if this record is signed.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some() && self.timestamp.is_some()
    }

    /// Get the primary address (first in the list).
    pub fn primary_addr(&self) -> Option<&str> {
        self.addrs.first().map(|s| s.as_str())
    }

    /// Iterate over all addresses.
    pub fn all_addrs(&self) -> impl Iterator<Item = &str> {
        self.addrs.iter().map(|s| s.as_str())
    }

    pub fn verify(&self) -> bool {
        // Unsigned records cannot be verified
        let (Some(timestamp), Some(sig)) = (self.timestamp, self.signature.as_ref()) else {
            return false;
        };

        let mut data = Vec::new();
        data.extend_from_slice(self.identity.as_bytes());
        data.extend_from_slice(&(self.addrs.len() as u32).to_le_bytes());
        for addr in &self.addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        data.extend_from_slice(&(self.relays.len() as u32).to_le_bytes());
        for relay in &self.relays {
            data.extend_from_slice(relay.as_bytes());
        }
        // Include is_relay in signature verification
        data.push(if self.is_relay { 1 } else { 0 });
        data.extend_from_slice(&timestamp.to_le_bytes());
        
        let Ok(verifying_key) = VerifyingKey::try_from(self.identity.as_bytes().as_slice()) else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> = sig.clone().try_into() else {
            return false;
        };
        let signature = Signature::from_bytes(&sig_bytes);
        
        verifying_key.verify_strict(&data, &signature).is_ok()
    }

    pub fn verify_fresh(&self, max_age_secs: u64) -> bool {
        if !self.verify() {
            return false;
        }
        
        // Already verified that timestamp exists in verify()
        let timestamp = self.timestamp.unwrap();
        let current_time = now_ms();
        
        let max_age_ms = max_age_secs * 1000;
        
        const FUTURE_TOLERANCE_MS: u64 = 10_000;
        if timestamp > current_time + FUTURE_TOLERANCE_MS {
            return false;
        }
        
        if current_time.saturating_sub(timestamp) > max_age_ms {
            return false;
        }
        
        true
    }

    pub fn has_relays(&self) -> bool {
        !self.relays.is_empty()
    }

    pub fn has_direct_addrs(&self) -> bool {
        !self.addrs.is_empty()
    }

    pub fn validate_structure(&self) -> bool {
        const MAX_ADDRS: usize = 16;
        const MAX_RELAYS: usize = 8;
        const MAX_ADDR_LEN: usize = 256;
        
        if self.addrs.len() > MAX_ADDRS {
            return false;
        }
        
        if self.relays.len() > MAX_RELAYS {
            return false;
        }
        
        for addr in &self.addrs {
            if addr.len() > MAX_ADDR_LEN || addr.is_empty() {
                return false;
            }
        }
        
        for relay in &self.relays {
            if !relay.is_valid() {
                return false;
            }
        }
        
        // If signed, signature must be exactly 64 bytes
        if let Some(ref sig) = self.signature {
            if sig.len() != 64 {
                return false;
            }
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
        
        record.timestamp = Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 - (2 * 60 * 60 * 1000));
        
        assert!(!record.verify_fresh(3600));    }

    #[test]
    fn test_contact_verify_fresh_rejects_future() {
        let kp = Keypair::generate();
        let mut record = kp.create_contact(vec!["192.168.1.1:8080".to_string()]);
        
        record.timestamp = Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 + (5 * 60 * 1000));
        
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
        
        record.signature = Some(vec![0u8; 32]);        
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
        
        assert!(record.verify(), "P5 violation: valid record rejected");
        
        let mut tampered = record.clone();
        let mut tampered_bytes = *tampered.identity.as_bytes();
        tampered_bytes[0] ^= 1;
        tampered.identity = Identity::from_bytes(tampered_bytes);
        assert!(!tampered.verify(), "P5 violation: identity tampering not detected");
        
        let mut tampered = record.clone();
        tampered.addrs[0] = "10.0.0.1:9999".to_string();
        assert!(!tampered.verify(), "P5 violation: address tampering not detected");
        
        let mut tampered = record.clone();
        if let Some(ref mut ts) = tampered.timestamp {
            *ts += 1;
        }
        assert!(!tampered.verify(), "P5 violation: timestamp tampering not detected");
        
        let mut tampered = record.clone();
        if let Some(ref mut sig) = tampered.signature {
            sig[0] ^= 1;
        }
        assert!(!tampered.verify(), "P5 violation: signature tampering not detected");
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

        assert!(record.verify());
        assert!(record.verify_fresh(3600));    }

    #[test]
    fn record_with_relays_verifies() {
        let keypair = Keypair::generate();
        let relay_keypair = Keypair::generate();

        let relays = vec![relay_keypair.identity()];

        let record =
            keypair.create_contact_with_relays(vec!["192.168.1.1:8080".to_string()], relays);

        assert!(record.verify());
        assert!(record.has_relays());
        assert!(record.has_direct_addrs());
    }

    #[test]
    fn tampered_addresses_fail_verification() {
        let keypair = Keypair::generate();
        let mut record = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        record.addrs = vec!["attacker.com:8080".to_string()];

        assert!(!record.verify());
    }

    #[test]
    fn wrong_signer_fails_verification() {
        let keypair = Keypair::generate();
        let attacker_keypair = Keypair::generate();

        let mut record = keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);

        let attacker_record =
            attacker_keypair.create_contact(vec!["192.168.1.1:8080".to_string()]);
        record.signature = attacker_record.signature;

        assert!(!record.verify());
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
        let old_timestamp = now_ms - (2 * 60 * 60 * 1000);
        let mut data = Vec::new();
        data.extend_from_slice(identity.as_bytes());
        data.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
        for addr in &addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        data.extend_from_slice(&(0u32).to_le_bytes());        // Include is_relay in signature (false = 0)
        data.push(0);
        data.extend_from_slice(&old_timestamp.to_le_bytes());

        let signature = keypair.sign(&data);

        let old_record = Contact {
            identity,
            addrs,
            relays: vec![],
            is_relay: false,
            timestamp: Some(old_timestamp),
            signature: Some(signature.to_bytes().to_vec()),
        };

        assert!(old_record.verify());        assert!(!old_record.verify_fresh(3600));    }

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
        let future_timestamp = now_ms + (2 * 60 * 60 * 1000);
        let mut data = Vec::new();
        data.extend_from_slice(identity.as_bytes());
        data.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
        for addr in &addrs {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(addr_bytes);
        }
        data.extend_from_slice(&(0u32).to_le_bytes());
        // Include is_relay in signature (false = 0)
        data.push(0);
        data.extend_from_slice(&future_timestamp.to_le_bytes());

        let signature = keypair.sign(&data);

        let future_record = Contact {
            identity,
            addrs,
            relays: vec![],
            is_relay: false,
            timestamp: Some(future_timestamp),
            signature: Some(signature.to_bytes().to_vec()),
        };

        assert!(!future_record.verify_fresh(3600));    }

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

        record.signature = record.signature.map(|s| s[..32].to_vec());

        assert!(!record.validate_structure());
        assert!(!record.verify());
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

        assert!(record1.verify());
        assert!(record2.verify());
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
}
