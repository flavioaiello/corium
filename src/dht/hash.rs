//! Hashing and distance functions for content-addressed storage.
//!
//! Provides BLAKE3-based hashing for content addressing and XOR distance
//! metrics for Kademlia-style routing.

use blake3::Hasher;
use crate::identity::{Identity, EndpointRecord};

/// A 256-bit content-addressed key for stored values.
///
/// Keys are computed as the BLAKE3 hash of the content, providing
/// content-addressable storage with built-in integrity verification.
pub type Key = [u8; 32];

/// Maximum age for EndpointRecords to prevent replay attacks (24 hours).
const ENDPOINT_RECORD_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Check if an Identity is valid (not a placeholder or obviously invalid).
///
/// # Security
///
/// Used to prevent routing table pollution from placeholder IDs.
/// Returns false for:
/// - All-zeros (placeholder for unknown peers)
/// - All-ones (reserved/invalid)
///
/// # Deprecated
///
/// Prefer using `Identity::is_valid()` directly.
#[inline]
pub fn is_valid_identity(id: &Identity) -> bool {
    id.is_valid()
}

/// Compute a 32-byte BLAKE3 digest of the input data.
pub(crate) fn blake3_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

/// Compute a content-addressed key as the BLAKE3 hash of content bytes.
///
/// This is the standard way to derive a DHT key for storing content:
///
/// ```
/// use corium::hash_content;
///
/// let content = b"hello world";
/// let key = hash_content(content);
/// // The same content always produces the same key
/// assert_eq!(key, hash_content(content));
/// ```
pub fn hash_content(data: &[u8]) -> Key {
    blake3_digest(data)
}

/// Compute XOR distance between two Identities for DHT routing.
///
/// # Zero-Hash Property
/// In the zero-hash architecture, XOR distance is computed directly
/// on Identity bytes (which ARE the public key bytes).
#[inline]
pub fn xor_distance(a: &Identity, b: &Identity) -> [u8; 32] {
    a.xor_distance(b)
}

/// Verify that a key matches the hash of a value.
///
/// Used to validate content integrity after retrieval:
///
/// ```
/// use corium::{hash_content, verify_key_value_pair};
///
/// let content = b"my data";
/// let key = hash_content(content);
/// assert!(verify_key_value_pair(&key, content));
/// assert!(!verify_key_value_pair(&key, b"wrong data"));
/// ```
///
/// # Security
///
/// For EndpointRecords, this function verifies both the cryptographic signature
/// AND timestamp freshness to prevent replay attacks where attackers re-publish
/// old records to redirect traffic to stale addresses.
pub fn verify_key_value_pair(key: &Key, value: &[u8]) -> bool {
    // 1. Check strict content addressing (immutable data)
    if hash_content(value) == *key {
        return true;
    }

    // 2. Check for signed EndpointRecord (mutable identity data)
    // Try to deserialize as EndpointRecord
    if let Ok(record) = crate::messages::deserialize_bounded::<EndpointRecord>(value) {
        // Check if the record belongs to the key (key == Identity bytes in zero-hash)
        if record.identity.as_bytes() == key {
            // Verify the signature AND timestamp freshness to prevent replay attacks
            // Old records with valid signatures should be rejected to prevent
            // attackers from redirecting traffic to stale/controlled addresses
            if record.verify_fresh(ENDPOINT_RECORD_MAX_AGE_SECS) {
                return true;
            }
        }
    }

    false
}

/// Compare two XOR distances lexicographically.
///
/// Returns `Ordering::Less` if `a` represents a smaller distance,
/// `Ordering::Greater` if larger, or `Ordering::Equal` if identical.
pub(crate) fn distance_cmp(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in 0..32 {
        if a[i] < b[i] {
            return std::cmp::Ordering::Less;
        } else if a[i] > b[i] {
            return std::cmp::Ordering::Greater;
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn hash_content_is_deterministic() {
        let data = b"hello world";
        let hash_one = hash_content(data);
        let hash_two = hash_content(data);
        assert_eq!(hash_one, hash_two, "hashes of identical data should match");

        let different_hash = hash_content(b"goodbye world");
        assert_ne!(
            hash_one, different_hash,
            "hashes of different data should differ"
        );
    }

    #[test]
    fn verify_key_value_pair_matches_hash() {
        let data = b"payload";
        let key = hash_content(data);
        assert!(
            verify_key_value_pair(&key, data),
            "verify_key_value_pair should accept matching key/value pairs"
        );

        let mut wrong_key = key;
        wrong_key[0] ^= 0xFF;
        assert!(
            !verify_key_value_pair(&wrong_key, data),
            "verify_key_value_pair should reject non-matching key/value pairs"
        );
    }

    #[test]
    fn hash_content_matches_blake3_reference() {
        let data = b"hello world";
        let expected = blake3::hash(data);
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(expected.as_bytes());

        assert_eq!(
            hash_content(data),
            expected_bytes,
            "hash_content should produce the BLAKE3 digest"
        );
    }

    #[test]
    fn xor_distance_produces_expected_value() {
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 0b1010_1010;
        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 0b0101_0101;

        let a = Identity::from_bytes(a_bytes);
        let b = Identity::from_bytes(b_bytes);
        let dist = xor_distance(&a, &b);
        assert_eq!(dist[0], 0b1111_1111);
        assert!(dist.iter().skip(1).all(|byte| *byte == 0));
    }

    #[test]
    fn distance_cmp_orders_lexicographically() {
        let mut smaller = [0u8; 32];
        smaller[1] = 1;
        let mut larger = [0u8; 32];
        larger[1] = 2;

        assert_eq!(distance_cmp(&smaller, &larger), Ordering::Less);
        assert_eq!(distance_cmp(&larger, &smaller), Ordering::Greater);
        assert_eq!(distance_cmp(&smaller, &smaller), Ordering::Equal);
    }
}
