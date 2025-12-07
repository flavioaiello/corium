//! Message authentication for PubSub.
//!
//! All published messages are cryptographically signed by the source's private key.
//! This module provides the signing and verification primitives.
//!
//! # Security
//!
//! Message signatures prevent:
//! - **Identity spoofing**: Cannot claim to be someone else
//! - **Message forgery**: Cannot create messages on behalf of others
//! - **Dedup cache poisoning**: Cannot inject fake seqnos for other identities

use ed25519_dalek::{Signature, VerifyingKey};

use crate::identity::{Identity, Keypair};

/// Reason why a message signature verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature is missing (empty).
    Missing,
    /// Signature has invalid length (must be 64 bytes).
    InvalidLength,
    /// Signature verification failed (wrong key or tampered data).
    VerificationFailed,
    /// Source identity has invalid public key bytes.
    InvalidPublicKey,
}

/// Build the data to sign for a pubsub message.
///
/// The signed data is: topic || seqno (le bytes) || data
/// Using length prefixes to prevent malleability attacks.
pub(crate) fn build_signed_data(topic: &str, seqno: u64, data: &[u8]) -> Vec<u8> {
    let mut signed_data = Vec::new();
    // Length-prefix topic to prevent concatenation attacks
    let topic_bytes = topic.as_bytes();
    signed_data.extend_from_slice(&(topic_bytes.len() as u32).to_le_bytes());
    signed_data.extend_from_slice(topic_bytes);
    // Sequence number
    signed_data.extend_from_slice(&seqno.to_le_bytes());
    // Length-prefix data
    signed_data.extend_from_slice(&(data.len() as u32).to_le_bytes());
    signed_data.extend_from_slice(data);
    signed_data
}

/// Sign a pubsub message.
///
/// Returns the Ed25519 signature over (topic || seqno || data).
pub fn sign_pubsub_message(keypair: &Keypair, topic: &str, seqno: u64, data: &[u8]) -> Vec<u8> {
    let signed_data = build_signed_data(topic, seqno, data);
    keypair.sign(&signed_data).to_bytes().to_vec()
}

/// Verify a pubsub message signature.
///
/// Checks that the signature is valid for the given source identity.
/// Returns `Ok(())` if valid, or `Err(SignatureError)` if invalid.
pub fn verify_pubsub_signature(
    source: &Identity,
    topic: &str,
    seqno: u64,
    data: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    // Check signature length
    if signature.is_empty() {
        return Err(SignatureError::Missing);
    }
    if signature.len() != 64 {
        return Err(SignatureError::InvalidLength);
    }

    // Parse the public key from source identity
    let verifying_key = VerifyingKey::try_from(source.as_bytes().as_slice())
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    // Parse the signature
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| SignatureError::InvalidLength)?;
    let signature = Signature::from_bytes(&sig_bytes);

    // Build the signed data and verify
    let signed_data = build_signed_data(topic, seqno, data);
    verifying_key
        .verify_strict(&signed_data, &signature)
        .map_err(|_| SignatureError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_message_valid() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, data);
        
        // Verify with the correct identity
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &signature,
        );
        assert!(result.is_ok(), "valid signature should verify");
    }

    #[test]
    fn verify_message_wrong_identity_fails() {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        // Sign with keypair1
        let signature = sign_pubsub_message(&keypair1, topic, seqno, data);
        
        // Try to verify with keypair2's identity - should fail
        let result = verify_pubsub_signature(
            &keypair2.identity(),
            topic,
            seqno,
            data,
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn verify_message_wrong_topic_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, data);
        
        // Verify with wrong topic
        let result = verify_pubsub_signature(
            &keypair.identity(),
            "different/topic",
            seqno,
            data,
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn verify_message_wrong_seqno_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, data);
        
        // Verify with wrong seqno
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            43, // different seqno
            data,
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn verify_message_wrong_data_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let signature = sign_pubsub_message(&keypair, topic, seqno, data);
        
        // Verify with wrong data
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            b"different data",
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn verify_message_empty_signature_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &[], // empty signature
        );
        assert_eq!(result, Err(SignatureError::Missing));
    }

    #[test]
    fn verify_message_short_signature_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &[0u8; 32], // too short (should be 64)
        );
        assert_eq!(result, Err(SignatureError::InvalidLength));
    }

    #[test]
    fn verify_message_corrupted_signature_fails() {
        let keypair = Keypair::generate();
        let topic = "test/topic";
        let seqno = 42u64;
        let data = b"hello world";
        
        let mut signature = sign_pubsub_message(&keypair, topic, seqno, data);
        // Corrupt the signature
        signature[0] ^= 0xFF;
        
        let result = verify_pubsub_signature(
            &keypair.identity(),
            topic,
            seqno,
            data,
            &signature,
        );
        assert_eq!(result, Err(SignatureError::VerificationFailed));
    }

    #[test]
    fn signed_data_not_malleable() {
        // Prove that different messages produce different signed data
        let topic1 = "topic1";
        let topic2 = "topic2";
        let seqno = 42u64;
        let data = b"hello";
        
        let signed1 = build_signed_data(topic1, seqno, data);
        let signed2 = build_signed_data(topic2, seqno, data);
        
        assert_ne!(signed1, signed2, "different topics should produce different signed data");
        
        // Test seqno affects signed data
        let signed3 = build_signed_data(topic1, 43, data);
        assert_ne!(signed1, signed3, "different seqnos should produce different signed data");
        
        // Test data affects signed data
        let signed4 = build_signed_data(topic1, seqno, b"world");
        assert_ne!(signed1, signed4, "different data should produce different signed data");
    }

    // ========================================================================
    // Message Authentication Security Tests (from tests/security_pubsub.rs)
    // ========================================================================

    #[test]
    fn valid_signature_verifies() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let data = b"important message";

        let signature = sign_pubsub_message(&keypair, topic, seqno, data);

        let result = verify_pubsub_signature(&keypair.identity(), topic, seqno, data, &signature);

        assert!(result.is_ok(), "valid signature must verify");
    }

    #[test]
    fn forged_message_rejected() {
        let real_author = Keypair::generate();
        let attacker = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let data = b"important message";

        let forged_signature = sign_pubsub_message(&attacker, topic, seqno, data);

        let result = verify_pubsub_signature(&real_author.identity(), topic, seqno, data, &forged_signature);

        assert_eq!(
            result,
            Err(SignatureError::VerificationFailed),
            "forged signature must be rejected"
        );
    }

    #[test]
    fn tampered_data_detected() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let original_data = b"important message";
        let tampered_data = b"malicious message";

        let signature = sign_pubsub_message(&keypair, topic, seqno, original_data);

        let result = verify_pubsub_signature(&keypair.identity(), topic, seqno, tampered_data, &signature);

        assert_eq!(
            result,
            Err(SignatureError::VerificationFailed),
            "tampered data must be detected"
        );
    }

    #[test]
    fn seqno_manipulation_detected() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let original_seqno = 123u64;
        let tampered_seqno = 999u64;
        let data = b"important message";

        let signature = sign_pubsub_message(&keypair, topic, original_seqno, data);

        let result = verify_pubsub_signature(&keypair.identity(), topic, tampered_seqno, data, &signature);

        assert_eq!(
            result,
            Err(SignatureError::VerificationFailed),
            "seqno manipulation must be detected"
        );
    }

    #[test]
    fn topic_substitution_detected() {
        let keypair = Keypair::generate();
        let original_topic = "public/channel";
        let tampered_topic = "private/admin";
        let seqno = 123u64;
        let data = b"important message";

        let signature = sign_pubsub_message(&keypair, original_topic, seqno, data);

        let result = verify_pubsub_signature(&keypair.identity(), tampered_topic, seqno, data, &signature);

        assert_eq!(
            result,
            Err(SignatureError::VerificationFailed),
            "topic substitution must be detected"
        );
    }

    #[test]
    fn missing_signature_rejected() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let data = b"important message";

        let result = verify_pubsub_signature(&keypair.identity(), topic, seqno, data, &[]);

        assert_eq!(
            result,
            Err(SignatureError::Missing),
            "missing signature must be rejected"
        );
    }

    #[test]
    fn malformed_signature_rejected() {
        let keypair = Keypair::generate();
        let topic = "secure/channel";
        let seqno = 123u64;
        let data = b"important message";

        let result = verify_pubsub_signature(&keypair.identity(), topic, seqno, data, &[0u8; 32]);

        assert_eq!(
            result,
            Err(SignatureError::InvalidLength),
            "wrong-length signature must be rejected"
        );
    }

    #[test]
    fn concatenation_attack_prevented() {
        let keypair = Keypair::generate();
        let seqno = 1u64;

        let topic1 = "chat";
        let data1 = b"room/hello";

        let topic2 = "chat/room";
        let data2 = b"hello";

        let sig1 = sign_pubsub_message(&keypair, topic1, seqno, data1);
        let sig2 = sign_pubsub_message(&keypair, topic2, seqno, data2);

        assert_ne!(sig1, sig2, "different messages must have different signatures");

        let cross_verify = verify_pubsub_signature(&keypair.identity(), topic1, seqno, data2, &sig2);
        assert!(cross_verify.is_err(), "cross verification must fail");
    }
}
