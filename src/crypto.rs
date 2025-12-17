//! # Cryptographic Infrastructure
//!
//! This module provides cryptographic primitives for Corium:
//!
//! - **Content Hashing**: BLAKE3 for content-addressed storage keys
//! - **Signatures**: Domain-separated Ed25519 signing and verification
//! - **TLS**: Certificate generation and verification for mutual auth
//!
//! ## Identity Model
//!
//! - **Identity = Public Key**: The 32-byte Ed25519 public key IS the peer's identity
//! - **Self-Signed Certs**: Each node generates its own certificate from its keypair
//! - **Mutual Auth**: Both client and server verify each other's certificates
//!
//! ## Security Properties
//!
//! - No PKI/CA required - trust is based on knowing the peer's identity (public key)
//! - Certificate CN contains hex-encoded public key for debugging
//! - ALPN protocol "corium" prevents cross-protocol attacks
//! - Only Ed25519 signatures are accepted (no RSA, ECDSA fallback)
//! - Domain separation prevents cross-protocol signature replay
//!
//! ## SECURITY WARNING
//!
//! The `dangerous()` APIs are used intentionally - we implement our own
//! certificate verification that binds identity to public key, not to
//! traditional CA-signed certificate chains.

use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use quinn::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::identity::{Identity, Keypair};

// ============================================================================
// Signature Error Types
// ============================================================================

/// Error type for signature verification failures.
/// Used across all Corium signature verification (GossipSub, Contact, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature is missing (empty).
    Missing,
    /// Signature has invalid length (expected 64 bytes for Ed25519).
    InvalidLength,
    /// Cryptographic verification failed.
    VerificationFailed,
    /// The public key is not a valid Ed25519 point.
    InvalidPublicKey,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::Missing => write!(f, "signature is missing"),
            SignatureError::InvalidLength => write!(f, "signature has invalid length"),
            SignatureError::VerificationFailed => write!(f, "signature verification failed"),
            SignatureError::InvalidPublicKey => write!(f, "invalid public key"),
        }
    }
}

impl std::error::Error for SignatureError {}

// ============================================================================
// Domain Separation Prefixes
// ============================================================================
//
// SECURITY: Domain separation prevents cross-protocol signature replay attacks.
// Each signed data type in Corium uses a unique prefix to ensure signatures
// cannot be reused in a different context.

/// Domain separation prefix for GossipSub message signatures.
pub const GOSSIPSUB_SIGNATURE_DOMAIN: &[u8] = b"corium-gossipsub-v1:";

/// Domain separation prefix for Contact record signatures.
pub const CONTACT_SIGNATURE_DOMAIN: &[u8] = b"corium-contact-v1:";

// ============================================================================
// Domain-Separated Signature Helpers
// ============================================================================

/// Sign data with domain separation.
/// 
/// Prepends the domain prefix to the data before signing, preventing
/// cross-protocol signature replay attacks.
/// 
/// # Arguments
/// * `keypair` - The signing keypair
/// * `domain` - Domain separation prefix (e.g., `GOSSIPSUB_SIGNATURE_DOMAIN`)
/// * `data` - The data to sign
/// 
/// # Returns
/// 64-byte Ed25519 signature as a Vec<u8>
pub fn sign_with_domain(keypair: &Keypair, domain: &[u8], data: &[u8]) -> Vec<u8> {
    let mut prefixed = Vec::with_capacity(domain.len() + data.len());
    prefixed.extend_from_slice(domain);
    prefixed.extend_from_slice(data);
    keypair.sign(&prefixed).to_bytes().to_vec()
}

/// Verify a signature with domain separation.
/// 
/// Reconstructs the prefixed data and verifies the Ed25519 signature.
/// 
/// # Arguments
/// * `identity` - The claimed signer's identity (public key)
/// * `domain` - Domain separation prefix (must match what was used during signing)
/// * `data` - The original data that was signed
/// * `signature` - The 64-byte Ed25519 signature
/// 
/// # Returns
/// `Ok(())` if signature is valid, `Err(SignatureError)` otherwise
pub fn verify_with_domain(
    identity: &Identity,
    domain: &[u8],
    data: &[u8],
    signature: &[u8],
) -> std::result::Result<(), SignatureError> {
    if signature.is_empty() {
        return Err(SignatureError::Missing);
    }
    if signature.len() != 64 {
        return Err(SignatureError::InvalidLength);
    }

    let verifying_key = VerifyingKey::try_from(identity.as_bytes().as_slice())
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| SignatureError::InvalidLength)?;
    let sig = Signature::from_bytes(&sig_bytes);

    let mut prefixed = Vec::with_capacity(domain.len() + data.len());
    prefixed.extend_from_slice(domain);
    prefixed.extend_from_slice(data);

    verifying_key
        .verify_strict(&prefixed, &sig)
        .map_err(|_| SignatureError::VerificationFailed)
}

/// Lazily-initialized crypto provider for rustls.
/// Uses ring as the underlying cryptographic implementation.
static CRYPTO_PROVIDER: std::sync::LazyLock<Arc<rustls::crypto::CryptoProvider>> =
    std::sync::LazyLock::new(|| Arc::new(rustls::crypto::ring::default_provider()));

/// ALPN protocol identifier. All Corium connections use this to prevent
/// accidental cross-protocol connections.
pub const ALPN: &[u8] = b"corium";

pub fn generate_ed25519_cert(
    keypair: &Keypair,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let secret_key = keypair.secret_key_bytes();
    let public_key = keypair.public_key_bytes();
    
    const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    const PKCS8_VERSION: [u8; 3] = [0x02, 0x01, 0x00];
    
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&[
        0x30, 0x2e,    ]);
    pkcs8.extend_from_slice(&PKCS8_VERSION);    pkcs8.extend_from_slice(&[
        0x30, 0x05,    ]);
    pkcs8.extend_from_slice(&ED25519_OID);
    pkcs8.extend_from_slice(&[
        0x04, 0x22,        0x04, 0x20,    ]);
    pkcs8.extend_from_slice(&secret_key);
    
    let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8.clone());
    let key_pair = rcgen::KeyPair::try_from(&pkcs8_der)
        .context("failed to create Ed25519 key pair for certificate")?;
    
    let mut params = rcgen::CertificateParams::new(vec!["corium".to_string()])
        .context("failed to create certificate params")?;
    
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String(hex::encode(public_key)),
    );
    
    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate self-signed Ed25519 certificate")?;
    
    let key = PrivateKeyDer::Pkcs8(pkcs8.into());
    let cert_der = CertificateDer::from(cert.der().to_vec());
    
    Ok((vec![cert_der], key))
}

pub fn create_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    let client_cert_verifier = Arc::new(Ed25519ClientCertVerifier);
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(certs, key)
        .context("failed to create server TLS config")?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("failed to create QUIC server config")?,
    ));
    
    server_config.migration(true);
    
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .expect("transport config should be exclusively owned immediately after creation");
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(60)
            .try_into()
            .expect("60 seconds is a valid VarInt duration"),
    ));
    transport_config.max_concurrent_bidi_streams(64u32.into());
    transport_config.max_concurrent_uni_streams(64u32.into());

    Ok(server_config)
}

pub fn create_client_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ClientConfig> {
    let verifier = Ed25519CertVerifier::new();

    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(certs, key)
        .context("failed to create client TLS config with client auth")?;

    let mut client_crypto_with_alpn = client_crypto;
    client_crypto_with_alpn.alpn_protocols = vec![ALPN.to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto_with_alpn)
            .context("failed to create QUIC client config")?,
    ));

    Ok(client_config)
}

pub fn extract_public_key_from_cert(cert_der: &[u8]) -> Option<[u8; 32]> {
    use x509_parser::prelude::*;
    
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    
    let spki = cert.public_key();
    let key_bytes = &spki.subject_public_key.data;
    
    if key_bytes.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        Some(key)
    } else {
        None
    }
}

pub fn extract_verified_identity(connection: &quinn::Connection) -> Option<Identity> {
    let peer_identity = connection.peer_identity()?;
    let certs: &Vec<rustls::pki_types::CertificateDer> = peer_identity.downcast_ref()?;
    let cert_der = certs.first()?.as_ref();
    let public_key = extract_public_key_from_cert(cert_der)?;
    Some(Identity::from_bytes(public_key))
}

#[derive(Debug)]
struct Ed25519ClientCertVerifier;

impl rustls::server::danger::ClientCertVerifier for Ed25519ClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let public_key = extract_public_key_from_cert(end_entity.as_ref())
            .ok_or(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ))?;
        
        let identity = Identity::from_bytes(public_key);
        if !identity.is_valid() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

pub(crate) fn identity_to_sni(identity: &Identity) -> String {
    let hex = hex::encode(identity);
    format!("{}.{}", &hex[..32], &hex[32..])
}

fn parse_identity_from_sni(sni: &str) -> Option<Identity> {
    let hex_str: String = sni.split('.').collect();
    let bytes = hex::decode(&hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Identity::from_bytes(arr))
}

#[derive(Debug)]
struct Ed25519CertVerifier;

impl Ed25519CertVerifier {
    fn new() -> Self {
        Self
    }
}

impl rustls::client::danger::ServerCertVerifier for Ed25519CertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let expected_identity_sni = match server_name {
            rustls::pki_types::ServerName::DnsName(name) => name.as_ref(),
            rustls::pki_types::ServerName::IpAddress(_) => {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
            _ => {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        };

        let expected_identity = parse_identity_from_sni(expected_identity_sni).ok_or_else(|| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        let public_key = extract_public_key_from_cert(end_entity.as_ref())
            .ok_or(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ))?;

        let actual_identity = Identity::from_bytes(public_key);
        if actual_identity != expected_identity {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ));
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;
    use std::collections::HashSet;

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

    #[test]
    fn identity_matches_public_key() {
        for _ in 0..50 {
            let keypair = Keypair::generate();
            let identity = keypair.identity();
            let public_key = keypair.public_key_bytes();
            
            assert_eq!(
                *identity.as_bytes(), public_key,
                "P3 violation: Identity does not match public key"
            );
        }
    }

    #[test]
    fn identity_rejects_mismatched_public_key() {
        for _ in 0..50 {
            let keypair1 = Keypair::generate();
            let keypair2 = Keypair::generate();
            
            let identity1 = keypair1.identity();
            let public_key2 = keypair2.public_key_bytes();
            
            assert_ne!(
                *identity1.as_bytes(), public_key2,
                "P3 violation: Identity incorrectly matched wrong public key"
            );
        }
    }

    #[test]
    fn identity_bound_to_keypair_via_cert() {
        for _ in 0..50 {
            let keypair = Keypair::generate();
            let identity = keypair.identity();
            
            let (certs, _) = generate_ed25519_cert(&keypair)
                .expect("cert generation must succeed");
            
            let cert_pk = extract_public_key_from_cert(certs[0].as_ref())
                .expect("pk extraction must succeed");
            
            assert_eq!(
                *identity.as_bytes(), cert_pk,
                "P4 violation: Identity not bound to keypair via certificate"
            );
        }
    }

    #[test]
    fn different_keypairs_different_cert_public_keys() {
        let mut public_keys = HashSet::new();
        
        for _ in 0..100 {
            let keypair = Keypair::generate();
            let (certs, _) = generate_ed25519_cert(&keypair)
                .expect("cert generation must succeed");
            
            let cert_pk = extract_public_key_from_cert(certs[0].as_ref())
                .expect("pk extraction must succeed");
            
            assert!(
                public_keys.insert(cert_pk),
                "P4 violation: Certificate public key collision between different keypairs"
            );
        }
    }

}
