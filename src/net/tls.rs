//! TLS configuration and Ed25519 certificate handling for QUIC connections.
//!
//! This module provides:
//! - Self-signed Ed25519 certificate generation
//! - Server and client TLS configuration for QUIC
//! - SNI-based identity pinning for peer verification
//! - Certificate verifiers for mutual TLS

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::identity::{Identity, Keypair};

/// Default crypto provider for TLS signature verification.
static CRYPTO_PROVIDER: std::sync::LazyLock<Arc<rustls::crypto::CryptoProvider>> =
    std::sync::LazyLock::new(|| Arc::new(rustls::crypto::ring::default_provider()));

/// ALPN protocol identifier for Corium connections.
pub const ALPN: &[u8] = b"corium";

/// Generate a self-signed Ed25519 certificate for QUIC connections.
///
/// This creates a certificate using the provided Ed25519 keypair, allowing
/// the node's cryptographic identity to be tied to its TLS certificate.
/// The Identity is the same as the keypair's public key.
pub fn generate_ed25519_cert(
    keypair: &Keypair,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Build the Ed25519 key pair in PKCS8 format for rcgen
    let secret_key = keypair.secret_key_bytes();
    let public_key = keypair.public_key_bytes();
    
    // Ed25519 PKCS8 format (RFC 8410)
    // This is a minimal PKCS#8 structure for Ed25519 private keys
    // OID 1.3.101.112 (Ed25519)
    const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    const PKCS8_VERSION: [u8; 3] = [0x02, 0x01, 0x00];
    
    let mut pkcs8 = Vec::with_capacity(48);
    // PKCS#8 header for Ed25519
    pkcs8.extend_from_slice(&[
        0x30, 0x2e, // SEQUENCE, 46 bytes
    ]);
    pkcs8.extend_from_slice(&PKCS8_VERSION); // INTEGER 0 (version)
    pkcs8.extend_from_slice(&[
        0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
    ]);
    pkcs8.extend_from_slice(&ED25519_OID);
    pkcs8.extend_from_slice(&[
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
    ]);
    pkcs8.extend_from_slice(&secret_key);
    
    // Create KeyPair from PKCS8 DER - rcgen will auto-detect Ed25519
    let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8.clone());
    let key_pair = rcgen::KeyPair::try_from(&pkcs8_der)
        .context("failed to create Ed25519 key pair for certificate")?;
    
    // Create certificate with the node's public key encoded in the subject
    let mut params = rcgen::CertificateParams::new(vec!["corium".to_string()])
        .context("failed to create certificate params")?;
    
    // Encode the public key in the common name for peer verification
    // Use Utf8String instead of PrintableString for hex-encoded data
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

/// Create a server configuration for accepting QUIC connections.
///
/// Enables connection migration by default, allowing clients to change
/// their IP address (e.g., switching from relay to direct) without
/// re-establishing the connection.
pub fn create_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    // Require client certificates for mutual TLS - enables peer identity verification
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
    
    // Enable connection migration - allows clients to change addresses
    // (e.g., switching from relay to direct path)
    server_config.migration(true);
    
    // Configure transport parameters for security and resource management
    // Arc::get_mut is safe here because we just created server_config and hold the only reference
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .expect("transport config should be exclusively owned immediately after creation");
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(60)
            .try_into()
            .expect("60 seconds is a valid VarInt duration"),
    ));
    // Bound concurrent inbound streams to mitigate resource exhaustion.
    transport_config.max_concurrent_bidi_streams(64u32.into());
    transport_config.max_concurrent_uni_streams(64u32.into());

    Ok(server_config)
}

/// Create a client config that enforces peer identity via SNI.
///
/// The verifier extracts the expected peer Identity from the SNI (Server Name Indication)
/// field during the handshake and verifies that the peer's certificate matches it.
///
/// This allows a single `ClientConfig` to be used for connecting to any peer,
/// provided the connection is initiated with the correct SNI (the peer's Identity hex string).
pub fn create_client_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ClientConfig> {
    let verifier = Ed25519CertVerifier::new();

    // For self-signed certs, accept valid Ed25519 certificates and enforce
    // the identity pinned in the SNI.
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

/// Extract the Ed25519 public key from a peer's certificate.
///
/// The public key is extracted from the Subject Public Key Info (SPKI) field.
/// Returns `None` if the certificate doesn't contain a valid Ed25519 public key.
pub fn extract_public_key_from_cert(cert_der: &[u8]) -> Option<[u8; 32]> {
    // Parse the certificate to extract the public key from the Subject Public Key Info (SPKI)
    // This ensures the identity is derived from the key used for the TLS handshake,
    // preventing identity spoofing via the Common Name.
    use x509_parser::prelude::*;
    
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    
    // Extract the public key bytes from the SPKI
    let spki = cert.public_key();
    let key_bytes = &spki.subject_public_key.data;
    
    // Ed25519 public keys are exactly 32 bytes
    if key_bytes.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        Some(key)
    } else {
        None
    }
}

/// Verify that a peer's certificate matches their claimed identity.
///
/// This extracts the Ed25519 public key from the certificate and verifies
/// that it matches the expected identity (public key bytes).
///
/// # Use Cases
///
/// - **Post-handshake verification**: After QUIC handshake completes, verify
///   that the peer's certificate identity matches what we expected
/// - **Sybil protection**: Ensure peers can't claim to be a different identity
pub fn verify_peer_identity(cert_der: &[u8], expected_identity: &Identity) -> bool {
    if let Some(public_key) = extract_public_key_from_cert(cert_der) {
        crate::identity::verify_identity(expected_identity, &public_key)
    } else {
        false
    }
}

// ============================================================================
// Certificate Verifiers
// ============================================================================

/// Client certificate verifier for mutual TLS.
///
/// Accepts any client certificate - actual identity verification is done at the
/// application layer after extracting the public key from the certificate.
#[derive(Debug)]
struct Ed25519ClientCertVerifier;

impl rustls::server::danger::ClientCertVerifier for Ed25519ClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Accept any certificate - identity verification is done at app layer
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Actually verify the cryptographic signature using the certificate's public key
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
        // Actually verify the cryptographic signature using the certificate's public key
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

/// Encode an Identity as a valid DNS-style SNI hostname for TLS identity pinning.
///
/// The hex-encoded Identity (64 chars) exceeds the DNS label limit (63 chars),
/// so we split it into two labels: `<first32>.<last32>`
///
/// # Formal Invariant
/// `∀ id. parse_identity_from_sni(&identity_to_sni(id)) == Some(id)`
pub(crate) fn identity_to_sni(identity: &Identity) -> String {
    let hex = hex::encode(identity);
    format!("{}.{}", &hex[..32], &hex[32..])
}

/// Parse an Identity from a DNS-style SNI hostname.
///
/// # Formal Invariant
/// Roundtrip: `parse_identity_from_sni(&identity_to_sni(id))` recovers the original.
fn parse_identity_from_sni(sni: &str) -> Option<Identity> {
    // Split by '.' and concatenate the hex parts
    let hex_str: String = sni.split('.').collect();
    let bytes = hex::decode(&hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Identity::from_bytes(arr))
}

/// Certificate verifier implementing SNI-based identity pinning.
///
/// # Formal Property (P3 - SNI Identity Pinning)
///
/// This verifier enforces the invariant:
/// ```text
/// verify_server_cert(cert, sni) succeeds ⟺
///     ∃ pk ∈ cert.SPKI : pk == parse_identity_from_sni(sni)
/// ```
///
/// The verification chain is:
/// 1. Extract expected identity from SNI hostname (DNS-encoded)
/// 2. Extract actual public key from certificate's Subject Public Key Info
/// 3. Compare: public key must equal expected identity (zero-hash model)
///
/// This prevents MITM attacks where an attacker presents a different certificate.
#[derive(Debug)]
struct Ed25519CertVerifier;

impl Ed25519CertVerifier {
    fn new() -> Self {
        Self
    }
}

impl rustls::client::danger::ServerCertVerifier for Ed25519CertVerifier {
    /// Verify server certificate matches the expected identity encoded in SNI.
    ///
    /// # Formal Verification Steps
    ///
    /// 1. **SNI → Expected Identity**: Parse DNS-encoded identity from SNI hostname
    /// 2. **Certificate → Actual Public Key**: Extract Ed25519 public key from SPKI
    /// 3. **Identity Comparison**: Verify public key == expected identity (constant-time)
    ///
    /// # Security Properties
    ///
    /// - **P3**: SNI Identity Pinning - certificate's public key must match expected identity
    /// - TLS signature verification is handled by `verify_tls1[23]_signature`
    /// - Prevents certificate substitution attacks
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // FORMAL VERIFICATION STEP 1:
        // Extract expected identity from SNI (DNS-style encoded)
        let expected_identity_sni = match server_name {
            rustls::pki_types::ServerName::DnsName(name) => name.as_ref(),
            rustls::pki_types::ServerName::IpAddress(_) => {
                // P3 violation: Cannot verify identity without SNI
                // Connecting by IP address bypasses identity pinning
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

        // Parse SNI as Identity (zero-hash model: identity = public key)
        let expected_identity = parse_identity_from_sni(expected_identity_sni).ok_or_else(|| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // FORMAL VERIFICATION STEP 2:
        // Extract actual public key from certificate's SPKI
        let public_key = extract_public_key_from_cert(end_entity.as_ref())
            .ok_or(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ))?;

        // FORMAL VERIFICATION STEP 3:
        // Zero-hash model: Identity IS the public key, no hashing needed
        // Compare expected identity vs actual public key
        let actual_identity = Identity::from_bytes(public_key);
        if actual_identity != expected_identity {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ));
        }

        // Certificate is valid and its public key matches the pinned identity.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Actually verify the cryptographic signature using the certificate's public key
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
        // Actually verify the cryptographic signature using the certificate's public key
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &CRYPTO_PROVIDER.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            // Keep other schemes for backwards compatibility
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
