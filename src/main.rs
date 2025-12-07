//! Example DHT node binary demonstrating corium usage.
//!
//! This binary starts a DHT node with QUIC transport. It demonstrates the
//! basic setup pattern for using the corium library.
//!
//! # Usage
//!
//! ```bash
//! # Show help
//! cargo run -- --help
//!
//! # Start with default settings
//! cargo run
//!
//! # Start on specific port with bootstrap peer
//! cargo run -- --bind 0.0.0.0:9000 --bootstrap 192.168.1.100:9000
//!
//! # With debug logging
//! RUST_LOG=debug cargo run
//! ```
//!
//! The node will start and print its NodeId and endpoint address. Telemetry
//! is printed periodically showing the current state of the node.

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Parser;
use futures::future;
use quinn::Endpoint;
use tokio::time::{self, Duration};
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use corium::{
    create_client_config, create_server_config, generate_ed25519_cert,
    Contact, MeshNode, DhtNode, Keypair, QuinnNetwork, Identity,
};

/// A bootstrap peer specification.
/// 
/// Format: `IP:PORT/NODEID` (e.g., `192.168.1.100:9000/5821a288e16c...`)
/// 
/// The NodeId is mandatory because TLS identity pinning requires knowing
/// the peer's public key before connecting. This prevents MITM attacks
/// during bootstrap.
#[derive(Clone, Debug)]
struct BootstrapPeer {
    addr: SocketAddr,
    identity: Identity,
}

impl FromStr for BootstrapPeer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // Format: IP:PORT/IDENTITY (Identity is mandatory)
        let (addr_part, id_part) = s.rsplit_once('/')
            .context("bootstrap peer must include Identity (format: IP:PORT/IDENTITY)")?;
        
        let addr: SocketAddr = addr_part.parse()
            .context("invalid socket address")?;
        let id_bytes = hex::decode(id_part)
            .context("invalid hex Identity")?;
        if id_bytes.len() != 32 {
            anyhow::bail!("Identity must be 64 hex characters (32 bytes)");
        }
        let mut identity_bytes = [0u8; 32];
        identity_bytes.copy_from_slice(&id_bytes);
        Ok(BootstrapPeer { addr, identity: Identity::from_bytes(identity_bytes) })
    }
}

/// Corium DHT node - Adaptive mesh networking with QUIC transport
#[derive(Parser, Debug)]
#[command(name = "corium")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to bind to (e.g., 0.0.0.0:9000)
    #[arg(short, long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,

    /// Bootstrap peer (can be specified multiple times)
    /// Format: IP:PORT/IDENTITY (Identity is required for TLS identity verification)
    /// Example:
    ///   -B 192.168.1.100:9000/5821a288e16c6491ae72f4cf060b8d6523cd416c418c1ec3b8b5bc7608a55b7d
    #[arg(short = 'B', long = "bootstrap", value_name = "PEER")]
    bootstrap: Vec<BootstrapPeer>,

    /// Bucket size / replication factor (k parameter)
    #[arg(short, long, default_value = "20")]
    k: usize,

    /// Lookup parallelism (alpha parameter)
    #[arg(short, long, default_value = "3")]
    alpha: usize,

    /// Telemetry logging interval in seconds
    #[arg(short, long, default_value = "300")]
    telemetry_interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing subscriber with env filter
    // Default to "info" level, can be overridden with RUST_LOG env var
    // Use a custom writer that flushes after each write for unbuffered output
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_writer(std::io::stderr)
        .init();

    // Generate Ed25519 keypair for node identity
    let keypair = Keypair::generate();
    let identity = keypair.identity();

    // Generate self-signed Ed25519 certificate for QUIC
    let (certs, key) = generate_ed25519_cert(&keypair)?;
    // Clone certs and key for client config (mutual TLS requires both sides)
    let (client_certs, client_key) = generate_ed25519_cert(&keypair)?;
    let server_config = create_server_config(certs, key)?;
    // Client config enforces identity verification via SNI pinning.
    let client_config = create_client_config(client_certs, client_key)?;

    // Bind to specified address
    let endpoint = Endpoint::server(server_config, args.bind)?;
    let local_addr = endpoint.local_addr()?;

    // Create our contact info for sharing with peers.
    let self_contact = Contact {
        identity,
        addr: local_addr.to_string(),
    };

    // Log node startup in format: Node IP:PORT/IDENTITY
    info!("Node {}/{}", local_addr, hex::encode(identity));
    info!(k = args.k, alpha = args.alpha, "Parameters");

    // Create the network layer and discovery node.
    let network = QuinnNetwork::new(endpoint.clone(), self_contact.clone(), client_config);
    let dht = DhtNode::new(identity, self_contact.clone(), network, args.k, args.alpha);

    // Start the mesh node to accept incoming connections.
    let node = MeshNode::new(dht.clone())
        .context("failed to initialize relay server - CSPRNG unavailable")?;
    let _node_handle = node.spawn(endpoint.clone());

    // Bootstrap from provided peers
    if !args.bootstrap.is_empty() {
        info!("Bootstrapping from {} peer(s)", args.bootstrap.len());
        
        // Add all bootstrap contacts to routing table
        // Identity is mandatory, so we can directly add verified contacts
        for peer in &args.bootstrap {
            let bootstrap_contact = Contact {
                identity: peer.identity,
                addr: peer.addr.to_string(),
            };
            info!("Bootstrap {}/{}", peer.addr, hex::encode(peer.identity));
            dht.observe_contact(bootstrap_contact).await;
        }
        
        // Perform initial lookup to populate routing table
        info!("Performing bootstrap lookup...");
        match dht.iterative_find_node(identity).await {
            Ok(nodes) => {
                info!(found = nodes.len(), "Bootstrap complete");
            }
            Err(e) => {
                warn!(error = %e, "Bootstrap lookup failed");
            }
        }
    }

    // Spawn a background task to periodically log telemetry.
    let telemetry_node = dht.clone();
    let telemetry_interval = args.telemetry_interval;
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(telemetry_interval));
        loop {
            interval.tick().await;
            let snapshot = telemetry_node.telemetry_snapshot().await;
            info!(
                pressure = format!("{:.2}", snapshot.pressure),
                stored_keys = snapshot.stored_keys,
                tier_counts = ?snapshot.tier_counts,
                tier_centroids = ?snapshot.tier_centroids,
                k = snapshot.replication_factor,
                alpha = snapshot.concurrency,
                "telemetry snapshot"
            );
        }
    });

    // Park the main task indefinitely.
    // A real application would expose an API for feeding peer contacts and performing lookups.
    future::pending::<()>().await;
    Ok(())
}
