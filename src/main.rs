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
//! The node will start and print its Identity (hex-encoded Ed25519 public key)
//! and endpoint address. Telemetry is printed periodically showing the current
//! state of the node.

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::time::{self, Duration};
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use corium::Node;

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
    identity: String,
}

impl FromStr for BootstrapPeer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // Format: IP:PORT/IDENTITY (Identity is mandatory)
        let (addr_part, id_part) = s.rsplit_once('/')
            .context("bootstrap peer must include Identity (format: IP:PORT/IDENTITY)")?;
        
        let addr: SocketAddr = addr_part.parse()
            .context("invalid socket address")?;
        
        // Validate identity is valid hex
        let id_bytes = hex::decode(id_part)
            .context("invalid hex Identity")?;
        if id_bytes.len() != 32 {
            anyhow::bail!("Identity must be 64 hex characters (32 bytes)");
        }
        
        Ok(BootstrapPeer { addr, identity: id_part.to_string() })
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

    /// Telemetry logging interval in seconds
    #[arg(short, long, default_value = "300")]
    telemetry_interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing subscriber with env filter
    // Default to "info" level, can be overridden with RUST_LOG env var
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

    // Start the node (auto-generates identity)
    let node = Node::bind(&args.bind.to_string()).await?;
    info!("Node identity: {}", node.identity());

    // Bootstrap from provided peers
    for peer in &args.bootstrap {
        info!("Bootstrapping from {}/{}", peer.addr, &peer.identity[..16]);
        match node.bootstrap(&peer.identity, &peer.addr.to_string()).await {
            Ok(()) => {
                info!("Bootstrap complete");
            }
            Err(e) => {
                warn!(error = %e, "Bootstrap failed");
            }
        }
    }

    // Periodically log telemetry
    let telemetry_interval = args.telemetry_interval;
    let mut interval = time::interval(Duration::from_secs(telemetry_interval));
    loop {
        interval.tick().await;
        let snapshot = node.telemetry().await;
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
}
