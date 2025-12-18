use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::time::{self, Duration};
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use corium::Node;

#[derive(Clone, Debug)]
struct BootstrapPeer {
    addr: SocketAddr,
    identity: String,
}

impl FromStr for BootstrapPeer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (addr_part, id_part) = s.rsplit_once('/')
            .context("bootstrap peer must include Identity (format: IP:PORT/IDENTITY)")?;
        
        let addr: SocketAddr = addr_part.parse()
            .context("invalid socket address")?;
        
        let id_bytes = hex::decode(id_part)
            .context("invalid hex Identity")?;
        if id_bytes.len() != 32 {
            anyhow::bail!("Identity must be 64 hex characters (32 bytes)");
        }
        
        Ok(BootstrapPeer { addr, identity: id_part.to_string() })
    }
}

#[derive(Parser, Debug)]
#[command(name = "corium")]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,

    #[arg(short = 'B', long = "bootstrap", value_name = "PEER")]
    bootstrap: Vec<BootstrapPeer>,

    #[arg(short, long, default_value = "300")]
    telemetry_interval: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    let node = Node::bind(&args.bind.to_string()).await?;
    info!("Node identity: {}", node.identity());

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

    let telemetry_interval = args.telemetry_interval;
    let mut interval = time::interval(Duration::from_secs(telemetry_interval));
    
    // Graceful shutdown on Ctrl+C
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal, exiting gracefully");
                break;
            }
            _ = interval.tick() => {
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
    }
    
    Ok(())
}