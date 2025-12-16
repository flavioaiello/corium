use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::AsyncBufReadExt;
use tokio::sync::RwLock;

use corium::Node;

#[derive(Parser, Debug)]
#[command(name = "chatroom")]
#[command(about = "A simple chatroom using Corium's pubsub and direct messaging API")]
struct ChatArgs {
    #[arg(long, default_value = "anon")]
    name: String,

    #[arg(long, default_value = "lobby")]
    room: String,

    #[arg(long, default_value = "0")]
    port: u16,

    #[arg(short = 'B', long = "bootstrap")]
    bootstrap: Option<String>,
}

type PeerRegistry = Arc<RwLock<HashMap<String, String>>>;

fn parse_bootstrap(s: &str) -> Result<(SocketAddr, String)> {
    let (addr_part, identity) = s
        .rsplit_once('/')
        .context("bootstrap peer must be in IP:PORT/IDENTITY format")?;

    let addr: SocketAddr = addr_part
        .parse()
        .context("invalid socket address in bootstrap peer")?;

    let id_bytes = hex::decode(identity).context("invalid hex in Identity")?;
    if id_bytes.len() != 32 {
        anyhow::bail!("Identity must be 64 hex characters (32 bytes)");
    }

    Ok((addr, identity.to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = ChatArgs::parse();

    let bind_addr = format!("0.0.0.0:{}", args.port);
    let node = Arc::new(Node::bind(&bind_addr).await?);

    let local_addr = node.local_addr()?;
    let identity = node.identity();

    let peers: PeerRegistry = Arc::new(RwLock::new(HashMap::new()));

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║                    Corium Chatroom                             ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ Nickname : {:<52} ║", args.name);
    println!("║ Room     : {:<52} ║", args.room);
    println!("║ Address  : {:<52} ║", local_addr);
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ Your Identity (for DMs):                                       ║");
    println!("║ {:<64} ║", identity);
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ Bootstrap string (copy this line):                             ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!("{}/{}", local_addr, identity);

    if let Some(bootstrap_str) = &args.bootstrap {
        let (addr, peer_identity) = parse_bootstrap(bootstrap_str)?;
        println!("\nBootstrapping from {}...", addr);
        match node.bootstrap(&peer_identity, &addr.to_string()).await {
            Ok(()) => println!("Bootstrap successful!"),
            Err(e) => eprintln!("Bootstrap failed: {}", e),
        }
    }

    let room_topic = format!("chat/{}", args.room);
    node.subscribe(&room_topic).await?;
    println!("\nSubscribed to room: {}", args.room);

    let mut pubsub_rx = node.messages().await?;
    let mut dm_rx = node.incoming_requests().await?;

    let room_filter = args.room.clone();
    let my_name = args.name.clone();
    let my_identity = identity.clone();
    let peers_for_pubsub = peers.clone();

    tokio::spawn(async move {
        while let Some(msg) = pubsub_rx.recv().await {
            if msg.topic == format!("chat/{}", room_filter) {
                let text = String::from_utf8_lossy(&msg.data);
                
                if let Some((name_id, _)) = text.split_once(": ") {
                    if let Some((name, id_prefix)) = name_id.split_once('@') {
                        if !my_identity.starts_with(id_prefix) {
                            let mut peers = peers_for_pubsub.write().await;
                            if !peers.contains_key(id_prefix) {
                                peers.insert(id_prefix.to_string(), name.to_string());
                            }
                        }
                    }
                }
                
                if !text.starts_with(&format!("{}@", my_name)) {
                    println!("\x1b[32m[room]\x1b[0m {}", text);
                }
            }
        }
    });

    tokio::spawn(async move {
        while let Some((from, data, response_tx)) = dm_rx.recv().await {
            let text = String::from_utf8_lossy(&data);
            println!("\x1b[35m[dm ← {}...]\x1b[0m {}", &from[..8], text);
            // Send acknowledgment response
            let _ = response_tx.send(b"received".to_vec());
        }
    });

    println!("\nCommands:");
    println!("  /dm <identity> <message>  - Send direct message (peer must be in DHT)");
    println!("  /peers                    - List known peers");
    println!("  /quit                     - Exit");
    println!("Type anything else to broadcast to the room.\n");

    let stdin = tokio::io::stdin();
    let mut stdin_reader = tokio::io::BufReader::new(stdin).lines();
    let my_id_prefix = &identity[..8];

    while let Some(line) = stdin_reader.next_line().await? {
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        if line == "/quit" {
            println!("Goodbye!");
            break;
        }

        if line == "/peers" {
            let peers_guard = peers.read().await;
            if peers_guard.is_empty() {
                println!("No peers discovered yet. Send messages to the room to discover peers.");
            } else {
                println!("Known peers:");
                for (id_prefix, name) in peers_guard.iter() {
                    println!("  {} ({}...)", name, id_prefix);
                }
            }
            continue;
        }

        if line.starts_with("/dm ") {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() < 3 {
                println!("Usage: /dm <identity_hex> <message>");
                println!("Example: /dm 5821a288e16c6491... Hello!");
                continue;
            }
            
            let peer_identity = parts[1];
            let message = parts[2];

            if peer_identity.len() != 64 || hex::decode(peer_identity).is_err() {
                println!("Invalid identity. Must be 64 hex characters.");
                continue;
            }

            let dm_payload = format!("{}@{}: {}", args.name, my_id_prefix, message);
            
            match node.send_request(peer_identity, dm_payload.into_bytes()).await {
                Ok(response) => {
                    let response_text = String::from_utf8_lossy(&response);
                    println!("\x1b[33m[dm → {}...]\x1b[0m {} (ack: {})", &peer_identity[..8], message, response_text);
                }
                Err(e) => {
                    eprintln!("\x1b[31m[dm error]\x1b[0m Failed to send: {}", e);
                }
            }
            continue;
        }

        let formatted = format!("{}@{}: {}", args.name, my_id_prefix, line);

        if let Err(e) = node.publish(&room_topic, formatted.as_bytes().to_vec()).await {
            eprintln!("Failed to send message: {}", e);
        } else {
            println!("\x1b[32m[room]\x1b[0m {}", formatted);
        }
    }

    Ok(())
}
