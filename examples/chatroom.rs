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

type PeerRegistry = Arc<RwLock<HashMap<String, (String, String)>>>;

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
    println!("║ Bootstrap string for other peers:                              ║");
    println!("║ {}/{} ║", local_addr, &identity[..32]);
    println!("║ ...{} ║", &identity[32..]);
    println!("╚════════════════════════════════════════════════════════════════╝");

    if let Some(bootstrap_str) = &args.bootstrap {
        let (addr, peer_identity) = parse_bootstrap(bootstrap_str)?;
        println!("\nBootstrapping from {}...", addr);
        match node.bootstrap(&peer_identity, &addr.to_string()).await {
            Ok(()) => println!("Bootstrap successful!"),
            Err(e) => eprintln!("Bootstrap failed: {}", e),
        }
    }

    let topic = format!("chat/{}", args.room);
    node.subscribe(&topic).await?;
    println!("\nSubscribed to room: {}", args.room);

    let mut rx = node.messages().await?;

    let room_filter = args.room.clone();
    let my_name = args.name.clone();
    let my_identity = identity.clone();
    let peers_for_rx = peers.clone();

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if msg.topic == format!("chat/{}", room_filter) {
                let text = String::from_utf8_lossy(&msg.data);
                
                if let Some((name_id, _)) = text.split_once(": ") {
                    if let Some((name, id_prefix)) = name_id.split_once('@') {
                        if !my_identity.starts_with(id_prefix) {
                            let mut peers = peers_for_rx.write().await;
                            if !peers.contains_key(id_prefix) {
                                peers.insert(id_prefix.to_string(), (name.to_string(), String::new()));
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

    let node_for_dm = node.clone();
    tokio::spawn(async move {
        accept_direct_messages(node_for_dm).await;
    });

    println!("\nCommands:");
    println!("  /dm <identity> <addr> <message>  - Send direct message");
    println!("  /peers                           - List known peers");
    println!("  /quit                            - Exit");
    println!("Type anything else to broadcast to the room.\n");

    let stdin = tokio::io::stdin();
    let mut stdin_reader = tokio::io::BufReader::new(stdin).lines();
    let my_id_prefix = &identity[..8]; // Short prefix for display

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
                for (id_prefix, (name, addr)) in peers_guard.iter() {
                    if addr.is_empty() {
                        println!("  {} ({}...) - address unknown", name, id_prefix);
                    } else {
                        println!("  {} ({}...) @ {}", name, id_prefix, addr);
                    }
                }
            }
            continue;
        }

        if line.starts_with("/dm ") {
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 4 {
                println!("Usage: /dm <identity_hex> <addr:port> <message>");
                println!("Example: /dm 5821a288e16c6491... 192.168.1.100:9000 Hello!");
                continue;
            }
            
            let peer_identity = parts[1];
            let peer_addr = parts[2];
            let message = parts[3];

            if hex::decode(peer_identity).is_err() || peer_identity.len() != 64 {
                println!("Invalid identity. Must be 64 hex characters.");
                continue;
            }

            println!("\x1b[33m[dm → {}...]\x1b[0m Connecting...", &peer_identity[..8]);
            
            match send_direct_message(&node, peer_identity, peer_addr, &args.name, message).await {
                Ok(()) => {
                    println!("\x1b[33m[dm → {}...]\x1b[0m {}: {}", 
                             &peer_identity[..8], args.name, message);
                }
                Err(e) => {
                    eprintln!("\x1b[31m[dm error]\x1b[0m Failed to send: {}", e);
                }
            }
            continue;
        }

        let formatted = format!("{}@{}: {}", args.name, my_id_prefix, line);

        if let Err(e) = node.publish(&topic, formatted.as_bytes().to_vec()).await {
            eprintln!("Failed to send message: {}", e);
        } else {
            println!("\x1b[32m[room]\x1b[0m {}", formatted);
        }
    }

    Ok(())
}

async fn send_direct_message(
    node: &Node,
    peer_identity: &str,
    peer_addr: &str,
    my_name: &str,
    message: &str,
) -> Result<()> {
    let conn = node.connect(peer_identity, peer_addr).await
        .context("failed to connect to peer")?;

    let (mut send, mut recv) = conn.open_bi().await
        .context("failed to open stream")?;

    let dm_payload = format!("DM:{}:{}", my_name, message);
    let len = dm_payload.len() as u32;
    
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(dm_payload.as_bytes()).await?;
    send.finish()?;

    let mut ack = [0u8; 4];
    let _ = recv.read_exact(&mut ack).await;

    Ok(())
}

async fn accept_direct_messages(node: Arc<Node>) {
    let endpoint = node.quic_endpoint().clone();
    
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let mut len_buf = [0u8; 4];
                        if recv.read_exact(&mut len_buf).await.is_ok() {
                            let len = u32::from_be_bytes(len_buf) as usize;
                            
                            if len > 0 && len < 65536 {
                                let mut buf = vec![0u8; len];
                                if recv.read_exact(&mut buf).await.is_ok() {
                                    if let Ok(payload) = String::from_utf8(buf) {
                                        if let Some(rest) = payload.strip_prefix("DM:") {
                                            if let Some((sender, msg)) = rest.split_once(':') {
                                                println!("\x1b[35m[dm ← {}]\x1b[0m {}", sender, msg);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        let _ = send.write_all(&[0u8; 4]).await;
                        let _ = send.finish();
                    }
                }
                Err(_) => {}
            }
        });
    }
}
