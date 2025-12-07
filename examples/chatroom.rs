use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use quinn::{Connection, Endpoint};
use tokio::io::AsyncBufReadExt;
use tokio::sync::Mutex;
use tracing::warn;

use corium::{
    Contact, Identity, Keypair, Node,
    advanced::{create_client_config, generate_ed25519_cert, hash_content},
};

/// CLI arguments for the chatroom example.
#[derive(Parser, Debug)]
struct ChatArgs {
    /// Nickname announced in the chatroom
    #[arg(long, default_value = "anon")]
    name: String,
    /// Room label that is embedded in each message
    #[arg(long, default_value = "lobby")]
    room: String,
    /// Socket address peers to notify directly (host:port format)
    #[arg(long = "peer")]
    peers: Vec<String>,
    /// Port to bind to (0 for random)
    #[arg(long, default_value = "0")]
    port: u16,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ChatMessage {
    room: String,
    author: String,
    body: String,
    timestamp: u64,
}

/// Handle an inbound chat connection:
/// - Read one framed ChatMessage
/// - Print it
async fn handle_chat_connection(connection: Connection) -> Result<()> {
    // Accept a single bidi stream for the chat message.
    let (mut send, mut recv) = connection.accept_bi().await?;

    // Simple length-prefixed frame:
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;

    let msg: ChatMessage = serde_json::from_slice(&buf).context("invalid ChatMessage JSON")?;

    println!("[{}] {}: {}", msg.room, msg.author, msg.body,);

    // Optionally ack; here we just send an empty frame as an ACK.
    send.write_all(&0u32.to_be_bytes()).await?;
    send.finish()?;
    Ok(())
}

/// Accept chat connections on a separate task
async fn run_chat_server(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_chat_connection(conn).await {
                        warn!("chat connection error: {:?}", e);
                    }
                }
                Err(e) => {
                    warn!("failed to accept chat connection: {:?}", e);
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = ChatArgs::parse();

    // Generate Ed25519 keypair for node identity
    let keypair = Keypair::generate();
    let identity = keypair.identity();

    // Bind full Corium node (facade handles server/DHT setup)
    let bind_addr = format!("0.0.0.0:{}", args.port);
    let node = Node::bind(&bind_addr, keypair.clone()).await?;
    let endpoint = node.endpoint().clone();
    let local_addr = endpoint.local_addr()?;

    // Client config for outbound chat connects (identity-pinned)
    let (client_certs, client_key) = generate_ed25519_cert(&keypair)?;
    let client_config = create_client_config(client_certs, client_key)?;

    println!("Chatroom node ready");
    println!("  Nickname        : {}", args.name);
    println!("  Room            : {}", args.room);
    println!("  Identity (hex)  : {}", hex::encode(identity.as_bytes()));
    println!("  Listening addr  : {local_addr}");
    println!("Share the listening address with peers so they can /add it.");

    let self_contact = node.contact().clone();

    // Start chat server (reusing the same endpoint)
    tokio::spawn(run_chat_server(endpoint.clone()));

    let peer_addrs = parse_initial_peers(args.peers)?;
    let peers = Arc::new(Mutex::new(peer_addrs));

    println!("\nCommands:");
    println!("  /add <host:port>  - add a peer socket address");
    println!("  /peers            - list known peers");
    println!("  /quit             - exit");
    println!("Type anything else to send it to the room.\n");

    run_repl(
        node,
        client_config,
        peers.clone(),
        args.name.clone(),
        args.room.clone(),
        self_contact,
    )
    .await
}
fn parse_initial_peers(raw: Vec<String>) -> Result<Vec<SocketAddr>> {
    raw.into_iter()
        .map(|entry| {
            entry
                .parse()
                .with_context(|| format!("invalid socket address: {}", entry))
        })
        .collect()
}

/// Derive a DHT key for the room to use for peer discovery.
/// This *does not* store anything in the DHT; it only gives us a target
/// for `iterative_find_node`-style queries on the routing table.
fn room_discovery_key(room: &str) -> Identity {
    // Hash the room name and use the result as an Identity for discovery.
    // This allows finding nodes close to the room in the keyspace.
    let key = hash_content(room.as_bytes());
    Identity::from_bytes(key)
}

async fn run_repl(
    node: Node,
    client_config: quinn::ClientConfig,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    nickname: String,
    room: String,
    _self_contact: Contact,
) -> Result<()> {
    let endpoint = node.endpoint().clone();
    let stdin = tokio::io::stdin();
    let mut stdin_reader = tokio::io::BufReader::new(stdin).lines();

    while let Some(line) = stdin_reader.next_line().await? {
        let line = line.trim().to_string();

        if line.is_empty() {
            continue;
        }

        if let Some(addr_str) = line.strip_prefix("/add ") {
            let addr_str = addr_str.trim();
            match addr_str.parse::<SocketAddr>() {
                Ok(addr) => {
                    peers.lock().await.push(addr);
                    println!("Added peer.");
                }
                Err(err) => {
                    eprintln!("Invalid socket address: {err:?}");
                }
            }
            continue;
        }

        if line == "/peers" {
            let list = peers.lock().await;
            println!("Known peers:");
            for (i, p) in list.iter().enumerate() {
                println!("  [{i}] {p}");
            }
            continue;
        }

        if line == "/quit" {
            println!("Exiting.");
            break;
        }

        // Regular chat message: build ChatMessage.
        let msg = ChatMessage {
            room: room.clone(),
            author: nickname.clone(),
            body: line.clone(),
            timestamp: current_unix_time(),
        };

        // Serialize it once.
        let msg_bytes = serde_json::to_vec(&msg)?;

        // 1. Local peers from CLI + /add.
        let static_peers = peers.lock().await.clone();

        // 2. DHT-based peers: ask the DHT for nodes close to a room-discovery key
        //    via a regular iterative_find_node lookup.
        let discovery_key = room_discovery_key(&room);
        let dynamic_peers = node
            .find_peers(discovery_key)
            .await
            .unwrap_or_default();

        // Merge peers:
        // - From static_peers: SocketAddr
        // - From dynamic_peers: Contact { addr: SocketAddr string }
        let mut all_peer_addrs: Vec<SocketAddr> = static_peers;

        for contact in dynamic_peers {
            if let Ok(addr) = contact.addr.parse::<SocketAddr>() {
                // Avoid duplicates
                if !all_peer_addrs.iter().any(|p| p == &addr) {
                    all_peer_addrs.push(addr);
                }
            }
        }

        if all_peer_addrs.is_empty() {
            println!("No peers to send to (yet).");
            continue;
        }

        // Send the message to every peer directly; no DHT put/get.
        for peer in all_peer_addrs {
            if let Err(err) =
                send_chat_message(&endpoint, &client_config, &peer, &msg_bytes).await
            {
                eprintln!("Failed to send to peer {peer}: {err:?}");
            }
        }
    }

    Ok(())
}

/// Send a ChatMessage (already serialized as `msg_bytes`) directly to a peer.
/// This uses the CHAT_ALPN protocol and a simple length-prefixed frame.
async fn send_chat_message(
    endpoint: &Endpoint,
    client_config: &quinn::ClientConfig,
    peer: &SocketAddr,
    msg_bytes: &[u8],
) -> Result<()> {
    let conn = endpoint
        .connect_with(client_config.clone(), *peer, "corium-chat")
        .context("failed to initiate connection to peer")?
        .await
        .context("failed to connect to peer for chat")?;

    let (mut send, mut recv) = conn.open_bi().await?;

    let len = msg_bytes.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(msg_bytes).await?;
    send.finish()?;

    // Optional: read ACK frame
    let mut ack_len_buf = [0u8; 4];
    if recv.read_exact(&mut ack_len_buf).await.is_ok() {
        // ignore ack body
    }

    Ok(())
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
