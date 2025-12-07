use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint};
use tracing::{debug, info, warn};

use crate::crypto::{generate_ed25519_cert, create_server_config, create_client_config};
use crate::dht::{Dht, Key, TelemetrySnapshot, DEFAULT_ALPHA, DEFAULT_K};
use crate::hyparview::{HyParView, HyParViewConfig};
use crate::identity::{EndpointRecord, Identity, Keypair};
use crate::messages::Message;
use crate::plumtree::{PlumTree, PlumTreeConfig, PlumTreeHandler, ReceivedMessage};
use crate::ratelimit::ConnectionRateLimiter;
use crate::transport::{Contact, SmartSock, UdpRelayForwarder};
use crate::rpc::{self, RpcNode};


pub struct Node {
    keypair: Keypair,
    endpoint: Endpoint,
    smartsock: Arc<SmartSock>,
    contact: Contact,
    dht: Dht<RpcNode>,
    network: RpcNode,
    rate_limiter: Arc<ConnectionRateLimiter>,
    #[allow(dead_code)]
    udp_forwarder: Arc<UdpRelayForwarder>,
    udp_forwarder_addr: SocketAddr,
    hyparview: Arc<HyParView<RpcNode>>,
    plumtree: Option<Arc<PlumTree<RpcNode>>>,
    plumtree_receiver: Option<tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<ReceivedMessage>>>>,
    direct_receiver: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<(Identity, Vec<u8>)>>>,
    server_handle: tokio::task::JoinHandle<Result<()>>,
    heartbeat_handle: Option<tokio::task::JoinHandle<()>>,
    probe_handle: tokio::task::JoinHandle<()>,
}

impl Node {
    pub async fn bind(addr: &str) -> Result<Self> {
        let keypair = Keypair::generate();
        Self::create(addr, keypair, true).await
    }

    pub async fn bind_with_keypair(addr: &str, keypair: Keypair) -> Result<Self> {
        Self::create(addr, keypair, true).await
    }

    async fn create(addr: &str, keypair: Keypair, enable_plumtree: bool) -> Result<Self> {
        let addr: SocketAddr = addr.parse()
            .context("invalid socket address")?;
        
        let identity = keypair.identity();
        
        let (server_certs, server_key) = generate_ed25519_cert(&keypair)?;
        let (client_certs, client_key) = generate_ed25519_cert(&keypair)?;
        
        let server_config = create_server_config(server_certs, server_key)?;
        let client_config = create_client_config(client_certs, client_key)?;
        
        let (endpoint, smartsock) = SmartSock::bind_endpoint(addr, server_config)
            .await
            .context("failed to bind SmartSock endpoint")?;
        let local_addr = endpoint.local_addr()?;
        
        let probe_handle = smartsock.spawn_probe_loop();
        debug!("SmartSock probe loop started");
        
        let contact = Contact {
            identity,
            addr: local_addr.to_string(),
            addrs: vec![],
        };
        
        let network = RpcNode::with_identity(
            endpoint.clone(),
            contact.clone(),
            client_config,
            identity,
        ).with_smartsock(smartsock.clone());
        
        let dht = Dht::new(
            identity,
            contact.clone(),
            network.clone(),
            DEFAULT_K,
            DEFAULT_ALPHA,
        );
        
        let rate_limiter = Arc::new(ConnectionRateLimiter::new());
        
        let udp_forwarder = Arc::new(UdpRelayForwarder::with_socket(smartsock.inner_socket().clone()));
        let udp_forwarder_addr = local_addr;
        info!("UDP relay forwarder sharing port {}", local_addr);
        
        let hyparview = Arc::new(
            HyParView::new(identity, HyParViewConfig::default(), Arc::new(network.clone()))
        );
        
        let (plumtree, plumtree_receiver) = if enable_plumtree {
            let mut plumtree = PlumTree::new(Arc::new(network.clone()), keypair.clone(), PlumTreeConfig::default());
            let receiver = plumtree.take_message_receiver();
            let plumtree = Arc::new(plumtree);
            
            hyparview.set_neighbor_callback(plumtree.clone()).await;
            
            (
                Some(plumtree),
                Some(tokio::sync::Mutex::new(receiver)),
            )
        } else {
            (None, None)
        };
        
        hyparview.spawn_shuffle_loop();
        
        let heartbeat_handle = if let Some(ref pt) = plumtree {
            let pt_clone = pt.clone();
            Some(tokio::spawn(async move {
                pt_clone.run_heartbeat().await;
            }))
        } else {
            None
        };
        
        let server_handle = {
            let endpoint = endpoint.clone();
            let dht = dht.clone();
            let rate_limiter = rate_limiter.clone();
            let udp_forwarder = udp_forwarder.clone();
            let smartsock_for_server = Some(smartsock.clone());
            let plumtree_handler: Option<Arc<dyn PlumTreeHandler + Send + Sync>> = 
                plumtree.clone().map(|p| p as Arc<dyn PlumTreeHandler + Send + Sync>);
            let hyparview_for_server = hyparview.clone();
            
            let (direct_tx, direct_rx) = tokio::sync::mpsc::channel::<(Identity, Vec<u8>)>(256);
            let direct_receiver = tokio::sync::Mutex::new(Some(direct_rx));
            
            let server_task = tokio::spawn(async move {
                info!(
                    addr = ?udp_forwarder_addr,
                    "starting UDP relay forwarder"
                );
                udp_forwarder.clone().spawn();

                while let Some(incoming) = endpoint.accept().await {
                    let remote_addr = incoming.remote_address();
                    if !rate_limiter.allow(remote_addr.ip()).await {
                        warn!(remote = %remote_addr, "rate limiting: rejecting connection");
                        continue;
                    }

                    let node = dht.clone();
                    let plumtree = plumtree_handler.clone();
                    let forwarder = Some(udp_forwarder.clone());
                    let forwarder_addr = Some(udp_forwarder_addr);
                    let ss = smartsock_for_server.clone();
                    let hv = hyparview_for_server.clone();
                    let direct_sender = Some(direct_tx.clone());
                    tokio::spawn(async move {
                        if let Err(e) =
                            rpc::handle_connection(node, plumtree, forwarder, forwarder_addr, ss, incoming, hv, direct_sender).await
                        {
                            warn!("connection error: {:?}", e);
                        }
                    });
                }
                Ok(())
            });
            
            (server_task, direct_receiver)
        };
        
        info!("Node {}/{}", local_addr, hex::encode(identity));
        
        Ok(Self {
            keypair,
            endpoint,
            smartsock,
            contact,
            dht,
            network,
            rate_limiter,
            udp_forwarder,
            udp_forwarder_addr,
            hyparview,
            plumtree,
            plumtree_receiver,
            direct_receiver: server_handle.1,
            server_handle: server_handle.0,
            heartbeat_handle,
            probe_handle,
        })
    }
    
    
    pub fn identity(&self) -> String {
        hex::encode(self.keypair.identity())
    }
    
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr()
            .context("failed to get local address")
    }
    
    
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
    
    pub fn peer_endpoint(&self) -> &Contact {
        &self.contact
    }
    
    pub fn quic_endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    
    pub fn smartsock(&self) -> &Arc<SmartSock> {
        &self.smartsock
    }

    
    pub async fn put(&self, value: Vec<u8>) -> Result<Key> {
        self.dht.put(value).await
    }
    
    pub async fn put_at(&self, key: Key, value: Vec<u8>) -> Result<()> {
        self.dht.put_at(key, value).await
    }
    
    pub async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.dht.get(key).await
    }
    
    pub async fn publish_address(&self, addresses: Vec<String>) -> Result<()> {
        self.dht.publish_address(&self.keypair, addresses).await
    }
    
    pub async fn publish_address_with_relays(
        &self,
        addresses: Vec<String>,
        relays: Vec<Contact>,
    ) -> Result<()> {
        self.dht
            .republish_on_network_change(&self.keypair, addresses, relays)
            .await
    }
    
    pub fn is_relay_capable(&self) -> bool {
        true    }
    
    pub async fn relay_endpoint(&self) -> Option<Contact> {
        let forwarder_addr = self.udp_forwarder_addr;
        let local_addr = self.endpoint.local_addr().ok()?;
        
        let relay_addr = self.network.public_addr().await
            .map(|public| SocketAddr::new(public.ip(), forwarder_addr.port()))
            .unwrap_or(forwarder_addr);
        
        Some(Contact {
            identity: self.keypair.identity(),
            addr: relay_addr.to_string(),
            addrs: vec![local_addr.to_string()],
        })
    }
    
    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<EndpointRecord>> {
        self.dht.resolve_peer(peer_id).await
    }
    
    pub async fn find_peers(&self, target: Identity) -> Result<Vec<Contact>> {
        self.dht.iterative_find_node(target).await
    }
    
    pub async fn add_peer(&self, endpoint: Contact) {
        self.network.cache_contact(&endpoint).await;
        self.dht.observe_contact(endpoint).await
    }
    
    pub async fn bootstrap(&self, identity: &str, addr: &str) -> Result<()> {
        let identity_bytes = hex::decode(identity)
            .context("invalid identity: must be 64 hex characters")?;
        if identity_bytes.len() != 32 {
            anyhow::bail!("invalid identity: must be 32 bytes (64 hex chars)");
        }
        let peer_identity = Identity::from_bytes(identity_bytes.try_into().unwrap());
        
        let contact = Contact {
            identity: peer_identity,
            addr: addr.to_string(),
            addrs: vec![],
        };
        
        self.network.cache_contact(&contact).await;
        self.dht.observe_contact(contact.clone()).await;
        
        self.hyparview.request_join(peer_identity).await;
        
        self.network.detect_nat(&[contact]).await;
        
        let self_identity = self.keypair.identity();
        self.dht.iterative_find_node(self_identity).await?;
        
        Ok(())
    }
    
    
    pub async fn connect(&self, identity: &str, addr: &str) -> Result<Connection> {
        let identity_bytes = hex::decode(identity)
            .context("invalid identity: must be 64 hex characters")?;
        if identity_bytes.len() != 32 {
            anyhow::bail!("invalid identity: must be 32 bytes (64 hex chars)");
        }
        let peer_identity = Identity::from_bytes(identity_bytes.try_into().unwrap());
        
        let record = EndpointRecord {
            identity: peer_identity,
            addrs: vec![addr.to_string()],
            relays: vec![],
            timestamp: crate::identity::now_ms(),
            signature: vec![],        };
        
        let conn = self.network.smartconnect(&record).await?;
        Ok(conn)
    }
    
    pub async fn connect_peer(&self, identity: &str) -> Result<Connection> {
        let identity_bytes = hex::decode(identity)
            .context("invalid identity: must be 64 hex characters")?;
        if identity_bytes.len() != 32 {
            anyhow::bail!("invalid identity: must be 32 bytes (64 hex chars)");
        }
        let peer_identity = Identity::from_bytes(identity_bytes.try_into().unwrap());
        
        let record = self.dht.resolve_peer(&peer_identity).await?
            .context("peer not found in DHT")?;
        
        debug!(
            peer = %identity,
            addrs = ?record.addrs,
            relays = record.relays.len(),
            "resolved peer endpoint, attempting smartconnect"
        );
        
        let conn = self.network.smartconnect(&record).await?;
        Ok(conn)
    }
    
    pub async fn send_direct(&self, identity: &str, data: Vec<u8>) -> Result<()> {
        let identity_bytes = hex::decode(identity)
            .context("invalid identity: must be 64 hex characters")?;
        if identity_bytes.len() != 32 {
            anyhow::bail!("invalid identity: must be 32 bytes (64 hex chars)");
        }
        let peer_identity = Identity::from_bytes(identity_bytes.try_into().unwrap());
        
        let record = self.dht.resolve_peer(&peer_identity).await?
            .context("peer not found in DHT")?;
        
        let contact = Contact {
            identity: peer_identity,
            addr: record.addrs.first().cloned().unwrap_or_default(),
            addrs: record.addrs.clone(),
        };
        
        self.network.send_direct(&contact, self.keypair.identity(), data).await
    }
    
    pub async fn direct_messages(&self) -> Result<tokio::sync::mpsc::Receiver<(String, Vec<u8>)>> {
        let mut guard = self.direct_receiver.lock().await;
        let internal_rx = guard.take().context("direct message receiver already taken")?;
        
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        tokio::spawn(async move {
            let mut internal_rx = internal_rx;
            while let Some((from, data)) = internal_rx.recv().await {
                let from_hex = hex::encode(from.as_bytes());
                if tx.send((from_hex, data)).await.is_err() {
                    break;
                }
            }
        });
        
        Ok(rx)
    }
    
    pub async fn public_addr(&self) -> Option<SocketAddr> {
        self.network.public_addr().await
    }
    
    
    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        let plumtree = self.plumtree.as_ref()
            .context("plumtree not enabled")?;
        plumtree.subscribe(topic).await
    }
    
    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        let plumtree = self.plumtree.as_ref()
            .context("plumtree not enabled")?;
        plumtree.publish(topic, data).await?;
        Ok(())
    }
    
    pub async fn unsubscribe(&self, topic: &str) -> Result<()> {
        let plumtree = self.plumtree.as_ref()
            .context("plumtree not enabled")?;
        plumtree.unsubscribe(topic).await?;
        Ok(())
    }
    
    pub async fn subscriptions(&self) -> Result<Vec<String>> {
        let plumtree = self.plumtree.as_ref()
            .context("plumtree not enabled")?;
        Ok(plumtree.subscriptions().await)
    }
    
    pub async fn messages(&self) -> Result<tokio::sync::mpsc::Receiver<Message>> {
        let receiver_mutex = self.plumtree_receiver.as_ref()
            .context("plumtree not enabled")?;
        let mut guard = receiver_mutex.lock().await;
        let internal_rx = guard.take().context("message receiver already taken")?;
        
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        tokio::spawn(async move {
            let mut internal_rx = internal_rx;
            while let Some(msg) = internal_rx.recv().await {
                let public_msg = Message {
                    topic: msg.topic,
                    from: hex::encode(msg.source.as_bytes()),
                    data: msg.data,
                };
                if tx.send(public_msg).await.is_err() {
                    break;
                }
            }
        });
        
        Ok(rx)
    }
    
    pub fn has_plumtree(&self) -> bool {
        self.plumtree.is_some()
    }
    
    pub fn is_running(&self) -> bool {
        !self.server_handle.is_finished()
    }
    
    pub async fn shutdown(&self) {
        self.hyparview.quit().await;
        
        if let Some(ref handle) = self.heartbeat_handle {
            handle.abort();
        }
        
        self.probe_handle.abort();
        
        self.server_handle.abort();
    }
    
    pub async fn connection_stats(&self) -> crate::ratelimit::RateLimitStats {
        self.rate_limiter.stats().await
    }
    
    
    pub async fn telemetry(&self) -> TelemetrySnapshot {
        self.dht.telemetry_snapshot().await
    }
}
