use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint};
use tracing::{debug, info, warn};

use crate::crypto::{generate_ed25519_cert, create_server_config, create_client_config};
use crate::dht::{DhtNode, Key, TelemetrySnapshot, DEFAULT_ALPHA, DEFAULT_K};
use crate::hyparview::{HyParView, HyParViewConfig};
use crate::identity::{EndpointRecord, Identity, Keypair};
use crate::messages::Message;
use crate::plumtree::{PlumTree, PlumTreeConfig, PlumTreeHandler, ReceivedMessage};
use crate::transport::{Contact, SmartSock, UdpRelayForwarder};
use crate::rpc::{self, RpcNode};


pub struct Node {
    keypair: Keypair,
    endpoint: Endpoint,
    smartsock: Arc<SmartSock>,
    contact: Contact,
    dhtnode: DhtNode<RpcNode>,
    rpcnode: RpcNode,
    udp_forwarder_addr: SocketAddr,
    hyparview: HyParView,
    plumtree: PlumTree<RpcNode>,
    plumtree_receiver: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<ReceivedMessage>>>,
    direct_receiver: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<(Identity, Vec<u8>)>>>,
    server_handle: tokio::task::JoinHandle<Result<()>>,
}

impl Node {
    pub async fn bind(addr: &str) -> Result<Self> {
        let keypair = Keypair::generate();
        Self::create(addr, keypair).await
    }

    pub async fn bind_with_keypair(addr: &str, keypair: Keypair) -> Result<Self> {
        Self::create(addr, keypair).await
    }

    async fn create(addr: &str, keypair: Keypair) -> Result<Self> {
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
        
        let contact = Contact {
            identity,
            addr: local_addr.to_string(),
            addrs: vec![],
        };
        
        let rpcnode = RpcNode::with_identity(
            endpoint.clone(),
            contact.clone(),
            client_config,
            identity,
        ).with_smartsock(smartsock.clone());
        
        let dhtnode = DhtNode::new(
            identity,
            contact.clone(),
            rpcnode.clone(),
            DEFAULT_K,
            DEFAULT_ALPHA,
        );
        
        let udp_forwarder = UdpRelayForwarder::with_socket(smartsock.inner_socket().clone());
        smartsock.set_forwarder(udp_forwarder.clone());
        let udp_forwarder_addr = local_addr;
        info!("UDP relay forwarder sharing port {}", local_addr);
        
        let hyparview = HyParView::spawn(identity, HyParViewConfig::default(), Arc::new(rpcnode.clone()));
        
        let (plumtree, plumtree_rx) = PlumTree::spawn(Arc::new(rpcnode.clone()), keypair.clone(), PlumTreeConfig::default());
        let plumtree_receiver = tokio::sync::Mutex::new(Some(plumtree_rx));
        
        hyparview.set_neighbor_callback(Arc::new(plumtree.clone())).await;
        
        let server_handle = {
            let endpoint = endpoint.clone();
            let dhtnode = dhtnode.clone();
            let udp_forwarder = udp_forwarder.clone();
            let smartsock_for_server = Some(smartsock.clone());
            let plumtree_handler: Arc<dyn PlumTreeHandler + Send + Sync> = Arc::new(plumtree.clone());
            let hyparview_for_server = hyparview.clone();
            
            let (direct_tx, direct_rx) = tokio::sync::mpsc::channel::<(Identity, Vec<u8>)>(256);
            let direct_receiver = tokio::sync::Mutex::new(Some(direct_rx));
            
            let server_task = tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let node = dhtnode.clone();
                    let plumtree = Some(plumtree_handler.clone());
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
            dhtnode,
            rpcnode,
            udp_forwarder_addr,
            hyparview,
            plumtree,
            plumtree_receiver,
            direct_receiver: server_handle.1,
            server_handle: server_handle.0,
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
        self.dhtnode.put(value).await
    }
    
    pub async fn put_at(&self, key: Key, value: Vec<u8>) -> Result<()> {
        self.dhtnode.put_at(key, value).await
    }
    
    pub async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.dhtnode.get(key).await
    }
    
    pub async fn publish_address(&self, addresses: Vec<String>) -> Result<()> {
        self.dhtnode.publish_address(&self.keypair, addresses).await
    }
    
    pub async fn publish_address_with_relays(
        &self,
        addresses: Vec<String>,
        relays: Vec<Contact>,
    ) -> Result<()> {
        self.dhtnode
            .republish_on_network_change(&self.keypair, addresses, relays)
            .await
    }
    
    pub async fn relay_endpoint(&self) -> Option<Contact> {
        let forwarder_addr = self.udp_forwarder_addr;
        let local_addr = self.endpoint.local_addr().ok()?;
        
        let relay_addr = self.rpcnode.public_addr().await
            .map(|public| SocketAddr::new(public.ip(), forwarder_addr.port()))
            .unwrap_or(forwarder_addr);
        
        Some(Contact {
            identity: self.keypair.identity(),
            addr: relay_addr.to_string(),
            addrs: vec![local_addr.to_string()],
        })
    }
    
    pub async fn resolve_peer(&self, peer_id: &Identity) -> Result<Option<EndpointRecord>> {
        self.dhtnode.resolve_peer(peer_id).await
    }
    
    pub async fn find_peers(&self, target: Identity) -> Result<Vec<Contact>> {
        self.dhtnode.iterative_find_node(target).await
    }
    
    pub async fn add_peer(&self, endpoint: Contact) {
        self.rpcnode.cache_contact(&endpoint).await;
        self.dhtnode.observe_contact(endpoint).await
    }
    
    pub async fn bootstrap(&self, identity: &str, addr: &str) -> Result<()> {
        let peer_identity = Identity::from_hex(identity)
            .context("invalid identity: must be 64 hex characters")?;
        
        let contact = Contact {
            identity: peer_identity,
            addr: addr.to_string(),
            addrs: vec![],
        };
        
        self.rpcnode.cache_contact(&contact).await;
        self.dhtnode.observe_contact(contact.clone()).await;
        
        self.hyparview.request_join(peer_identity).await;
        
        self.rpcnode.discover_public_addr(&contact).await;
        
        let self_identity = self.keypair.identity();
        self.dhtnode.iterative_find_node(self_identity).await?;
        
        Ok(())
    }
    
    
    pub async fn connect(&self, identity: &str, addr: &str) -> Result<Connection> {
        let peer_identity = Identity::from_hex(identity)
            .context("invalid identity: must be 64 hex characters")?;
        
        let conn = self.rpcnode.connect_to_peer(&peer_identity, &[addr.to_string()]).await?;
        Ok(conn)
    }
    
    pub async fn connect_peer(&self, identity: &str) -> Result<Connection> {
        let peer_identity = Identity::from_hex(identity)
            .context("invalid identity: must be 64 hex characters")?;
        
        let (record, path_nodes) = self.dhtnode.resolve_peer_with_path(&peer_identity).await?;
        let record = record.context("peer not found in DHT")?;
        
        debug!(
            peer = %identity,
            addrs = ?record.addrs,
            path_nodes = path_nodes.len(),
            "resolved peer endpoint, attempting smartconnect"
        );
        
        let conn = self.rpcnode.smartconnect(&record, path_nodes).await?;
        Ok(conn)
    }
    
    pub async fn send_direct(&self, identity: &str, data: Vec<u8>) -> Result<()> {
        let peer_identity = Identity::from_hex(identity)
            .context("invalid identity: must be 64 hex characters")?;
        
        let record = self.dhtnode.resolve_peer(&peer_identity).await?
            .context("peer not found in DHT")?;
        
        let contact = Contact {
            identity: peer_identity,
            addr: record.addrs.first().cloned().unwrap_or_default(),
            addrs: record.addrs.clone(),
        };
        
        self.rpcnode.send_direct(&contact, self.keypair.identity(), data).await
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
        self.rpcnode.public_addr().await
    }
    
    
    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        self.plumtree.subscribe(topic).await
    }
    
    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        self.plumtree.publish(topic, data).await?;
        Ok(())
    }
    
    pub async fn unsubscribe(&self, topic: &str) -> Result<()> {
        self.plumtree.unsubscribe(topic).await?;
        Ok(())
    }
    
    pub async fn subscriptions(&self) -> Result<Vec<String>> {
        Ok(self.plumtree.subscriptions().await)
    }
    
    pub async fn messages(&self) -> Result<tokio::sync::mpsc::Receiver<Message>> {
        let mut guard = self.plumtree_receiver.lock().await;
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
    
    pub fn is_running(&self) -> bool {
        !self.server_handle.is_finished()
    }
    
    pub async fn shutdown(&self) {
        self.hyparview.quit().await;
        self.plumtree.quit().await;
        self.dhtnode.quit().await;
        self.server_handle.abort();
    }
    
    
    pub async fn telemetry(&self) -> TelemetrySnapshot {
        self.dhtnode.telemetry_snapshot().await
    }
}
