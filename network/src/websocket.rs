use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Instant},
};

use futures_channel::mpsc::{unbounded, UnboundedSender};
use futures_util::{future, pin_mut, stream::TryStreamExt, SinkExt, StreamExt};
use serde::Serialize;
use serde_json::Value;
use tokio::{net::{TcpListener, TcpStream}, time::Sleep};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;
use log::{debug, info, warn, error};
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};

type Tx = UnboundedSender<Message>;
type PeerMap = Arc<RwLock<HashMap<SocketAddr, (Tx, Instant)>>>;

const CHANNEL_CAPACITY: usize = 1000;
// 交易数据结构
#[derive(Debug)]
struct Transaction {
    id: String,
    amount: f64,
    recipient: String,
}

// 区块数据结构
#[derive(Debug)]
struct Block {
    hash: String,
    transactions: Vec<Transaction>,
    timestamp: u64,
}

// 消息处理 trait
#[async_trait::async_trait]
pub trait RequestHandler: Clone + Copy + Send + Sync + 'static {
    async fn process_txn(&self, txn: String) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_block(&self, block_hash: String) -> Result<String, Box<dyn std::error::Error>>;
}

pub struct WebSocketServer<Handler: RequestHandler> {
    address: SocketAddr,
    handler: Handler,
    peers: PeerMap,
    block_rx: Receiver<String>,
}

impl<Handler: RequestHandler> WebSocketServer<Handler> {
    pub fn new(address: SocketAddr, handler: Handler, block_rx: Receiver<String>) -> Self {
        info!("new websocketserver");
        let peers = PeerMap::new(RwLock::new(HashMap::new()));
        Self { address, handler, peers, block_rx}
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.address).await?;
        info!("Listening on {}", self.address);

        loop {
            tokio::select! {
                Ok((stream, addr)) = listener.accept() => {
                    let peers = self.peers.clone();
                    let handler = self.handler.clone();
                    tokio::spawn(Self::handle_connection(peers, stream, addr, handler));
                }
                Some(block_hash) = self.block_rx.recv()  => {
                    let peers = self.peers.read().unwrap();
                    let msg = Message::Text(format!(r#"{{"type": "block_hash", "hash": "{}"}}"#, block_hash).into());
                    for (_, (tx, _)) in peers.iter() {
                        if let Err(e) = tx.unbounded_send(msg.clone()) {
                            warn!("Failed to send block_hash to a peer: {}", e);
                        }
                    }
                    info!("Broadcasted block_hash {} to all {} clients", block_hash, peers.len());
                }
            }
        }
    }

    async fn heartbeat_task(&self, peers: PeerMap) {
        let heartbeat_interval = Duration::from_secs(5);
        let timeout_duration = Duration::from_secs(10);

        loop {
            tokio::time::sleep(heartbeat_interval).await;
            let mut peers = peers.write().unwrap();
            let mut to_remove = Vec::new();

            let ping_msg = tokio_tungstenite::tungstenite::protocol::Message::Text(
                r#"{"type": "ping"}"#.to_string().into()
            );

            for (addr, (tx, last_response)) in peers.iter_mut() {
                if let Err(e) = tx.unbounded_send(ping_msg.clone()) {
                    warn!("Failed to send ping to {}: {}", addr, e);
                    to_remove.push(*addr);
                    continue;
                }
                if last_response.elapsed() > timeout_duration {
                    info!("Client {} timed out, removing from peers", addr);
                    to_remove.push(*addr);
                }
            }

            for addr in to_remove {
                peers.remove(&addr);
            }
        }
    }

    async fn handle_connection(
        peers: PeerMap,
        raw_stream: TcpStream,
        addr: SocketAddr,
        handler: Handler
    ) {
        let ws_stream = tokio_tungstenite::accept_async(raw_stream)
            .await
            .map_err(|e| {
                error!("WebSocket handshake failed for {}: {}", addr, e);
                e
            }).expect("");
        let (tx, rx) = unbounded();
        peers.write().unwrap().insert(addr, (tx.clone(), Instant::now()));

        let (mut outgoing, incoming) = ws_stream.split();
        
        info!("addr:{:?}", addr);
        let broadcast_incoming = incoming.try_for_each(|msg| async move {
            let txt = match msg {
                Message::Text(text) => text,
                _ => {
                    debug!("Received non-text message from {}: {:?}", addr, msg);
                    return Ok(());
                }
            };

            info!("txt: {:?}", txt);

            if let Ok(json) = serde_json::from_str::<Value>(&txt) {
                info!("json:{:?}", json);
                if json.get("type").and_then(|t| t.as_str()) == Some("transaction") {
                    info!("txn: {:?}", json.get("txn"));
                    if let Some(txn) = json.get("txn").and_then(|h| h.as_str())  {
                        if let Err(e) = handler.process_txn(txn.to_string()).await {
                            warn!("Failed to process transaction from {}: {}", addr, e);
                        }
                    }
                } else if json.get("type").and_then(|t| t.as_str()) == Some("get_block") {
                    if let Some(hash) = json.get("hash").and_then(|h| h.as_str()) {
                        match handler.get_block(hash.to_string()).await {
                            Ok(block) => {
                                let msg = Message::Text("123".into());
                            }
                            Err(e) => {
                                warn!("Failed to get block for {}: {}", addr, e);
                            }
                        }
                    }
                }
            }
            Ok(())
        });

        let receive_from_others = rx.map(Ok).forward(&mut outgoing);

        pin_mut!(broadcast_incoming, receive_from_others);
        future::select(broadcast_incoming, receive_from_others).await;

        peers.write().unwrap().remove(&addr);
    }
}

#[derive(Clone, Copy)]
pub struct DummyHandler;

#[async_trait::async_trait]
impl RequestHandler for DummyHandler {
    async fn process_txn(&self, txn: String) -> Result<(), Box<dyn std::error::Error>> {
        info!("Processed transaction: {:?}", txn);
        Ok(())
    }

    async fn get_block(&self, block_hash: String) -> Result<String, Box<dyn std::error::Error>> {
        // 模拟返回区块内容
        Ok("1213".to_string())
    }
}

#[tokio::test]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::new()
         .filter_level(log::LevelFilter::Debug)
        .target(env_logger::Target::Stdout)
        .init();       info!("test main");
    let (block_tx, block_rx) = channel(CHANNEL_CAPACITY);
    let mut server = WebSocketServer::new(format!("127.0.0.1:8080").parse().unwrap(), DummyHandler, block_rx);
    let server_handle = tokio::spawn(async move { server.run().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(500)).await;
    loop  {
        block_tx.send("12312".to_string()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1000)).await; // 等待服务器启动
    }
    server_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_server_connection() -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:8080").parse().unwrap();
    let server = tokio::spawn(async move {
        let (block_tx, block_rx) = channel(CHANNEL_CAPACITY);
        block_tx.send("12312".to_string());
        let mut server = WebSocketServer::new(addr, DummyHandler, block_rx);
        server.run().await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await; // 等待服务器启动

    // 模拟客户端连接
    let (mut ws_stream, _) = tokio_tungstenite::connect_async(addr.to_string()).await?;
    ws_stream
        .send(Message::Text(r#"{"type": "transaction", "id": "tx1", "amount": 100.0, "recipient": "user1"}"#.to_string().into()))
        .await?;
    ws_stream
        .send(Message::Text(r#"{"type": "get_block", "hash": "block_0"}"#.to_string().into()))
        .await?;

    // 接收响应（可选）
    while let Some(msg) = ws_stream.next().await {
        if let Ok(Message::Text(text)) = msg {
            info!("Received: {}", text);
        }
    }

    server.abort(); // 终止服务器任务
    Ok(())
}