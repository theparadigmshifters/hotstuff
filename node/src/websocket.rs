use bincode::{serialize, deserialize};
use circuit::Digest;
use log::{debug, error, info, warn};
use mempool::{SerializedTransaction, TransactionFields};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use store::Store;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio_tungstenite::{
    accept_async, 
    tungstenite::Message as WsMessage
};
use consensus::WebSocketEvent;
use futures::{SinkExt, StreamExt};

use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::{PlaceholderProjectNamePlaceholderField, PlaceholderProjectNamePlaceholderHash};

use std::array::from_fn;
use bytes::Bytes;
use consensus::SyncBlock;


#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Message {
    SubscribeChainUpdate,
    UnsubscribeChainUpdate,
    ChainUpdate(Fields),
    SendTransactions(Vec<Fields>),
    RequestBlocks(Vec<Fields>),
    SyncBlocks(Vec<Fields>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Fields(#[serde(with = "fields_serde")] pub Vec<PlaceholderProjectNamePlaceholderField>);

mod fields_serde {
    use std::array::from_fn;
    use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::{PlaceholderProjectNamePlaceholderField};
    use serde::{Deserialize, Deserializer, Serializer};
    use serde::de::Error;
    
    pub fn serialize<S>(bytes: &Vec<PlaceholderProjectNamePlaceholderField>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<u8> = bytes.iter().flat_map(|v| u64::to_be_bytes((*v).into()).to_vec()).collect();
        let hex_string = hex::encode(bytes);
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PlaceholderProjectNamePlaceholderField>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(Error::custom)?;
        let fields: Vec<PlaceholderProjectNamePlaceholderField> = bytes.chunks(8).map(|v| u64::from_be_bytes(from_fn(|i|v[i])).into()).collect();
        Ok(fields)
    }
}

#[derive(Debug)]
pub enum WebSocketError {
    SerializationError(Box<bincode::ErrorKind>),
    NetworkError(std::io::Error),
    MessageError(String),
}

impl std::fmt::Display for WebSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WebSocketError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            WebSocketError::NetworkError(e) => write!(f, "Network error: {}", e),
            WebSocketError::MessageError(e) => write!(f, "Message error: {}", e),
        }
    }
}

impl std::error::Error for WebSocketError {}

impl From<Box<bincode::ErrorKind>> for WebSocketError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        WebSocketError::SerializationError(error)
    }
}

impl From<std::io::Error> for WebSocketError {
    fn from(error: std::io::Error) -> Self {
        WebSocketError::NetworkError(error)
    }
}

pub struct ClientConnection {
    pub id: String,
    pub sender: mpsc::UnboundedSender<Message>,
    pub subscribed: bool,
}

pub enum ServerMessage {
    NewClient {
        id: String,
        sender: mpsc::UnboundedSender<Message>,
    },
    ClientDisconnected {
        id: String,
    },
    Subscribe {
        client_id: String,
    },
    Unsubscribe {
        client_id: String,
    },
    BroadcastChainUpdate {
        hash: Fields,
    },
    SendSyncBlocks {
        client_id: String,
        sync_blocks: Vec<Fields>,
    },
}

pub struct WebSocketServer {
    store: Store,
    mempool_tx: mpsc::Sender<SerializedTransaction>,
    event_receiver: Option<mpsc::Receiver<WebSocketEvent>>,
    clients: Arc<RwLock<HashMap<String, ClientConnection>>>,
    message_sender: mpsc::UnboundedSender<ServerMessage>,
    message_receiver: Option<mpsc::UnboundedReceiver<ServerMessage>>,
}

impl WebSocketServer {
    pub fn new(store: Store, mempool_tx: mpsc::Sender<SerializedTransaction>, event_receiver: mpsc::Receiver<WebSocketEvent>) -> Self {
        let (message_sender, message_receiver) = mpsc::unbounded_channel();
        Self {
            store,
            mempool_tx,
            event_receiver: Some(event_receiver),
            clients: Arc::new(RwLock::new(HashMap::new())),
            message_sender,
            message_receiver: Some(message_receiver),
        }
    }

    pub async fn start(&mut self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;
        info!("WebSocket server listening on: {}", addr);
        
        let message_receiver = self.message_receiver.take().unwrap();
        let event_receiver = self.event_receiver.take().unwrap();
        let clients = self.clients.clone();
        let clients_for_messages = clients.clone();
        tokio::spawn(async move {
            Self::handle_server_messages(message_receiver, clients_for_messages).await;
        });
        let clients_for_events = clients.clone();
        tokio::spawn(async move {
            Self::handle_websocket_events(event_receiver, clients_for_events).await;
        });
        let mempool_tx = self.mempool_tx.clone();
        let message_sender = self.message_sender.clone();
        
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New connection from: {}", addr);
                    let store_clone = self.store.clone();
                    let mempool_tx_clone = mempool_tx.clone();
                    let message_sender_clone = message_sender.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            stream, 
                            store_clone, 
                            mempool_tx_clone, 
                            message_sender_clone
                        ).await {
                            error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        mut store: Store,
        mempool_tx: mpsc::Sender<SerializedTransaction>,
        message_sender: mpsc::UnboundedSender<ServerMessage>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ws_stream = accept_async(stream).await?;
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        let client_id = uuid::Uuid::new_v4().to_string();
        let (client_tx, mut client_rx) = mpsc::unbounded_channel::<Message>();
        let _ = message_sender.send(ServerMessage::NewClient {
            id: client_id.clone(),
            sender: client_tx.clone(),
        });
        info!("Client {} connected", client_id);

        let client_id_for_receive = client_id.clone();
        let mempool_tx_for_receive = mempool_tx.clone();
        let message_sender_for_receive = message_sender.clone();
        let client_tx_for_receive = client_tx.clone();
        let mut store_for_receive = store.clone();
        
        let receive_task = tokio::spawn(async move {
            while let Some(msg) = ws_receiver.next().await {
                match msg {
                    Ok(WsMessage::Text(text)) => {
                        match serde_json::from_str::<Message>(&text) {
                            Ok(message) => {
                                Self::handle_client_message(
                                    message,
                                    &mut store_for_receive,
                                    &mempool_tx_for_receive,
                                    &message_sender_for_receive,
                                    &client_id_for_receive,
                                    &client_tx_for_receive,
                                ).await;
                            }
                            Err(e) => {
                                error!("Failed to parse message from client {}: {}", client_id_for_receive, e);
                            }
                        }
                    }
                    Ok(WsMessage::Binary(data)) => {
                        match bincode::deserialize::<Message>(&data) {
                            Ok(message) => {
                                Self::handle_client_message(
                                    message,
                                    &mut store_for_receive,
                                    &mempool_tx_for_receive,
                                    &message_sender_for_receive,
                                    &client_id_for_receive,
                                    &client_tx_for_receive,
                                ).await;
                            }
                            Err(e) => {
                                error!("Failed to parse binary message from client {}: {}", client_id_for_receive, e);
                            }
                        }
                    }
                    Ok(WsMessage::Close(_)) => {
                        info!("Client {} disconnected", client_id_for_receive);
                        break;
                    }
                    Err(e) => {
                        error!("WebSocket error for client {}: {}", client_id_for_receive, e);
                        break;
                    }
                    _ => {}
                }
            }
        });
        let client_id_for_send = client_id.clone();
        let send_task = tokio::spawn(async move {
            while let Some(message) = client_rx.recv().await {
                if let Err(e) = ws_sender.send(serde_json::to_string(&message).unwrap().into()).await {
                    error!("Failed to send message to client {}: {}", client_id_for_send, e);
                    break;
                }
            }
        });

        tokio::select! {
            _ = receive_task => {},
            _ = send_task => {},
        }

        let _ = message_sender.send(ServerMessage::ClientDisconnected {
            id: client_id.clone(),
        });
        
        info!("Connection handler for client {} finished", client_id);
        Ok(())
    }

    async fn handle_server_messages(
        mut message_receiver: mpsc::UnboundedReceiver<ServerMessage>,
        clients: Arc<RwLock<HashMap<String, ClientConnection>>>,
    ) {
        while let Some(message) = message_receiver.recv().await {
            match message {
                ServerMessage::NewClient { id, sender } => {
                    let mut clients_guard = clients.write().await;
                    clients_guard.insert(id.clone(), ClientConnection {
                        id: id.clone(),
                        sender,
                        subscribed: false,
                    });
                    debug!("Registered new client: {}", id);
                }
                
                ServerMessage::ClientDisconnected { id } => {
                    let mut clients_guard = clients.write().await;
                    clients_guard.remove(&id);
                    debug!("Removed client: {}", id);
                }
                
                ServerMessage::Subscribe { client_id } => {
                    let mut clients_guard = clients.write().await;
                    if let Some(client) = clients_guard.get_mut(&client_id) {
                        client.subscribed = true;
                        debug!("Client {} subscribed to chain updates", client_id);
                    }
                }
                
                ServerMessage::Unsubscribe { client_id } => {
                    let mut clients_guard = clients.write().await;
                    if let Some(client) = clients_guard.get_mut(&client_id) {
                        client.subscribed = false;
                        debug!("Client {} unsubscribed from chain updates", client_id);
                    }
                }
                
                ServerMessage::BroadcastChainUpdate { hash } => {
                    let clients_guard = clients.read().await;
                    for (_, client) in clients_guard.iter() {
                        if client.subscribed {
                            let chain_update_msg = Message::ChainUpdate(hash.clone());
                            if let Err(e) = client.sender.send(chain_update_msg) {
                                error!("Failed to send chain update to client {}: {}", client.id, e);
                            }
                        }
                    }
                }
                
                ServerMessage::SendSyncBlocks { client_id, sync_blocks } => {
                    let clients_guard = clients.read().await;
                    if let Some(client) = clients_guard.get(&client_id) {
                        let response_msg = Message::SyncBlocks(sync_blocks);
                        if let Err(e) = client.sender.send(response_msg) {
                            error!("Failed to send SyncBlocks to client {}: {}", client_id, e);
                        }
                    } else {
                        warn!("Client {} not found when sending SyncBlocks", client_id);
                    }
                }
            }
        }
    }

    async fn handle_client_message(
        message: Message,
        store: &mut Store,
        mempool_tx: &mpsc::Sender<SerializedTransaction>,
        message_sender: &mpsc::UnboundedSender<ServerMessage>,
        client_id: &str,
        client_tx: &mpsc::UnboundedSender<Message>,
    ) {
        match message {
            Message::SubscribeChainUpdate => {
                debug!("Client {} subscribed to chain updates", client_id);
                let _ = message_sender.send(ServerMessage::Subscribe {
                    client_id: client_id.to_string(),
                });
            }
            
            Message::UnsubscribeChainUpdate => {
                debug!("Client {} unsubscribed from chain updates", client_id);
                let _ = message_sender.send(ServerMessage::Unsubscribe {
                    client_id: client_id.to_string(),
                });
            }
            
            Message::SendTransactions(transaction_fields) => {
                debug!("Received {} transactions from client {}", transaction_fields.len(), client_id);
                for tf in transaction_fields {
                    let tf_fields = TransactionFields(tf.0.into());
                    let serialized_transaction: SerializedTransaction = bincode::serialize(&tf_fields).unwrap();
                    if let Err(e) = mempool_tx.send(serialized_transaction).await {
                        error!("Failed to send transaction to mempool: {}", e);
                    }
                }
            }
            
            Message::RequestBlocks(prev_hash_fields) => {
                debug!("Requesting {} blocks by prev_hash", prev_hash_fields.len());
                let mut sync_blocks = Vec::new();
                for prev_hash in prev_hash_fields {
                    if let Some(block_data) = Self::get_block_by_fields(store, &prev_hash).await {
                        if let Ok(fields) = bincode::deserialize::<SyncBlock>(&block_data) {
                            sync_blocks.push(Fields(fields.0));
                        } else {
                            error!("Failed to deserialize block data for prev_hash: {:?}", prev_hash);
                        }
                    } else {
                        debug!("Block not found for prev_hash: {:?}", prev_hash);
                    }
                }
                if sync_blocks.is_empty() {
                    return;
                }
                
                let _ = message_sender.send(ServerMessage::SendSyncBlocks {
                    client_id: client_id.to_string(),
                    sync_blocks,
                });
            }
            
            Message::SyncBlocks(sync_blocks_fields) => {
            }
            
            Message::ChainUpdate(chain_update_fields) => {
            }
            
        }
    }

    async fn get_block_by_fields(
        store: &mut Store,
        prev_hash: &Fields,
    ) -> Option<Vec<u8>> {
        let prev_field: [PlaceholderProjectNamePlaceholderField; 4] = from_fn(|i|prev_hash.0[i]);
        let prev_key: PlaceholderProjectNamePlaceholderHash = prev_field.clone().into();
        let digest_prev_hash = Digest(prev_key.clone().into());
        let prev_hash_bytes = digest_prev_hash.to_vec();

        match store.read(prev_hash_bytes).await {
            Ok(Some(data)) => {
                debug!("Successfully retrieved block data for prev_hash: {:?}", prev_hash);
                Some(data)
            },
            Ok(None) => {
                debug!("No block data found for prev_hash: {:?}", prev_hash);
                None
            },
            Err(e) => {
                error!("Error getting block data for prev_hash {:?}: {}", prev_hash, e);
                None
            }
        }
    }

    async fn handle_websocket_events(
        mut event_receiver: mpsc::Receiver<WebSocketEvent>,
        clients: Arc<RwLock<HashMap<String, ClientConnection>>>,
    ) {
        while let Some(event) = event_receiver.recv().await {
            match event {
                WebSocketEvent::BroadcastChainUpdate { prev_hash } => {
                    let clients = clients.read().await;
                    let fields = Fields(prev_hash.to_vec_field().into_iter()
                    .map(PlaceholderProjectNamePlaceholderField::from)
                    .collect());
                    let message = Message::ChainUpdate(fields);
                    for (client_id, client) in clients.iter() {
                        if client.subscribed {
                            if let Err(e) = client.sender.send(message.clone()) {
                                error!("Failed to send chain update to client {}: {}", client_id, e);
                            }
                        }
                    }
                }
            }
        }
        debug!("WebSocket event handler stopped");
    }
}
