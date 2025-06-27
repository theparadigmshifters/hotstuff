use crate::{mempool::MempoolMessage, transaction::Transaction};
use crate::quorum_waiter::QuorumWaiterMessage;
use bytes::Bytes;
use circuit::Digest;
use network::ReliableSender;
use std::net::SocketAddr;
#[cfg(feature = "benchmark")]
use log::info;
use tokio::sync::mpsc::{Receiver, Sender};

/// broadcast payloads.
pub struct PayloadBroadcaster {
    /// Channel to receive payload from the network.
    rx_transaction: Receiver<Transaction>,
    /// Output channel to deliver payload to the `QuorumWaiter`.
    tx_message: Sender<QuorumWaiterMessage>,
    /// The network addresses of the other mempools.
    mempool_addresses: Vec<(Digest, SocketAddr)>,
    /// A network sender to broadcast the batches to the other mempools.
    network: ReliableSender,
}

impl PayloadBroadcaster {
    pub fn spawn(
        rx_transaction: Receiver<Transaction>,
        tx_message: Sender<QuorumWaiterMessage>,
        mempool_addresses: Vec<(Digest, SocketAddr)>,
    ) {
        tokio::spawn(async move {
            Self {
                rx_transaction,
                tx_message,
                mempool_addresses,
                network: ReliableSender::new(),
            }
            .run()
            .await;
        });
    }

    /// Main loop receiving incoming payload.
    async fn run(&mut self) {
        loop {
            tokio::select! {
                // Assemble client transactions into batches of preset size.
                Some(transaction) = self.rx_transaction.recv() => {
                    self.broadcast(transaction).await;
                },
            }

            // Give the change to schedule other tasks.
            tokio::task::yield_now().await;
        }
    }

    /// broadcast the transaction.
    async fn broadcast(&mut self, transaction: Transaction) {
        // Serialize the transaction.
        let message = MempoolMessage::Transaction(transaction.clone());
        let serialized = bincode::serialize(&message).expect("Failed to serialize our own transaction");

        #[cfg(feature = "benchmark")]
        {
            // NOTE: This is one extra hash that is only needed to print the following log entries.
            let digest = transaction.hash();
            // NOTE: This log entry is used to compute performance.
            info!(
                "receive transaction Hash {:?}",
                digest
            );
        }

        // Broadcast the transaction through the network.
        let (names, addresses): (Vec<_>, _) = self.mempool_addresses.iter().cloned().unzip();
        let bytes = Bytes::from(serialized.clone());
        let handlers = self.network.broadcast(addresses, bytes).await;

        // Send the transaction through the deliver channel for further processing.
        self.tx_message
            .send(QuorumWaiterMessage {
                transaction: transaction,
                handlers: names.into_iter().zip(handlers.into_iter()).collect(),
            })
            .await
            .expect("Failed to deliver payload");
    }
}