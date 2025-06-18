use circuit::Digest;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::transaction::Transaction;

pub struct Processor;

impl Processor {
    pub fn spawn(
        // The persistent storage.
        mut store: Store,
        // Input channel to receive batches.
        mut rx_transaction: Receiver<Transaction>,
        // Output channel to send out batches' digests.
        tx_digest: Sender<Digest>,
    ) {
        tokio::spawn(async move {
            while let Some(tx) = rx_transaction.recv().await {
                // Hash the transaction.
                let digest = tx.hash();

                // Store the transaction.
                store.write(digest.to_vec(), tx.to_bytes()).await;

                tx_digest.send(digest).await.expect("Failed to send digest");
            }
        });
    }
}
