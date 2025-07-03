use crypto::Digest;
use crypto::Transaction;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

/// Indicates a serialized `MempoolMessage::Batch` message.
pub type SerializedBatchMessage = Vec<Transaction>;

/// Hashes and stores batches, it then outputs the batch's digest.
pub struct Processor;

impl Processor {
    pub fn spawn(
        // The persistent storage.
        mut store: Store,
        // Input channel to receive batches.
        mut rx_batch: Receiver<SerializedBatchMessage>,
        // Output channel to send out batches' digests.
        tx_digest: Sender<Digest>,
    ) {
        tokio::spawn(async move {
            while let Some(batch) = rx_batch.recv().await {
                for v in batch.iter() {
                    let hash = v.hash();
                    let digest = Digest::from_field(hash);
                    let txn = bincode::serialize(v).expect("Fail to serialize transaction");
                    store.write(digest.to_vec(), txn).await;
                    tx_digest.send(digest).await.expect("Failed to send digest");
                }
            }
        });
    }
}
