use circuit::Digest;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use placeholder_project_name_placeholder_zk::{field::types::Sample, hash::hash_types::HashOut};

/// Indicates a serialized `MempoolMessage::Batch` message.
pub type SerializedBatchMessage = Vec<u8>;

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
                // Hash the batch.
                let digest = Digest(HashOut::rand()); //TODO

                // Store the batch.
                store.write(digest.to_vec(), batch).await;

                tx_digest.send(digest).await.expect("Failed to send digest");
            }
        });
    }
}
