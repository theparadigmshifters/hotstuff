use super::*;
use crate::common::{committee_with_base_port, keys};
use crate::config::Parameters;
use crypto::{generate_circuit, SecretKey};
use futures::future::try_join_all;
use std::fs;
use tokio::sync::mpsc::channel;
use tokio::task::JoinHandle;

fn spawn_nodes(
    keys: Vec<(PublicKey, SecretKey)>,
    committee: Committee,
    store_path: &str,
) -> Vec<JoinHandle<Vec<Block>>> {
    keys.into_iter()
        .enumerate()
        .map(|(i, (name, secret))| {
            let committee = committee.clone();
            let parameters = Parameters {
                timeout_delay: 2000,
                ..Parameters::default()
            };
            let store_path = format!("{}_{}", store_path, i);
            let _ = fs::remove_dir_all(&store_path);
            let store = Store::new(&store_path).unwrap();
           
            let (circuit_data, secret_targets, block_hash_target) = generate_circuit(secret.to_field());
            // Run the signature service.
            let signature_service = SignatureService::new(circuit_data, secret_targets, block_hash_target, secret);
            let (tx_consensus_to_mempool, mut rx_consensus_to_mempool) = channel(10);
            let (_tx_mempool_to_consensus, rx_mempool_to_consensus) = channel(1);
            let (tx_commit, mut rx_commit) = channel(1);

            // Sink the mempool channel.
            tokio::spawn(async move {
                loop {
                    rx_consensus_to_mempool.recv().await;
                }
            });

            // Spawn the consensus engine.
            tokio::spawn(async move {
                Consensus::spawn(
                    name,
                    committee,
                    parameters,
                    signature_service,
                    store,
                    rx_mempool_to_consensus,
                    tx_consensus_to_mempool,
                    tx_commit,
                );

                let mut blocks = Vec::new();
                while let Some(block) = rx_commit.recv().await {
                    blocks.push(block);
                }
                info!("Node {} collected {} blocks", name, blocks.len());
                blocks           
            })
        })
        .collect()
}
#[tokio::test]
async fn end_to_end() {
    let committee = committee_with_base_port(15_000);
    env_logger::Builder::new()
         .filter_level(log::LevelFilter::Debug)
        .target(env_logger::Target::Stdout)
        .init();   
    // Run all nodes.
    let store_path = ".db_test_end_to_end";
    let handles = spawn_nodes(keys(), committee, store_path);

    // Ensure all threads terminated correctly.
    let blocks = try_join_all(handles).await.unwrap();
}
