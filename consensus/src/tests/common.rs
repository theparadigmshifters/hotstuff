use crate::config::Committee;
use crate::consensus::Round;
use crate::messages::{Block, Timeout, Vote, QC};
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SecretKey, Signature};
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use placeholder_project_name_placeholder_zk::plonk::config::Hasher;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng as _};
use std::convert::TryInto;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData;
use crypto::{generate_circuit, generate_keypair};
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use placeholder_project_name_placeholder_zk::hash::hash_types::HashOut;

// Fixture.
pub fn keys() -> Vec<(PublicKey, SecretKey)> {
    let rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(rng.clone())).collect()
}


// Fixture.
pub fn committee() -> Committee {
    Committee::new(
        keys()
            .into_iter()
            .enumerate()
            .map(|(i, (name, secret))| {
                let (circuit_data, _, _) =  generate_circuit(secret.to_field());
                let verifier_only: PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData = circuit_data
                        .verifier_only
                        .try_into()
                        .expect("Failed to convert circuit data to verifier only type");
                let common = circuit_data.common;
                let secret_hash = Digest::from_field(PoseidonHash::hash_no_pad(&secret.to_field()).elements);
                let address = format!("127.0.0.1:{}", i).parse().unwrap();
                let stake = 1;
                println!("Authority {}: {} with address {}", i, name, address);
                (name, stake, verifier_only, common, secret_hash, address)
            })
            .collect(),
        /* epoch */ 100,
    )
}

// Fixture.
pub fn committee_with_base_port(base_port: u16) -> Committee {
    let mut committee = committee();
    for authority in committee.authorities.values_mut() {
        let port = authority.address.port();
        authority.address.set_port(base_port + port);
    }
    committee
}
