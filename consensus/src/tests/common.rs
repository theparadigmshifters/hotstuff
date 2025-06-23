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
use placeholder_project_name_placeholder_zk::util::serialization::DefaultGateSerializer;

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
                let vd = circuit_data.verifier_data().to_bytes(&DefaultGateSerializer).unwrap();
                let address = format!("127.0.0.1:{}", i).parse().unwrap();
                let stake = 1;
                println!("Authority {}: {} with address {}", i, name, address);
                (name, stake, vd, address)
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
