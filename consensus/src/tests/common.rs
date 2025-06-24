use crate::config::Committee;
use crypto::{PublicKey, SecretKey};
use rand::rngs::StdRng;
use rand::{SeedableRng as _};
use crypto::{generate_circuit, generate_keypair};
use placeholder_project_name_placeholder_zk::util::serialization::DefaultGateSerializer;
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;

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
                let (circuit_data, _, _) =  generate_circuit(PoseidonHash::hash_no_pad(&secret.to_field()));
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
