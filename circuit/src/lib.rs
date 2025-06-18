use placeholder_project_name_placeholder_zk::field::goldilocks_field::GoldilocksField;
use placeholder_project_name_placeholder_zk::hash::hash_types::{HashOut, HashOutTarget};
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use placeholder_project_name_placeholder_zk::iop::witness::{PartialWitness, WitnessWrite};
use placeholder_project_name_placeholder_zk::plonk::circuit_data::{CircuitData, CircuitConfig};
use placeholder_project_name_placeholder_zk::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use placeholder_project_name_placeholder_zk::plonk::proof::Proof;
use placeholder_project_name_placeholder_zk::plonk::circuit_builder::CircuitBuilder;
use placeholder_project_name_placeholder_zk::plonk::circuit_data::VerifierOnlyCircuitData;
use placeholder_project_name_placeholder_zk::plonk::config::GenericHashOut;
use base64::{Engine as _, engine::general_purpose};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use std::fmt;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use std::cmp::Ordering;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub struct SecretTargets {
    msg_hash: HashOutTarget,
    secret: HashOutTarget,
}

pub struct SecretCircuit {
    targets: SecretTargets,
    secret: HashOut<GoldilocksField>,
    cd: CircuitData<F, C, D>,
}

impl SecretCircuit {
    pub fn new(secret: HashOut<GoldilocksField>) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let secret_hash = PoseidonHash::hash_no_pad(&secret.elements); // TODO: use [secret, secret]?
        let targets = Self::build(&mut builder, secret_hash);
        dbg!(builder.num_gates());
        let cd = builder.build::<C>();
        Self {
            secret,
            cd,
            targets,
        }
    }

    fn build(builder: &mut CircuitBuilder<GoldilocksField, D>, secret_hash: HashOut<GoldilocksField>) -> SecretTargets {
        let secret = builder.add_virtual_hash();
        let msg_hash = builder.add_virtual_hash_public_input();
        let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(secret.elements.to_vec()); // TODO: use [secret, secret]?
        let secret_hash = builder.constant_hash(secret_hash);
        builder.connect_hashes(hash, secret_hash);
        SecretTargets { msg_hash, secret }
    }

    pub fn prove(&self, msg_hash: HashOut<GoldilocksField>) -> Proof<GoldilocksField, C, 2> {
        let mut wi = PartialWitness::<GoldilocksField>::new();
        wi.set_hash_target(self.targets.msg_hash, msg_hash).unwrap();
        wi.set_hash_target(self.targets.secret, self.secret).unwrap();
        self.cd.prove(wi).unwrap().proof
    }

    pub fn vk(&self) -> VerifierOnlyCircuitData<C, D> {
        self.cd.verifier_only.clone()
    }
}

#[derive(Clone)]
pub struct ProofService {
    channel: Sender<(Digest, oneshot::Sender<Proof<GoldilocksField, C, 2>>)>,
}

impl ProofService {
    pub fn new(secret_circuit: SecretCircuit) -> Self {
        let (tx, mut rx) = channel::<(Digest, oneshot::Sender<Proof<GoldilocksField, C, 2>>)>(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let proof = secret_circuit.prove(digest.0);
                let _ = sender.send(proof);
            }
        });
        Self { channel: tx }
    }

    pub async fn request_proof(&mut self, digest: Digest) -> Proof<GoldilocksField, C, 2> {
        let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
        if let Err(e) = self.channel.send((digest, sender)).await {
            panic!("Failed to send message Proof Service: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive proof from Proof Service")
    }
}

/// Represents a hash digest (32 bytes).
#[derive(Copy, Hash, PartialEq, Default, Eq, Clone)]
pub struct Digest(pub HashOut<GoldilocksField>);

impl Digest {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn size(&self) -> usize {
        self.0.elements.len()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", general_purpose::STANDARD.encode(&self.0.to_bytes()))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", general_purpose::STANDARD.encode(&self.0.to_bytes()))
    }
}

impl PartialOrd for Digest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Digest {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let base64_str = general_purpose::STANDARD.encode(&self.0.to_bytes());
        serializer.serialize_str(&base64_str)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base64_str = String::deserialize(deserializer)?;
        let bytes = general_purpose::STANDARD.decode(&base64_str).unwrap();
        Ok(Digest(HashOut::from_bytes(&bytes)))
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> Digest;
}

#[cfg(test)]
mod tests {
    use super::*;
    use placeholder_project_name_placeholder_zk::plonk::proof::ProofWithPublicInputs;
    use placeholder_project_name_placeholder_zk::field::types::Sample;
    use std::time::Instant;

    #[test]
    fn test_verify_block_circuit() {
        let secret = HashOut::<GoldilocksField>::rand();
        let msg_hash = HashOut::<GoldilocksField>::rand();
        
        let secret_circuit = SecretCircuit::new(secret);
        let prove_start = Instant::now();
        let proof = secret_circuit.prove(msg_hash);
        let prove_duration = prove_start.elapsed();
        println!("Prove time: {:?}", prove_duration);
        
        let verify_start = Instant::now();
        secret_circuit.cd.verify(ProofWithPublicInputs { 
            proof: proof, 
            public_inputs: [msg_hash.elements].concat()
        }).unwrap();
        let verify_duration = verify_start.elapsed();
        println!("Verify time: {:?}", verify_duration);
    }
}
