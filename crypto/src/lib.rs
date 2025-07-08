// Copyright(C) Facebook, Inc. and its affiliates.
use ed25519_dalek::ed25519;
use placeholder_project_name_placeholder_zk::field::types::Field;
use placeholder_project_name_placeholder_zk::field::types::PrimeField64;
use placeholder_project_name_placeholder_zk::plonk::config::Hasher;
use placeholder_project_name_placeholder_zk::util::serialization::gate_serialization::log::info;
use rand::rngs::StdRng;
use rand::Rng;
use rand::{RngCore};
use serde::{de, ser, Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::fmt::Debug;
use std::time::Instant;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use placeholder_project_name_placeholder_zk::field::goldilocks_field::GoldilocksField;
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use placeholder_project_name_placeholder_zk::hash::hash_types::HashOut;
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData;
use placeholder_project_name_placeholder_zk::plonk::proof::ProofWithPublicInputsTarget;
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::PlaceholderProjectNamePlaceholderProof;

use placeholder_project_name_placeholder_zk::hash::hash_types::HashOutTarget;
use placeholder_project_name_placeholder_zk::{
    plonk::{
        circuit_builder::{CircuitBuilder},
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
    iop::{
        witness::{PartialWitness, WitnessWrite},
    }
};
use l0::Transaction as L0Transaction;
pub type CryptoError = ed25519::Error;
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::PlaceholderProjectNamePlaceholderHash;
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::PlaceholderProjectNamePlaceholderField;



/// Represents a hash digest (32 bytes).
#[derive(Hash, PartialEq, Default, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn to_field(&self) -> [GoldilocksField; 4] {
       let mut elements = [GoldilocksField::ZERO; 4];
        for i in 0..4 {
            let start = i * 8;
            let chunk = &self.0[start..start + 8];
            let value = u64::from_le_bytes(chunk.try_into().unwrap());
            elements[i] = GoldilocksField::from_canonical_u64(value);
        }
        elements
    }

    pub fn from_field(elements: [GoldilocksField; 4]) -> Self {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let value = elements[i].to_canonical_u64();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&value.to_le_bytes());
        }
        Digest(bytes)
    }
}


impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0).get(0..16).unwrap())
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Digest(item.try_into()?))
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> Digest;
}

/// Represents a public key (in bytes).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn encode_base32(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base32(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }

    pub fn to_field(&self) -> [GoldilocksField; 4] {
       let mut elements = [GoldilocksField::ZERO; 4];
        for i in 0..4 {
            let start = i * 8;
            let chunk = &self.0[start..start + 8];
            let value = u64::from_le_bytes(chunk.try_into().unwrap());
            elements[i] = GoldilocksField::from_canonical_u64(value);
        }
        elements
    }
    pub fn from_field(elements: [GoldilocksField; 4]) -> Self {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let value = elements[i].to_canonical_u64();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&value.to_le_bytes());
        }
        PublicKey(bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base32())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base32().get(0..16).unwrap())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base32())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base32(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents a secret key (in bytes).
#[derive(Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn encode_base32(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base32(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }

    pub fn to_field(&self) -> [GoldilocksField; 4] {
       let mut elements = [GoldilocksField::ZERO; 4];
        for i in 0..4 {
            let start = i * 8;
            let chunk = &self.0[start..start + 8];
            let value = u64::from_le_bytes(chunk.try_into().unwrap());
            elements[i] = GoldilocksField::from_canonical_u64(value);
        }
        elements
    }

    pub fn from_field(elements: [GoldilocksField; 4]) -> Self {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let value = elements[i].to_canonical_u64();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&value.to_le_bytes());
        }
        SecretKey(bytes)
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base32())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base32(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}

pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
    let mut pri_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut pri_key);
    let secret_key = SecretKey(pri_key);

    let (circuit_data, _, _) =  generate_circuit(PoseidonHash::hash_no_pad(&secret_key.to_field()));
    let verifier_only: PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData = circuit_data
        .verifier_only
        .try_into()
        .expect("Failed to convert circuit data to verifier only type");
    let name = HashOut::from(verifier_only);
    (PublicKey::from_field(name.elements), secret_key)
}

pub fn generate_keypair(mut rng: StdRng) -> (PublicKey, SecretKey) {
    let mut pri_key = [0u8; 32];
    rng.fill(&mut pri_key);
    let secret_key = SecretKey(pri_key);

    let (circuit_data, _, _) =  generate_circuit(PoseidonHash::hash_no_pad(&secret_key.to_field()));
    let verifier_only: PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData = circuit_data
        .verifier_only
        .try_into()
        .expect("Failed to convert circuit data to verifier only type");
    let name = HashOut::from(verifier_only);
    (PublicKey::from_field(name.elements), secret_key)
}

#[derive(Debug)]
pub enum Error {
    InvalidPublicInputsLength { expected: usize, found: usize },
    SecretHashMismatch,
    BlockHashMismatch,
    ProofVerificationFailed(String),
    TryFromSliceError(TryFromSliceError),
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Signature {
    proof: ProofWithPublicInputs<F, C, D>,
}

impl Signature {
    pub fn default() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        let circuit_data = builder.build::<C>();

        let proof = circuit_data
            .prove(PartialWitness::<GoldilocksField>::new())
            .expect("Failed to generate default proof");

        Signature { proof }
    }

    pub fn new(proof: ProofWithPublicInputs<F, C, D> ) -> Self {
        Signature { proof }
    }

    pub fn proof(&self) -> &ProofWithPublicInputs<F, C, D> {
        &self.proof
    }

    pub fn verify(&self, vd: VerifierCircuitData<F, C, D>, digest: &Digest) -> Result<(), Error> {
        let public_inputs = self.proof.clone().public_inputs;
        if public_inputs.len() != 4 {
            return Err(Error::InvalidPublicInputsLength {
                expected: 4,
                found: public_inputs.len(),
            });
        }
        
        let computed_block_hash = Digest::from_field(public_inputs[0..4].try_into().unwrap());
        if digest != &computed_block_hash {
            return Err(Error::SecretHashMismatch)   
        }
        
        // Call the verify method on the struct
        vd.verify(
            self.proof.clone(),
        ).map_err(|e| Error::ProofVerificationFailed(e.to_string()))?;
        Ok(())
    }
    
}

/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a oneshot channel).
#[derive(Debug, Clone)]
pub struct SignatureService {
    channel: Sender<(Digest, oneshot::Sender<Signature>)>,
}

impl SignatureService {
    pub fn new(circuit_data: CircuitData<F, C, D>, secret_target: HashOutTarget, block_hash_target: HashOutTarget, secret: SecretKey) -> Self {
        let (tx, mut rx): (Sender<(Digest, oneshot::Sender<Signature>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let prove_start = Instant::now();
                let mut pw = PartialWitness::<GoldilocksField>::new();
                pw.set_hash_target(secret_target, HashOut::from(secret.to_field())).unwrap();
                pw.set_hash_target(block_hash_target, HashOut::from(digest.to_field())).unwrap();
                let proof = circuit_data.prove(pw).unwrap();
                let prove_duration = prove_start.elapsed();
                info!("Signature Service: Proving took {:?}", prove_duration);
                let _ = sender.send(Signature::new(proof));
            }  
});
        Self { channel: tx }
    }

    pub async fn request_signature(&mut self, digest: Digest) -> Signature {
        let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
        if let Err(e) = self.channel.send((digest, sender)).await {
            panic!("Failed to send message Signature Service: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive signature from Signature Service")
    }
}

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

pub fn generate_circuit(secret_hash: HashOut<GoldilocksField>) -> (CircuitData<F, C, D>, HashOutTarget, HashOutTarget) {
    let config = CircuitConfig::standard_recursion_zk_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let secret_target = builder.add_virtual_hash();
    let block_hash_target = builder.add_virtual_hash_public_input();
    let secret = builder.constant_hash(secret_hash);
    let computed_secret_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(secret_target.elements.to_vec());

    builder.connect_hashes(secret, computed_secret_hash);

    (builder.build::<C>(), secret_target, block_hash_target)
}

pub fn generate_recursion_circuit(inner_data: &Vec<VerifierCircuitData<F, C, D>>) -> (CircuitData<F, C, D>, Vec<HashOutTarget>, Vec<ProofWithPublicInputsTarget<D>>) {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut targets: Vec<HashOutTarget> = Vec::new();
    let mut proof_targets: Vec<ProofWithPublicInputsTarget<D>> = Vec::new();

    let author_target = builder.add_virtual_hash();
    targets.push(author_target);
    let qc_target = builder.add_virtual_hash();
    targets.push(qc_target);
    let prev_target = builder.add_virtual_hash_public_input();
    targets.push(prev_target);
    let round_target = builder.add_virtual_hash();
    targets.push(round_target);
    let txns_target = builder.add_virtual_hash_public_input();
    targets.push(txns_target);

    let h1 = builder.hash_n_to_hash_no_pad::<PoseidonHash>([author_target.elements, round_target.elements].concat());
    let h2 = builder.hash_n_to_hash_no_pad::<PoseidonHash>([prev_target.elements, txns_target.elements].concat());
    let h3 = builder.hash_n_to_hash_no_pad::<PoseidonHash>([h1.elements, h2.elements].concat());
    let block_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>([h3.elements, qc_target.elements].concat());

    let vote_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>([block_hash.elements, round_target.elements].concat());

    for data in inner_data.iter() {
        let proof_target = builder.add_virtual_proof_with_pis(&data.common);
        proof_targets.push(proof_target.clone());
        let vk_target = builder.constant_verifier_data(&data.verifier_only);
        builder.verify_proof::<C>(&proof_target, &vk_target, &data.common);
        assert_eq!(proof_target.public_inputs.len(), 4, "proof_target.public_inputs must have length 4");
        builder.connect_hashes(vote_hash, HashOutTarget::from_vec(proof_target.public_inputs));
    }

    let zero = builder.constant_hash([GoldilocksField(0); 4].into());
    builder.register_public_inputs(&[zero.elements, zero.elements].concat());

    (builder.build::<C>(), targets, proof_targets)
}

pub struct BlockTarget {
    author_target: HashOut<GoldilocksField>,
    qc_target: HashOut<GoldilocksField>,
    prev_target: HashOut<GoldilocksField>,
    round_target: HashOut<GoldilocksField>,
    txns_target: HashOut<GoldilocksField>,
}

impl BlockTarget {
    pub fn new(author_target: HashOut<GoldilocksField>, qc_target: HashOut<GoldilocksField>, prev_target: HashOut<GoldilocksField>, round_target: HashOut<GoldilocksField>, txns_target: HashOut<GoldilocksField>) -> Self {
        BlockTarget{
            author_target,
            qc_target,
            prev_target,
            round_target,
            txns_target,
        }
    }
}

 pub async fn recursion_prove(circuit_data: CircuitData<F, C, D>, targets: Vec<HashOutTarget>, proof_target: Vec<ProofWithPublicInputsTarget<D>>, proof: Vec<ProofWithPublicInputs<F, C, D>>, block: BlockTarget) -> Result<ProofWithPublicInputs<F, C, D>, Box<dyn std::error::Error>> {
    let handle= tokio::spawn(async move {
        let mut witness = PartialWitness::new();
        witness.set_hash_target(targets[0], block.author_target).unwrap();
        witness.set_hash_target(targets[1], block.qc_target).unwrap();
        witness.set_hash_target(targets[2], block.prev_target).unwrap();
        witness.set_hash_target(targets[3], block.round_target).unwrap();
        witness.set_hash_target(targets[4], block.txns_target).unwrap();

        for (i, p) in proof_target.iter().enumerate(){
            witness.set_proof_with_pis_target(&p, &proof[i]).unwrap();
        }
        let prove_start = Instant::now();
        let prove = circuit_data.prove(witness).unwrap();
        let prove_duration = prove_start.elapsed();
        info!("recursion_prove: Proving took {:?}", prove_duration);
        prove
    });
    let proof = handle.await?;
    Ok(proof)
}

pub async fn convert_to_placeholder_proof(inner_data: &VerifierCircuitData<F, C, D>, proof: ProofWithPublicInputs<F, C, D>,) -> (VerifierCircuitData<F, C, D>, PlaceholderProjectNamePlaceholderProof) {
    let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
    let t = builder.add_virtual_proof_with_pis(&inner_data.common);
    let inner_verifier_data = builder.constant_verifier_data(&inner_data.verifier_only);
    builder.register_public_inputs(&t.public_inputs);
    builder.verify_proof::<PoseidonGoldilocksConfig>(&t, &inner_verifier_data, &inner_data.common);
    let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
    
    let mut witness = PartialWitness::new();
    witness.set_proof_with_pis_target(&t, &proof).unwrap();
    let proof = circuit_data.prove(witness).unwrap().proof.try_into().unwrap();
    (circuit_data.verifier_data(), proof)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub snap: [GoldilocksField; 4],
    pub from: Vec<GoldilocksField>,
    pub to: [GoldilocksField; 4],
    pub amount: GoldilocksField,
    pub nonce: GoldilocksField,
    pub gas: GoldilocksField,
    pub payload: Vec<GoldilocksField>,
    pub proof: Vec<GoldilocksField>,
}

impl Transaction {
    pub fn default() -> Self {
        let r = rand::thread_rng().gen();
        Transaction{
            snap: [GoldilocksField(0); 4],
            from: [GoldilocksField(0); 68].to_vec(),
            to: [GoldilocksField(0); 4],
            amount: GoldilocksField(0),
            nonce: GoldilocksField(r),
            gas: GoldilocksField(0),
            payload: [GoldilocksField(0)].to_vec(),
            proof: [GoldilocksField(0); 16581].to_vec(), 
        }
    }
     pub fn public_inputs(&self) -> [[GoldilocksField; 4]; 4] {
        let info = [self.amount, self.nonce, self.gas, GoldilocksField(self.payload.len() as u64)];
        let payload_tail = self.payload.iter().fold([GoldilocksField(0); 4], |x, y| PoseidonHash::two_to_one(x.into(), PoseidonHash::hash_no_pad(y)).elements);
        let info_hash = PoseidonHash::two_to_one(info.into(), payload_tail.into()).elements;
        [self.snap, self.get_from_addr().elements, self.to, info_hash]
    }
    pub fn hash(&self) -> [GoldilocksField; 4] { PoseidonHash::hash_no_pad(&self.public_inputs().concat()).elements }
    pub fn verify_proof(&self) { VerifierCircuitData::from(self.get_from()).verify(ProofWithPublicInputs { proof: self.get_proof().into(), public_inputs: self.public_inputs().concat() }).unwrap() }
    pub fn get_proof(&self) -> PlaceholderProjectNamePlaceholderProof {
        let arr: [GoldilocksField; 16581] = self.proof.clone().try_into().expect("proof must have length 16581");
        PlaceholderProjectNamePlaceholderProof::from(arr)
    }
    pub fn get_from(&self) -> PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData {
        let from: [GoldilocksField; 68] = self.from.clone().try_into().expect("proof must have length 68");
        PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData::from(from)
    }
    pub fn get_from_addr(&self) -> HashOut<GoldilocksField> {
         HashOut::from(self.get_from())
    }
    pub fn to_l0_txn(&self) -> L0Transaction {
        let proof_array: [GoldilocksField; 16581] = self.proof.clone().try_into().expect("Proof vector has incorrect length");
        let proof: PlaceholderProjectNamePlaceholderProof = proof_array.into();     
        let snap: PlaceholderProjectNamePlaceholderHash = self.snap.into();
        let from_arry: [GoldilocksField; 68] = self.from.clone().try_into().expect("Consensus vector has incorrect length");
        let from: PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData = from_arry.into();
        let to: PlaceholderProjectNamePlaceholderHash = self.to.into();
        let nonce: PlaceholderProjectNamePlaceholderField = self.nonce.into();
        let amount: PlaceholderProjectNamePlaceholderField = self.amount.into();
        let gas: PlaceholderProjectNamePlaceholderField = self.gas.into();
        let payload: Vec<PlaceholderProjectNamePlaceholderField> = self
            .payload
            .iter()
            .map(|arr| PlaceholderProjectNamePlaceholderField::from(*arr))
            .collect();
        L0Transaction{
            proof,
            snap,
            from,
            to,
            nonce,
            amount,
            gas,
            payload 
        }
    }
}

#[test]
fn test_txn() {
    let txn = Transaction::default();
    print!("txn: {:?}", txn)
}