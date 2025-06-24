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
use std::time::Instant;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use placeholder_project_name_placeholder_zk::field::goldilocks_field::GoldilocksField;
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use placeholder_project_name_placeholder_zk::hash::hash_types::HashOut;
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData;
use placeholder_project_name_placeholder_zk::hash::hash_types::HashOutTarget;
use placeholder_project_name_placeholder_zk::{
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
    },
    iop::{
        witness::{PartialWitness, WitnessWrite},
    }
};

pub type CryptoError = ed25519::Error;

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

    pub fn verify(&self, vd: VerifierCircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>, digest: &Digest) -> Result<(), Error> {
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

