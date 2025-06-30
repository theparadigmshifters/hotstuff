use placeholder_project_name_placeholder_zk::field::goldilocks_field::GoldilocksField;
use placeholder_project_name_placeholder_zk::hash::hash_types::HashOut;
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use placeholder_project_name_placeholder_zk::plonk::config::Hasher;
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::{PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData, PlaceholderProjectNamePlaceholderProof};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub snap: [GoldilocksField; 4],
    pub from: PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData,
    pub to: [GoldilocksField; 4],
    pub amount: GoldilocksField,
    pub nonce: GoldilocksField,
    pub price: GoldilocksField,
    pub payload: Vec<[GoldilocksField; 8]>,
    pub proof: PlaceholderProjectNamePlaceholderProof,
}

impl Transaction {
    pub fn public_inputs(&self) -> [[GoldilocksField; 4]; 4] {
        let info = [self.amount, self.nonce, self.price, GoldilocksField(self.payload.len() as u64)];
        let payload_tail = self.payload.iter().fold([GoldilocksField(0); 4], |x, y| PoseidonHash::two_to_one(x.into(), PoseidonHash::hash_no_pad(y)).elements);
        let info_hash = PoseidonHash::two_to_one(info.into(), payload_tail.into()).elements;
        [self.snap, HashOut::from(self.from).elements, self.to, info_hash]
    }

    pub fn payload_tail(&self) -> [GoldilocksField; 4] { self.payload.iter().fold([GoldilocksField(0); 4], |x, y| PoseidonHash::two_to_one(x.into(), PoseidonHash::hash_no_pad(y)).elements) }
    pub fn info(&self) -> [GoldilocksField; 4] { [self.amount, self.nonce, self.price, GoldilocksField(self.payload.len() as u64)] }

    pub fn hash(&self) -> HashOut<GoldilocksField> { PoseidonHash::hash_no_pad(&self.public_inputs().concat()) }
    pub fn new(
        snap: [GoldilocksField; 4],
        from: PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData,
        to: [GoldilocksField; 4],
        amount: GoldilocksField,
        nonce: GoldilocksField,
        price: GoldilocksField,
        payload: Vec<[GoldilocksField; 8]>,
        proof: PlaceholderProjectNamePlaceholderProof,
    ) -> Self {
        Transaction { snap, from, to, amount, nonce, price, payload, proof }
    }
    pub fn set_proof(&mut self, proof: PlaceholderProjectNamePlaceholderProof) {
        self.proof = proof;
    } 

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        serde_json::from_slice(bytes).unwrap()
    }
}