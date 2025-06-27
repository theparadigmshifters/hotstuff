use circuit::Digest;
use placeholder_project_name_placeholder_zk::field::{goldilocks_field::GoldilocksField, types::Field};
use placeholder_project_name_placeholder_zk::field::types::PrimeField64;
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use placeholder_project_name_placeholder_zk::plonk::config::Hasher;
use std::convert::TryInto;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction(Vec<GoldilocksField>);

impl Transaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.iter()
            .flat_map(|x| x.to_canonical_u64().to_le_bytes())
            .collect()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        // TODO: check overflow
        assert!(bytes.len() % 8 == 0, "the byte length must be a multiple of 8");
        
        let data = bytes.chunks_exact(8)
            .map(|chunk| {
                let arr: [u8; 8] = chunk.try_into().unwrap();
                GoldilocksField::from_canonical_u64(u64::from_le_bytes(arr))
            })
            .collect();
        Transaction(data)
    }

    pub fn hash(&self) -> Digest {
        Digest(PoseidonHash::hash_no_pad(&self.0)) //TODO: hash pad?
    }
}
