use crate::config::Committee;
use crate::consensus::{Round, ToField};
use crate::error::{ConsensusError, ConsensusResult};
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use placeholder_project_name_placeholder_zk::plonk::circuit_data::VerifierCircuitData;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use base64::{Engine as _, engine::general_purpose};
use circuit::{AggCircuit, Digest, Hash, ProofService};
use placeholder_project_name_placeholder_zk::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use placeholder_project_name_placeholder_zk::plonk::proof::Proof;
use placeholder_project_name_placeholder_zk::field::goldilocks_field::GoldilocksField;
use placeholder_project_name_placeholder_zk::util::serialization::DefaultGateSerializer;
use placeholder_project_name_placeholder_zk::plonk::proof::ProofWithPublicInputs;
use placeholder_project_name_placeholder_zk::hash::hash_types::HashOut;

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncBlock {
    pub prev: [GoldilocksField; 4],
    pub transactions: Vec<HashOut<GoldilocksField>>,
    pub proof: Proof<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    //pub proof: PlaceholderProjectNamePlaceholderProof,
}

impl fmt::Debug for SyncBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "B(prev: {:?}, tx_num: {})",
            self.prev,
            self.transactions.len(),
            //&self.proof,
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub qc: QC,
    pub tc: Option<TC>,
    pub author: Digest,
    pub round: Round,
    pub payload: Vec<Digest>,
    pub proof: Option<Proof<GoldilocksField, PoseidonGoldilocksConfig, 2>>,
}

impl Block {
    pub async fn new(
        qc: QC,
        tc: Option<TC>,
        author: Digest,
        round: Round,
        payload: Vec<Digest>,
        mut proof_service: ProofService,
    ) -> Self {
        let block = Self {
            qc,
            tc,
            author,
            round,
            payload,
            proof: None,
        };
        let proof = proof_service.request_proof(block.digest()).await;
        Self { proof: Some(proof), ..block }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    pub fn parent(&self) -> &Digest {
        &self.qc.hash
    }

    pub fn tx_tail(&self) -> Digest {
        let tx_tail = self.payload.iter().fold(HashOut::<GoldilocksField>::default(), |x, y| PoseidonHash::two_to_one(x, y.0));
        Digest(tx_tail)
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the author proof.
        verify_proof(&self.digest(), &self.author, committee, self.proof.clone().unwrap());

        // Check the embedded QC.
        if self.qc != QC::genesis() {
            self.qc.verify(committee)?;
        }

        // Check the TC embedded in the block (if any).
        if let Some(ref tc) = self.tc {
            tc.verify(committee)?;
        }
        Ok(())
    }

    pub fn aggregated_block(&self, parent: Block, committee: &Committee) -> SyncBlock {
        let vds = self.qc.votes
            .iter()
            .map(|v| {
                let vd_encoded = committee.authorities.get(&v.0)
                    .map(|auth| auth.vd.clone())
                    .unwrap();
                let vd_decoded = general_purpose::STANDARD.decode(&vd_encoded).unwrap();
                VerifierCircuitData::from_bytes(vd_decoded, &DefaultGateSerializer).unwrap()
            }).collect::<Vec<_>>();
        let prev = parent.qc.tx_tail.0;
        let transactions: Vec<HashOut<GoldilocksField>> = parent.payload.iter().map(|v| v.0).collect();
        let agg_circuit = AggCircuit::new(vds.clone(), prev, transactions.clone());
        let proofs_with_inputs = self.qc.votes
            .iter()
            .map(|(_, proof)| {
                ProofWithPublicInputs {
                    proof: proof.clone(),
                    public_inputs: self.qc.digest().to_vec_field(),
                }
            }).collect::<Vec<_>>();
        let all_public_inputs = proofs_with_inputs.iter().flat_map(|p| p.public_inputs.clone()).collect();
        let proof = agg_circuit.prove(proofs_with_inputs, parent.author.0, parent.round.to_field(), parent.qc.hash.0, parent.tx_tail().0);
        //let proof = PlaceholderProjectNamePlaceholderProof::try_from(proof).unwrap();
        agg_circuit.vd().verify(ProofWithPublicInputs {proof: proof.clone(), public_inputs: all_public_inputs}).expect("aggregated proof verification failed");
        SyncBlock { prev: prev.elements, transactions, proof }
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut elements = Vec::new();
        elements.extend_from_slice(&self.author.to_vec_field());
        elements.push(self.round.to_field());
        elements.extend_from_slice(&self.qc.hash.to_vec_field());
        elements.extend_from_slice(&self.qc.tx_tail.to_vec_field());
        elements.extend_from_slice(&self.payload.iter().flat_map(|d| d.to_vec_field()).collect::<Vec<GoldilocksField>>());
        Digest(PoseidonHash::hash_no_pad(&elements))
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B({}, {}, {:?}, {})",
            self.digest(),
            self.author,
            self.round,
            self.qc,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.round)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub hash: Digest,
    pub round: Round,
    pub tx_tail: Digest,
    pub author: Digest,
    pub proof: Option<Proof<GoldilocksField, PoseidonGoldilocksConfig, 2>>,
}

impl Vote {
    pub async fn new(
        block: &Block,
        author: Digest,
        mut proof_service: ProofService,
    ) -> Self {
        let vote = Self {
            hash: block.digest(),
            round: block.round,
            tx_tail: block.tx_tail(),
            author,
            proof: None,
        };
        let proof = proof_service.request_proof(vote.digest()).await;
        Self { proof: Some(proof), ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the proof.
        verify_proof(&self.digest(), &self.author, committee, self.proof.clone().unwrap());
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut elements = Vec::new();
        elements.extend_from_slice(&self.hash.to_vec_field());
        elements.push(self.round.to_field());
        elements.extend_from_slice(&self.tx_tail.to_vec_field());
        Digest(PoseidonHash::hash_no_pad(&elements))
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "V({}, {}, {}, {})", self.author, self.round, self.hash, self.tx_tail)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
    pub hash: Digest,
    pub round: Round,
    pub tx_tail: Digest,
    pub votes: Vec<(Digest, Proof<GoldilocksField, PoseidonGoldilocksConfig, 2>)>,
}

impl QC {
    pub fn genesis() -> Self {
        QC::default()
    }

    pub fn timeout(&self) -> bool {
        self.hash == Digest::default() && self.round != 0
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::QCRequiresQuorum
        );

        // Check the proof.
        for (author, proof) in &self.votes {
            verify_proof(&self.digest(), author, committee, proof.clone());
        }
        Ok(())
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let mut elements = Vec::new();
        elements.extend_from_slice(&self.hash.to_vec_field());
        elements.push(self.round.to_field());
        elements.extend_from_slice(&self.tx_tail.to_vec_field());
        Digest(PoseidonHash::hash_no_pad(&elements))
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "QC({}, {}, {})", self.hash, self.round, self.tx_tail)
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.round == other.round
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub high_qc: QC,
    pub round: Round,
    pub author: Digest,
    pub proof: Option<Proof<GoldilocksField, PoseidonGoldilocksConfig, 2>>,
}

impl Timeout {
    pub async fn new(
        high_qc: QC,
        round: Round,
        author: Digest,
        mut proof_service: ProofService,
    ) -> Self {
        let timeout = Self {
            high_qc,
            round,
            author,
            proof: None,
        };
        let proof = proof_service.request_proof(timeout.digest()).await;
        Self {
            proof: Some(proof),
            ..timeout
        }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the proof.
        verify_proof(&self.digest(), &self.author, committee, self.proof.clone().unwrap());

        // Check the embedded QC.
        if self.high_qc != QC::genesis() {
            self.high_qc.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut elements = Vec::new();
        elements.push(self.round.to_field());
        elements.push(self.high_qc.round.to_field());
        Digest(PoseidonHash::hash_no_pad(&elements))
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TV({}, {}, {:?})", self.author, self.round, self.high_qc)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TC {
    pub round: Round,
    pub votes: Vec<(Digest, Proof<GoldilocksField, PoseidonGoldilocksConfig, 2>, Round)>,
}

impl TC {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _, _) in self.votes.iter() {
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::TCRequiresQuorum
        );

        // Check the proofs.
        for (author, proof, high_qc_round) in &self.votes {
            let mut elements = Vec::new();
            elements.push(self.round.to_field());
            elements.push(high_qc_round.to_field());
            let digest = Digest(PoseidonHash::hash_no_pad(&elements));
            verify_proof(&digest, author, committee, proof.clone());
        }
        Ok(())
    }

    pub fn high_qc_rounds(&self) -> Vec<Round> {
        self.votes.iter().map(|(_, _, r)| r).cloned().collect()
    }
}

impl fmt::Debug for TC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TC({}, {:?})", self.round, self.high_qc_rounds())
    }
}

fn verify_proof(digest: &Digest, author: &Digest, committee: &Committee, proof: Proof<GoldilocksField, PoseidonGoldilocksConfig, 2>) {
    let vd_encoded = committee.authorities.get(author).map(|auth| auth.vd.clone()).unwrap();
    let vd_decoded = general_purpose::STANDARD.decode(&vd_encoded).unwrap();
    let vd = VerifierCircuitData::from_bytes(vd_decoded, &DefaultGateSerializer).unwrap();
    vd.verify(ProofWithPublicInputs { proof: proof.into(), public_inputs: digest.to_vec_field() }).expect("proof verification failed");
}