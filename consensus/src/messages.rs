use crate::config::Committee;
use crate::consensus::{Round, ToField};
use crate::error::{ConsensusError, ConsensusResult};
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use circuit::{Hash, Digest, ProofService};
use placeholder_project_name_placeholder_zk::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use placeholder_project_name_placeholder_zk::plonk::proof::Proof;
use placeholder_project_name_placeholder_zk::field::goldilocks_field::GoldilocksField;

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

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        // self.signature.verify(&self.digest(), &self.author)?;

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
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut elements = Vec::new();
        elements.extend_from_slice(&self.author.to_vec_field());
        elements.push(self.round.to_field());
        elements.extend_from_slice(&self.payload.iter().flat_map(|d| d.to_vec_field()).collect::<Vec<GoldilocksField>>());
        elements.extend_from_slice(&self.qc.hash.to_vec_field());
        Digest(PoseidonHash::hash_pad(&elements))
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

        // Check the signature.
        //self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut elements = Vec::new();
        elements.extend_from_slice(&self.hash.to_vec_field());
        elements.push(self.round.to_field());
        Digest(PoseidonHash::hash_pad(&elements))
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "V({}, {}, {})", self.author, self.round, self.hash)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
    pub hash: Digest,
    pub round: Round,
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

        // Check the signatures.
        // Signature::verify_batch(&self.digest(), &self.votes).map_err(ConsensusError::from)
        Ok(())
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let mut elements = Vec::new();
        elements.extend_from_slice(&self.hash.to_vec_field());
        elements.push(self.round.to_field());
        Digest(PoseidonHash::hash_pad(&elements))
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "QC({}, {})", self.hash, self.round)
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

        // Check the signature.
        //self.signature.verify(&self.digest(), &self.author)?;

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
        Digest(PoseidonHash::hash_pad(&elements))
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

        // Check the signatures.
        // for (author, signature, high_qc_round) in &self.votes {
        //     let mut hasher = Sha512::new();
        //     hasher.update(self.round.to_le_bytes());
        //     hasher.update(high_qc_round.to_le_bytes());
        //     let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
        //     signature.verify(&digest, author)?;
        // }
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
