use crate::config::Committee;
use crate::consensus::Round;
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService, generate_recursion_circuit, recursion_prove};
use placeholder_project_name_placeholder_zk::field::types::Field;
use placeholder_project_name_placeholder_zk::plonk::config::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::iter::once;
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use placeholder_project_name_placeholder_zk::field::goldilocks_field::GoldilocksField;

#[derive(Serialize, Deserialize, Clone)]
pub struct Block {
    pub qc: QC,
    pub tc: Option<TC>,
    pub author: PublicKey,
    pub round: Round,
    pub prev: Digest,
    pub payload: Vec<Digest>,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        qc: QC,
        tc: Option<TC>,
        author: PublicKey,
        round: Round,
        prev: Digest,
        payload: Vec<Digest>,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            qc,
            tc,
            author,
            round,
            prev,
            payload,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(block.digest()).await;
        Self { signature, ..block }
    }

    pub fn genesis() -> Self {
        Self {
            qc: QC::genesis(),
            tc: Some(TC::default()),
            author: PublicKey::default(),
            round: 0,
            prev: Digest::default(),
            payload: Vec::new(),
            signature: Signature::default(),
        }
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

       let vd = committee.vd(&self.author).unwrap();
        // Check the signature.
        self.signature.verify(vd, &self.digest()).unwrap();

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

    pub fn txns_hash_tail(&self, prev: Digest) -> Digest {
        if self.payload.len() > 0 {
            let fields: Vec<GoldilocksField> = self
                    .payload
                    .iter()
                    .flat_map(|v| v.to_field())
                    .collect();
            let current = PoseidonHash::hash_pad(&fields);
            return Digest::from_field(PoseidonHash::two_to_one(prev.to_field().into(), current).elements)
        }
        prev
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let payload_fields: Vec<GoldilocksField> = self.payload.iter().flat_map(|x| x.to_field()).collect();
        let block_data: Vec<GoldilocksField> = self.author.to_field().iter()
            .cloned()
            .chain(once(GoldilocksField::from_canonical_u64(self.round)))
            .chain(payload_fields.into_iter())
            .chain(self.qc.hash.to_field().iter().cloned())
            .collect::<Vec<_>>();

        let block_hash = PoseidonHash::hash_pad(&block_data);
        Digest::from_field(block_hash.elements)
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
    pub author: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        block: &Block,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let vote = Self {
            hash: block.digest(),
            round: block.round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        let vd = committee.vd(&self.author).unwrap();
        // Check the signature.
        self.signature.verify(vd, &self.digest()).unwrap();
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let vote_data = self.hash.to_field().iter()
            .cloned()
            .chain(once(GoldilocksField::from_canonical_u64(self.round)))
            .collect::<Vec<_>>();
        Digest::from_field(PoseidonHash::hash_pad(&vote_data).elements)
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
    pub votes: Vec<(PublicKey, Signature)>,
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
        for (author, signature) in &self.votes {
             let vd = committee.vd(&author).unwrap();
            // Check the signature.
            signature.verify(vd, &self.digest()).unwrap();
        }
        Ok(())
    }
    pub async fn generate_recursion_prove(&self, committee: &Committee) -> Vec<u8> {
        let vds = self.votes.iter().map(|v| committee.vd(&v.0).unwrap()).collect();
        let (circuit_data, targets) = generate_recursion_circuit(&vds);
        let proofs = self.votes.iter().map(|v| v.1.proof().clone()).collect::<Vec<_>>();
        recursion_prove(circuit_data, targets, proofs).await.unwrap().to_bytes()
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let qc_data: Vec<GoldilocksField> = self.hash.to_field().iter()
            .cloned()
            .chain(once(GoldilocksField::from_canonical_u64(self.round)))
            .collect::<Vec<_>>();
        Digest::from_field(PoseidonHash::hash_pad(&qc_data).elements)
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
    pub author: PublicKey,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        high_qc: QC,
        round: Round,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let timeout = Self {
            high_qc,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(timeout.digest()).await;
        Self {
            signature,
            ..timeout
        }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );
        
        let vd = committee.vd(&self.author).unwrap();
        // Check the signature.
        self.signature.verify(vd, &self.digest()).unwrap();

        // Check the embedded QC.
        if self.high_qc != QC::genesis() {
            self.high_qc.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let data: Vec<GoldilocksField> = once(GoldilocksField::from_canonical_u64(self.round))
            .chain(once(GoldilocksField::from_canonical_u64(self.high_qc.round)))
            .collect();
        let hash_out = PoseidonHash::hash_pad(&data).elements;
        Digest::from_field(hash_out)
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TV({}, {}, {:?})", self.author, self.round, self.high_qc)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TC {
    pub round: Round,
    pub votes: Vec<(PublicKey, Signature, Round)>,
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
        for (author, signature, high_qc_round) in &self.votes {
            let digest = Digest::from_field(
                PoseidonHash::hash_pad(
                    &once(GoldilocksField::from_canonical_u64(self.round))
                        .chain(once(GoldilocksField::from_canonical_u64(*high_qc_round)))
                        .collect::<Vec<_>>()
                ).elements,
            );
            let vd = committee.vd(&author).unwrap();
            // Check the signature.
            signature.verify(vd, &digest).unwrap();
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
