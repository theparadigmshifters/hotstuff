use crate::config::Committee;
use crate::consensus::Round;
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
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
    pub payload: Vec<Digest>,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        qc: QC,
        tc: Option<TC>,
        author: PublicKey,
        round: Round,
        payload: Vec<Digest>,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            qc,
            tc,
            author,
            round,
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

        let vk = committee.vk(&self.author).unwrap();
        let common = committee.common(&self.author).unwrap();
        let secret_hash = committee.secret_hash(&self.author).unwrap();
        // Check the signature.
        self.signature.verify(vk, common, &self.digest(), &secret_hash).unwrap();

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
        let block_data: Vec<GoldilocksField> = self.author.to_field().iter()
            .cloned()
            .chain(once(GoldilocksField::from_canonical_u64(self.round)))
            .chain(self.payload.iter().map(|x| GoldilocksField::from_canonical_u64(x.size() as u64)))
            .chain(self.qc.hash.to_field().iter().cloned())
            .collect::<Vec<_>>();

        let block_hash = PoseidonHash::hash_no_pad(&block_data);
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
        let vk = committee.vk(&self.author).unwrap();
        let common = committee.common(&self.author).unwrap();
        let secret_hash = committee.secret_hash(&self.author).unwrap();
        // Check the signature.
        self.signature.verify(vk, common, &self.digest(), &secret_hash).unwrap();
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let vote_data = self.hash.to_field().iter()
            .cloned()
            .chain(once(GoldilocksField::from_canonical_u64(self.round)))
            .collect::<Vec<_>>();
        Digest::from_field(PoseidonHash::hash_no_pad(&vote_data).elements)
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
            let vk = committee.vk(&author).unwrap();
            let common = committee.common(&author).unwrap();
            let secret_hash = committee.secret_hash(&author).unwrap();

            // Check the signature.
            signature.verify(vk, common, &self.digest(), &secret_hash).unwrap();
        }
        Ok(())
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let qc_data: Vec<GoldilocksField> = self.hash.to_field().iter()
            .cloned()
            .chain(once(GoldilocksField::from_canonical_u64(self.round)))
            .collect::<Vec<_>>();
        Digest::from_field(PoseidonHash::hash_no_pad(&qc_data).elements)
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
        
        let vk = committee.vk(&self.author).unwrap();
        let common = committee.common(&self.author).unwrap();
        let secret_hash = committee.secret_hash(&self.author).unwrap();
        // Check the signature.
        self.signature.verify(vk, common, &self.digest(), &secret_hash).unwrap();

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
        let hash_out = PoseidonHash::hash_no_pad(&data).elements;
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
                PoseidonHash::hash_no_pad(
                    &once(GoldilocksField::from_canonical_u64(self.round))
                        .chain(once(GoldilocksField::from_canonical_u64(*high_qc_round)))
                        .collect::<Vec<_>>()
                ).elements,
            );
            let vk = committee.vk(&author).unwrap();
            let common = committee.common(&author).unwrap();
            let secret_hash = committee.secret_hash(&author).unwrap();

            // Check the signature.
            signature.verify(vk, common, &digest, &secret_hash).unwrap();
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
