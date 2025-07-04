use crate::config::Committee;
use crate::consensus::Round;
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{generate_recursion_circuit, recursion_prove, BlockTarget, Digest, Hash, PublicKey, Signature, SignatureService, convert_to_placeholder_proof};
use placeholder_project_name_placeholder_zk::field::types::Field;
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::{PlaceholderProjectNamePlaceholderProof};
use placeholder_project_name_placeholder_zk::plonk::config::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt;
use std::iter::once;
use placeholder_project_name_placeholder_zk::hash::poseidon::PoseidonHash;
use placeholder_project_name_placeholder_zk::field::goldilocks_field::GoldilocksField;
use placeholder_project_name_placeholder_zk::plonk::proof::ProofWithPublicInputs;
use crypto::Transaction;
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData;

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

    pub fn txns_hash(&self) -> Digest {
        let fields: Vec<GoldilocksField> = self
                .payload
                .iter()
                .flat_map(|v| v.to_field())
                .collect();
        Digest::from_field(PoseidonHash::hash_pad(&fields).elements)
    }

    pub fn prev(&self) -> Digest {
        self.prev.clone()
    }

    pub fn txns_hash_tail(&self, prev: Digest) -> Digest {
        if self.payload.len() > 0 {
            let hash = self.payload.iter().fold(prev.to_field().into(), |x, y| PoseidonHash::two_to_one(x, y.to_field().into()));
            return Digest::from_field(hash.elements)
        }
        prev
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let round_hash = [GoldilocksField::from_canonical_u64(self.round), GoldilocksField(0), GoldilocksField(0), GoldilocksField(0)].into();
        let h1= PoseidonHash::two_to_one(self.author.to_field().into(), round_hash);
        let h2 = PoseidonHash::two_to_one(self.prev.to_field().into(), self.txns_hash().to_field().into());
        let h3 = PoseidonHash::two_to_one(h1, h2);
        let h4 = PoseidonHash::two_to_one(h3, self.qc.hash.to_field().into());
        Digest::from_field(h4.elements)
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
        let round_hash = [GoldilocksField::from_canonical_u64(self.round), GoldilocksField(0), GoldilocksField(0),GoldilocksField(0)].into();
        let h = PoseidonHash::two_to_one(self.hash.to_field().into(), round_hash);
        Digest::from_field(h.elements)
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
    pub async fn generate_recursion_prove(&self, committee: &Committee, block: &Block) -> (PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData, PlaceholderProjectNamePlaceholderProof) {
        let vds = self.votes.iter().map(|v| committee.vd(&v.0).unwrap()).collect();
        let (circuit_data, targets, proof_targets) = generate_recursion_circuit(&vds);
        let proofs = self.votes.iter().map(|v| v.1.proof().clone()).collect::<Vec<_>>();
        let block_target = BlockTarget::new(
            block.author.to_field().into(),
            block.qc.hash.to_field().into(),
            block.prev().to_field().into(),
            [
                GoldilocksField::from_canonical_u64(block.round),
                GoldilocksField(0),
                GoldilocksField(0),
                GoldilocksField(0),
            ].into(),
            block.txns_hash().to_field().into(),
        );
        let verifier_data = circuit_data.verifier_data().clone();
        let proof = recursion_prove(circuit_data, targets, proof_targets, proofs, block_target).await.unwrap();
        let (verifier_data, proof) = convert_to_placeholder_proof(&verifier_data, proof).await;
        verifier_data.verify(ProofWithPublicInputs{ proof: proof.into(), public_inputs: [block.prev.to_field(), block.txns_hash().to_field(), [GoldilocksField(0); 4], [GoldilocksField(0); 4]].concat()}).unwrap();
        (PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData::try_from(verifier_data.verifier_only).expect("Failed to palcehoder!"), proof)
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let round_hash = [GoldilocksField::from_canonical_u64(self.round), GoldilocksField(0), GoldilocksField(0),GoldilocksField(0)].into();
        let h = PoseidonHash::two_to_one(self.hash.to_field().into(), round_hash);
        Digest::from_field(h.elements)
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

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct SyncBlock {
    pub proof: Vec<GoldilocksField>,
    pub last: [GoldilocksField; 4],
    pub consensus:  Vec<GoldilocksField>,
    pub meta: [GoldilocksField; 4],
    pub transactions: Vec<Transaction>,
}