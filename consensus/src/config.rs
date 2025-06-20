use crypto::{Digest, PublicKey, SecretKey};
use log::info;
use placeholder_project_name_placeholder_zk::field::goldilocks_field::GoldilocksField;
use placeholder_project_name_placeholder_zk::placeholder_project_name_placeholder_patch::PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData;
use placeholder_project_name_placeholder_zk::plonk::circuit_data::CommonCircuitData;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

pub type Stake = u32;
pub type EpochNumber = u128;

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    pub timeout_delay: u64,
    pub sync_retry_delay: u64,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            timeout_delay: 5_000,
            sync_retry_delay: 10_000,
        }
    }
}

impl Parameters {
    pub fn log(&self) {
        // NOTE: These log entries are used to compute performance.
        info!("Timeout delay set to {} rounds", self.timeout_delay);
        info!("Sync retry delay set to {} ms", self.sync_retry_delay);
    }
}

#[derive(Clone)]
pub struct Authority {
    pub stake: Stake,
    pub address: SocketAddr,
    pub vk: PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData,
    pub common: CommonCircuitData<GoldilocksField, 2>,
    pub secret_hash: Digest,
}

#[derive(Clone)]
pub struct Committee {
    pub authorities: HashMap<PublicKey, Authority>,
    pub epoch: EpochNumber,
}

impl Committee {
    pub fn new(info: Vec<(PublicKey, Stake, PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData, CommonCircuitData<GoldilocksField, 2>, Digest, SocketAddr)>, epoch: EpochNumber) -> Self {
        Self {
            authorities: info
                .into_iter()
                .map(|(name, stake, vk, common, secret_hash, address)| {
                    let authority = Authority { stake, address, vk, secret_hash, common};
                    (name, authority)
                })
                .collect(),
            epoch,
        }
    }

    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    pub fn stake(&self, name: &PublicKey) -> Stake {
        self.authorities.get(name).map_or_else(|| 0, |x| x.stake)
    }

    pub fn quorum_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        let total_votes: Stake = self.authorities.values().map(|x| x.stake).sum();
        2 * total_votes / 3 + 1
    }

    pub fn address(&self, name: &PublicKey) -> Option<SocketAddr> {
        self.authorities.get(name).map(|x| x.address)
    }

    pub fn vk(&self, name: &PublicKey) -> Option<PlaceholderProjectNamePlaceholderVerifierOnlyCircuitData> {
        self.authorities.get(name).map(|x| x.vk)
    }

    pub fn common(&self, name: &PublicKey) -> Option<CommonCircuitData<GoldilocksField, 2>> {
        self.authorities.get(name).map(|x| x.common.clone())
    }

    pub fn secret_hash(&self, name: &PublicKey) -> Option<Digest> {
        self.authorities.get(name).map(|x| x.secret_hash.clone())
    }

    pub fn broadcast_addresses(&self, myself: &PublicKey) -> Vec<(PublicKey, SocketAddr)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, x)| (*name, x.address))
            .collect()
    }
}
