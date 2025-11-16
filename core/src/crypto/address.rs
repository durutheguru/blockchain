use bs58::encode as base58_encode;
use ripemd::Ripemd160;
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::crypto::{algorithm::SignatureAlgorithm, signature::{PublicKey, SignatureError}};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkId {
    Mainnet = 0x00,
    Testnet = 0x6F,
}

#[derive(Error, Debug)]
pub enum AddressError {

    #[error("invalid checksum")]
    InvalidChecksum,

    #[error("invalid length")]
    InvalidLength,

    #[error("invalid network byte")]
    InvalidNetwork,

    #[error("invalid algorithm byte")]
    InvalidAlgorithm,

}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address([u8; 26]);

impl Address {

    pub fn derive(pk: &PublicKey, network: NetworkId) -> Result<Self, SignatureError> {
        let payload = Self::hash_payload(pk.as_bytes());
        let mut data = [0u8; 26];
        data[0] = network as u8;
        data[1] = pk.algorithm.to_u8();
        data[2..22].copy_from_slice(&payload);

        let checksum = Self::checksum(&data[..22]);
        data[22..].copy_from_slice(&checksum);

        Ok(Self(data))
    }

    pub fn to_string(&self) -> String {
        base58_encode(self.0).into_string()
    }

    pub fn from_str(s: &str) -> Result<Self, AddressError> {
        let bytes = bs58::decode(s).into_vec()
            .map_err(|_| AddressError::InvalidChecksum)?;
        if bytes.len() != 26 {
            return Err(AddressError::InvalidLength);
        }
        let mut arr = [0u8; 26];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn network(&self) -> Result<NetworkId, AddressError> {
        match self.0[0] {
            0x00 => Ok(NetworkId::Mainnet),
            0x6F => Ok(NetworkId::Testnet),
            _ => Err(AddressError::InvalidNetwork),
        }
    }

    pub fn algorithm(&self) -> Result<SignatureAlgorithm, AddressError> {
        SignatureAlgorithm::from_u8(self.0[1]).ok_or(AddressError::InvalidAlgorithm)
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[2..22]
    }

    fn hash_payload(pk_bytes: &[u8]) -> [u8; 20] {
        let sha = Sha256::digest(pk_bytes);
        let ripemd = Ripemd160::digest(sha);
        ripemd.into()
    }

    fn checksum(prefix: &[u8]) -> [u8; 4] {
        let first = Sha256::digest(prefix);
        let second = Sha256::digest(&first);
        second[0..4].try_into().unwrap()
    }

}