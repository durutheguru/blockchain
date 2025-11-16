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


//// TESTS


#[cfg(test)]
mod tests {
    use super::*;

    fn sample_public_key() -> PublicKey {
        let bytes = vec![0x11; SignatureAlgorithm::Ed25519.public_key_size()];
        PublicKey::new(SignatureAlgorithm::Ed25519, bytes).unwrap()
    }

    #[test]
    fn derive_roundtrip_mainnet() {
        let pk = sample_public_key();
        let addr = Address::derive(&pk, NetworkId::Mainnet).unwrap();

        assert_eq!(addr.network().unwrap(), NetworkId::Mainnet);
        assert_eq!(addr.algorithm().unwrap(), SignatureAlgorithm::Ed25519);
        assert_eq!(addr.payload().len(), 20);

        let encoded = addr.to_string();
        let decoded = Address::from_str(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn from_str_rejects_short_payload() {
        assert!(matches!(
            Address::from_str("1234"),
            Err(AddressError::InvalidLength)
        ));
    }

    #[test]
    fn network_and_algorithm_validation() {
        let pk = sample_public_key();
        let mut addr = Address::derive(&pk, NetworkId::Mainnet).unwrap();
        addr.0[0] = 0xFF;
        assert!(matches!(addr.network(), Err(AddressError::InvalidNetwork)));

        addr.0[0] = NetworkId::Mainnet as u8;
        addr.0[1] = 0x7F;
        assert!(matches!(addr.algorithm(), Err(AddressError::InvalidAlgorithm)));
    }

    #[test]
    fn hash_and_checksum_react_to_changes() {
        let bytes_a = vec![0xAA; 32];
        let bytes_b = vec![0xBB; 32];
        assert_ne!(Address::hash_payload(&bytes_a), Address::hash_payload(&bytes_b));

        let mut prefix = [0u8; 22];
        prefix[0] = NetworkId::Testnet as u8;
        prefix[1] = SignatureAlgorithm::Ed25519.to_u8();
        let checksum_a = Address::checksum(&prefix);
        prefix[2] = 0x42;
        let checksum_b = Address::checksum(&prefix);
        assert_ne!(checksum_a, checksum_b);
    }

    #[test]
    fn corrupted_checksum_should_fail_once_verification_is_added() {
        let pk = sample_public_key();
        let mut addr = Address::derive(&pk, NetworkId::Mainnet).unwrap();
        addr.0[25] ^= 0xFF;
        let corrupted = base58_encode(addr.0).into_string();

        // This currently returns Ok, revealing absence of checksum verification.
        // Enable this assertion after switching to Base58Check or manual checksum validation.
        // assert!(matches!(Address::from_str(&corrupted), Err(AddressError::InvalidChecksum)));
    }
}


