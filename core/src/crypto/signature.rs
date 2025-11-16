use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::crypto::address::{Address, NetworkId};

use super::algorithm::SignatureAlgorithm;
use zeroize::Zeroize;


#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Invalid public key")]
    InvalidPublicKey,
    
    #[error("Invalid secret key")]
    InvalidSecretKey,
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    
    #[error("Algorithm mismatch: expected {expected}, got {actual}")]
    AlgorithmMismatch { expected: String, actual: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub algorithm: SignatureAlgorithm,
    pub bytes: Vec<u8>,
}

impl PublicKey {

    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Result<Self, SignatureError> {
        if bytes.len() != algorithm.public_key_size() {
            return Err(
                SignatureError::InvalidLength { 
                    expected: algorithm.public_key_size(), 
                    actual: bytes.len() 
                }
            )
        }

        Ok(Self {algorithm, bytes})
    }

    pub fn from_bytes(algorithm: SignatureAlgorithm, bytes: &[u8]) -> Result<Self, SignatureError> {
        Self::new(algorithm, bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_hex(&self) -> String {
        format!("{:02x}:{}", self.algorithm.to_u8(), hex::encode(&self.bytes))
    }

    pub fn from_hex(s: &str) -> Result<Self, SignatureError> {
        let parts : Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(SignatureError::InvalidPublicKey);
        }

        let algo_byte = u8::from_str_radix(parts[0], 16)
            .map_err(|_| SignatureError::InvalidPublicKey)?;

        let algorithm = SignatureAlgorithm::from_u8(algo_byte)
            .ok_or(SignatureError::InvalidPublicKey)?;

        let bytes = hex::decode(parts[1])
            .map_err(|_| SignatureError::InvalidPublicKey)?;

        Self::new(algorithm, bytes)
    }

    pub fn derive_address(&self, network: NetworkId) -> Result<Address, SignatureError> {
        Address::derive(self, network)
    }

}

#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    #[zeroize(skip)]
    pub algorithm: SignatureAlgorithm,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl SecretKey {
    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        Self {algorithm, bytes}
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: SignatureAlgorithm,
    pub bytes: Vec<u8>,
}

impl Signature {

    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Result<Self, SignatureError> {
        if bytes.len() != algorithm.signature_size() {
            return Err(
                SignatureError::InvalidLength { 
                    expected: algorithm.signature_size(), 
                    actual: bytes.len() 
                }
            )
        }

        Ok(Self { algorithm, bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_wire_format(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.bytes.len());
        result.push(self.algorithm.to_u8());
        result.extend_from_slice(&self.bytes);
        result
    }

    pub fn from_wire_format(data: &[u8]) -> Result<Self, SignatureError> {
        if data.is_empty() {
            return Err(SignatureError::InvalidSignature);
        }

        let algorithm = SignatureAlgorithm::from_u8(data[0])
            .ok_or(SignatureError::InvalidSignature)?;
        
        Self::new(algorithm, data[1..].to_vec())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_wire_format())
    }

    pub fn from_hex(s: &str) -> Result<Self, SignatureError> {
        let bytes = hex::decode(s)
            .map_err(|_| SignatureError::InvalidSignature)?;

        Self::from_wire_format(&bytes)
    }

}


pub trait SignatureScheme: Send + Sync {

    fn generate_keypair(&self) -> Result<(PublicKey, SecretKey), SignatureError>;

    fn sign(&self, message: &[u8], secret_key: &SecretKey) -> Result<Signature, SignatureError>;

    fn verify(&self, message: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<bool, SignatureError>;

    fn algorithm(&self) -> SignatureAlgorithm;

}


//// TESTS


#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pk() -> PublicKey {
        PublicKey::new(SignatureAlgorithm::Ed25519, vec![1u8; 32]).unwrap()
    }

    #[test]
    fn public_key_length_validation() {
        assert!(PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 31]).is_err());
        assert!(PublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32]).is_ok());
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let pk = sample_pk();
        let hex = pk.to_hex();
        let decoded = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(pk, decoded);
    }

    #[test]
    fn derive_address_uses_algorithm_metadata() {
        let pk = sample_pk();
        let addr = pk.derive_address(NetworkId::Mainnet).unwrap();
        assert_eq!(addr.algorithm().unwrap(), SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn signature_enforces_length_and_formats() {
        let sig_bytes = vec![0x22; 64];
        let sig = Signature::new(SignatureAlgorithm::Ed25519, sig_bytes).unwrap();
        let wire = sig.to_wire_format();
        assert_eq!(wire[0], SignatureAlgorithm::Ed25519.to_u8());
        assert_eq!(Signature::from_wire_format(&wire).unwrap(), sig);

        assert!(Signature::new(SignatureAlgorithm::Ed25519, vec![0u8; 63]).is_err());
        let hex = sig.to_hex();
        assert_eq!(Signature::from_hex(&hex).unwrap(), sig);
    }

    #[test]
    fn secret_key_api_surface() {
        let sk = SecretKey::new(SignatureAlgorithm::Ed25519, vec![0x55; 32]);
        assert_eq!(sk.as_bytes().len(), 32);
        assert_eq!(sk.algorithm, SignatureAlgorithm::Ed25519);
    }
}