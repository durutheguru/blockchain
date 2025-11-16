use std::sync::Arc;
use std::collections::HashMap;

use super::signature::{SignatureScheme, SignatureError, PublicKey, SecretKey, Signature};
use super::algorithm::SignatureAlgorithm;
use crate::crypto::address::{Address, NetworkId};
use crate::crypto::schemes::ed25519_scheme::Ed25519Scheme;

/// Central manager for all signature schemes
/// 
/// This provides a unified interface for:
/// - Key generation
/// - Signing
/// - Verification
/// 
/// New algorithms can be registered dynamically
pub struct SignatureManager {
    schemes: HashMap<SignatureAlgorithm, Arc<dyn SignatureScheme>>,
}

impl SignatureManager {
    pub fn new() -> Self {
        let mut manager = Self {
            schemes: HashMap::new(),
        };
        
        manager.register_scheme(Arc::new(Ed25519Scheme::new()));
        
        manager
    }
    
    pub fn register_scheme(&mut self, scheme: Arc<dyn SignatureScheme>) {
        self.schemes.insert(scheme.algorithm(), scheme);
    }
    
    pub fn generate_keypair(&self, algorithm: SignatureAlgorithm) 
        -> Result<(PublicKey, SecretKey), SignatureError> 
    {
        let scheme = self.schemes.get(&algorithm)
            .ok_or(SignatureError::UnsupportedAlgorithm(algorithm))?;
        scheme.generate_keypair()
    }

    pub fn generate_wallet(
        &self,
        algorithm: SignatureAlgorithm,
        network: NetworkId,
    ) -> Result<(Address, PublicKey, SecretKey), SignatureError> {
        let (pk, sk) = self.generate_keypair(algorithm)?;
        let address = pk.derive_address(network)?;
        Ok((address, pk, sk))
    }
    
    pub fn sign(&self, message: &[u8], secret_key: &SecretKey) 
        -> Result<Signature, SignatureError> 
    {
        let scheme = self.schemes.get(&secret_key.algorithm)
            .ok_or(SignatureError::UnsupportedAlgorithm(secret_key.algorithm))?;
        scheme.sign(message, secret_key)
    }
    
    pub fn verify(&self, message: &[u8], signature: &Signature, public_key: &PublicKey) 
        -> Result<bool, SignatureError> 
    {
        if signature.algorithm != public_key.algorithm {
            return Err(SignatureError::AlgorithmMismatch {
                expected: public_key.algorithm.to_string(),
                actual: signature.algorithm.to_string(),
            });
        }
        
        let scheme = self.schemes.get(&signature.algorithm)
            .ok_or(SignatureError::UnsupportedAlgorithm(signature.algorithm))?;
        scheme.verify(message, signature, public_key)
    }
    
    pub fn is_supported(&self, algorithm: SignatureAlgorithm) -> bool {
        self.schemes.contains_key(&algorithm)
    }
    
    pub fn supported_algorithms(&self) -> Vec<SignatureAlgorithm> {
        self.schemes.keys().copied().collect()
    }
}

impl Default for SignatureManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_manager_basic_operations() {
        let manager = SignatureManager::new();
        
        assert!(manager.is_supported(SignatureAlgorithm::Ed25519));
        assert!(!manager.is_supported(SignatureAlgorithm::MlDsa65));
        
        let (public_key, secret_key) = manager
            .generate_keypair(SignatureAlgorithm::Ed25519)
            .unwrap();
        
        let message = b"Test message";
        let signature = manager.sign(message, &secret_key).unwrap();
        
        assert!(manager.verify(message, &signature, &public_key).unwrap());
    }
}
