use ed25519_dalek::{
    Signer, Verifier, 
    SigningKey, VerifyingKey,
    Signature as DalekSignature,
};
use rand::rngs::OsRng;

use crate::crypto::algorithm::SignatureAlgorithm;
use crate::crypto::signature::{SignatureScheme, PublicKey, SecretKey, Signature, SignatureError};


pub struct Ed25519Scheme;

impl Ed25519Scheme {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureScheme for Ed25519Scheme {

    fn generate_keypair(&self) -> Result<(PublicKey, SecretKey), SignatureError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        let public_key = PublicKey::new(
            SignatureAlgorithm::Ed25519,
            verifying_key.to_bytes().to_vec(),
        )?;
        
        let secret_key = SecretKey::new(
            SignatureAlgorithm::Ed25519,
            signing_key.to_bytes().to_vec(),
        );
        
        Ok((public_key, secret_key))
    }
    
    fn sign(&self, message: &[u8], secret_key: &SecretKey) -> Result<Signature, SignatureError> {
        if secret_key.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(
                SignatureError::AlgorithmMismatch { 
                    expected: "ED25519".to_string(), 
                    actual: secret_key.algorithm.to_string(),
                }
            )
        }

        let signing_key = SigningKey::from_bytes(
            secret_key.as_bytes().try_into()
            .map_err(|_| SignatureError::InvalidSecretKey)?
        );
        let sig = signing_key.sign(message);

        Signature::new(SignatureAlgorithm::Ed25519, sig.to_bytes().to_vec())
    }
    
    fn verify(&self, message: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<bool, SignatureError> {
        if signature.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(SignatureError::AlgorithmMismatch {
                expected: "Ed25519".to_string(),
                actual: signature.algorithm.to_string(),
            });
        }
        
        if public_key.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(SignatureError::AlgorithmMismatch {
                expected: "Ed25519".to_string(),
                actual: public_key.algorithm.to_string(),
            });
        }
        
        let verifying_key = VerifyingKey::from_bytes(
            public_key.as_bytes().try_into()
                .map_err(|_| SignatureError::InvalidPublicKey)?
        ).map_err(|_| SignatureError::InvalidPublicKey)?;
        
        let sig = DalekSignature::from_bytes(
            signature.as_bytes().try_into()
                .map_err(|_| SignatureError::InvalidSignature)?
        );
        
        Ok(verifying_key.verify(message, &sig).is_ok())
    }
    
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ed25519_sign_verify() {
        let scheme = Ed25519Scheme::new();
        let (public_key, secret_key) = scheme.generate_keypair().unwrap();
        
        let message = b"Hello, blockchain!";
        let signature = scheme.sign(message, &secret_key).unwrap();
        
        assert!(scheme.verify(message, &signature, &public_key).unwrap());
        
        // Verify fails with wrong message
        let wrong_message = b"Wrong message";
        assert!(!scheme.verify(wrong_message, &signature, &public_key).unwrap());
    }
    
    #[test]
    fn test_signature_serialization() {
        let scheme = Ed25519Scheme::new();
        let (_public_key, secret_key) = scheme.generate_keypair().unwrap();
        
        let message = b"Test message";
        let signature = scheme.sign(message, &secret_key).unwrap();
        
        // Test wire format
        let wire = signature.to_wire_format();
        assert_eq!(wire[0], SignatureAlgorithm::Ed25519.to_u8());
        assert_eq!(wire.len(), 1 + 64);
        
        let decoded = Signature::from_wire_format(&wire).unwrap();
        assert_eq!(signature, decoded);
        
        // Test hex format
        let hex = signature.to_hex();
        let from_hex = Signature::from_hex(&hex).unwrap();
        assert_eq!(signature, from_hex);
    }
    
    #[test]
    fn test_public_key_hex() {
        let scheme = Ed25519Scheme::new();
        let (public_key, _) = scheme.generate_keypair().unwrap();
        
        let hex = public_key.to_hex();
        let decoded = PublicKey::from_hex(&hex).unwrap();
        
        assert_eq!(public_key, decoded);
    }
}