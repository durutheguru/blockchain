use serde::{Serialize, Deserialize};


/// Enumeration of all supported signature algorithms
/// 
/// Design note: IDs 0-99 reserved for classical algorithms
///              IDs 100-199 reserved for post-quantum algorithms
///              IDs 200-255 reserved for hybrid schemes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {

    /// Ed25519: 32-byte keys, 64-byte signatures
    Ed25519 = 0,

    /// ML-DSA-65 (Dilithium3): NIST Level 3 security
    /// ~1952-byte public key, ~3293-byte signature
    MlDsa65 = 100,

    /// ML-DSA-87 (Dilithium5): NIST Level 5 security
    /// ~2592-byte public key, ~4595-byte signature
    MlDsa87 = 101,

    /// SLH-DSA-SHAKE-128f (SPHINCS+-128f): Conservative PQ
    /// ~32-byte public key, ~17088-byte signature
    SlhDsaShake128f = 110,

    /// SLH-DSA-SHAKE-256f (SPHINCS+-256f): High security PQ
    /// ~64-byte public key, ~49856-byte signature
    SlhDsaShake256f = 111,

    /// Hybrid: Ed25519 + ML-DSA-65
    /// Both signatures must verify for validity
    HybridEd25519MlDsa65 = 200,

    /// Hybrid: Ed25519 + SLH-DSA-SHAKE-128f
    HybridEd25519SlhDsa128f = 201,

}

impl SignatureAlgorithm {

    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
            Self::SlhDsaShake128f => 32,
            Self::SlhDsaShake256f => 64,
            Self::HybridEd25519MlDsa65 => 32 + 1952,
            Self::HybridEd25519SlhDsa128f => 32 + 32,
        }
    }

    pub fn signature_size(&self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::MlDsa65 => 3293,
            Self::MlDsa87 => 4595,
            Self::SlhDsaShake128f => 17088,
            Self::SlhDsaShake256f => 49856,
            Self::HybridEd25519MlDsa65 => 64 + 3293,
            Self::HybridEd25519SlhDsa128f => 64 + 17088,
        }
    }

    pub fn is_quantum_resistant(&self) -> bool {
        match self {
            Self::Ed25519 => false,
            Self::MlDsa65 | Self::MlDsa87 | 
            Self::SlhDsaShake128f | Self::SlhDsaShake256f |
            Self::HybridEd25519MlDsa65 | Self::HybridEd25519SlhDsa128f => true,
        }
    }

    pub fn nist_security_level(&self) -> u8 {
        match self {
            Self::Ed25519 => 0, // Not applicable (128-bit classical security)
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,
            Self::SlhDsaShake128f => 1,
            Self::SlhDsaShake256f => 5,
            Self::HybridEd25519MlDsa65 => 3,
            Self::HybridEd25519SlhDsa128f => 1,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ed25519),
            100 => Some(Self::MlDsa65),
            101 => Some(Self::MlDsa87),
            110 => Some(Self::SlhDsaShake128f),
            111 => Some(Self::SlhDsaShake256f),
            200 => Some(Self::HybridEd25519MlDsa65),
            201 => Some(Self::HybridEd25519SlhDsa128f),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }

}


impl std::fmt::Display for SignatureAlgorithm {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::MlDsa65 => write!(f, "ML-DSA-65"),
            Self::MlDsa87 => write!(f, "ML-DSA-87"),
            Self::SlhDsaShake128f => write!(f, "SLH-DSA-SHAKE-128f"),
            Self::SlhDsaShake256f => write!(f, "SLH-DSA-SHAKE-256f"),
            Self::HybridEd25519MlDsa65 => write!(f, "Hybrid(Ed25519+ML-DSA-65)"),
            Self::HybridEd25519SlhDsa128f => write!(f, "Hybrid(Ed25519+SLH-DSA-128f)"),
        }
    }

}


//// TESTS


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_documented_values() {
        assert_eq!(SignatureAlgorithm::Ed25519.public_key_size(), 32);
        assert_eq!(SignatureAlgorithm::MlDsa65.signature_size(), 3293);
        assert_eq!(SignatureAlgorithm::HybridEd25519SlhDsa128f.public_key_size(), 64);
    }

    #[test]
    fn quantum_resistance_flags() {
        assert!(!SignatureAlgorithm::Ed25519.is_quantum_resistant());
        assert!(SignatureAlgorithm::SlhDsaShake256f.is_quantum_resistant());
    }

    #[test]
    fn nist_levels_are_consistent() {
        assert_eq!(SignatureAlgorithm::MlDsa87.nist_security_level(), 5);
        assert_eq!(SignatureAlgorithm::SlhDsaShake128f.nist_security_level(), 1);
    }

    #[test]
    fn to_from_u8_roundtrip() {
        for algo in [
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::MlDsa65,
            SignatureAlgorithm::SlhDsaShake256f,
            SignatureAlgorithm::HybridEd25519MlDsa65,
        ] {
            let byte = algo.to_u8();
            assert_eq!(SignatureAlgorithm::from_u8(byte), Some(algo));
        }
        assert!(SignatureAlgorithm::from_u8(0xFF).is_none());
    }
}