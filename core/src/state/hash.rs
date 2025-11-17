use primitive_types::H256;
use sha3::{Keccak256, Digest};

/// Configurable hash function for state trie
pub trait StateHasher {
    fn hash_node(&self, left: &H256, right: &H256) -> H256;
    fn hash_leaf(&self, key: &H256, value: &[u8]) -> H256;
}

/// Keccak256 hasher (Ethereum-compatible)
#[derive(Default)]
pub struct Keccak256Hasher;

impl StateHasher for Keccak256Hasher {
    fn hash_node(&self, left: &H256, right: &H256) -> H256 {
        let mut hasher = Keccak256::new();
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        H256::from_slice(&hasher.finalize())
    }
    
    fn hash_leaf(&self, key: &H256, value: &[u8]) -> H256 {
        let mut hasher = Keccak256::new();
        hasher.update(key.as_bytes());
        hasher.update(value);
        H256::from_slice(&hasher.finalize())
    }
}

// Future: Add PoseidonHasher when ZK features needed
// pub struct PoseidonHasher { ... }