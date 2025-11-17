use primitive_types::{H256, U256};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use thiserror::Error;

/// Keccak256("") — hash of empty bytecode
pub const EMPTY_CODE_HASH: H256 = H256([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

/// Empty Merkle Patricia trie root
pub const EMPTY_STORAGE_ROOT: H256 = H256([
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
]);


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: H256,
    pub storage_root: H256,
}

impl Account {
    /// Empty account (zero balance, no code, default nonce/storage)
    pub fn new() -> Self {
        Self {
            nonce: 0,
            balance: U256::zero(),
            code_hash: EMPTY_CODE_HASH,
            storage_root: EMPTY_STORAGE_ROOT,
        }
    }

    /// Create a new externally owned account with the provided balance.
    pub fn new_eoa(balance: U256) -> Self {
        Self {
            balance,
            ..Self::new()
        }
    }

    /// Is this account a smart contract (non-empty code hash)?
    pub fn is_contract(&self) -> bool {
        self.code_hash != EMPTY_CODE_HASH
    }

    pub fn exists(&self) -> bool {
        self.nonce != 0 || self.balance != U256::zero() || self.is_contract()
    }

    pub fn encode(&self) -> Vec<u8> {
        ssz::Encode::as_ssz_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        ssz::Decode::from_ssz_bytes(bytes).map_err(AccountError::from)
    }
}

impl Default for Account {
    fn default() -> Self {
        Self::new()
    }
}

impl Encode for Account {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        // u64 (8) + U256 (32) + H256 (32) + H256 (32) = 104 bytes
        104
    }

    fn ssz_bytes_len(&self) -> usize {
        <Self as Encode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.nonce.to_le_bytes());
    
        let balance_bytes = self.balance.to_big_endian();
        buf.extend_from_slice(&balance_bytes);
    
        buf.extend_from_slice(self.code_hash.as_bytes());
        buf.extend_from_slice(self.storage_root.as_bytes());
    }
}

// Manual SSZ Decode implementation
impl Decode for Account {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        104
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != <Self as Decode>::ssz_fixed_len() {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: <Self as Decode>::ssz_fixed_len(),
            });
        }

        let mut offset = 0;

        // Parse nonce (little-endian u64)
        let nonce = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: 8,
                })?,
        );
        offset += 8;

        // Parse balance (little-endian U256)
        let balance = U256::from_big_endian(&bytes[offset..offset + 32]);
        offset += 32;

        // Parse code_hash (32 bytes)
        let code_hash = H256::from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Parse storage_root (32 bytes)
        let storage_root = H256::from_slice(&bytes[offset..offset + 32]);

        Ok(Self {
            nonce,
            balance,
            code_hash,
            storage_root,
        })
    }
}


#[derive(Debug, Error)]
pub enum AccountError {
    #[error("SSZ decode error: {0:?}")]
    Ssz(DecodeError),
}

impl From<DecodeError> for AccountError {
    fn from(err: DecodeError) -> Self {
        AccountError::Ssz(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_contract_account() -> Account {
        Account {
            nonce: 5,
            balance: U256::from(42u128),
            code_hash: H256::repeat_byte(0x11),
            storage_root: H256::repeat_byte(0xaa),
        }
    }

    #[test]
    fn encode_decode_roundtrip_eoa() {
        let account = Account {
            nonce: 7,
            balance: U256::from(123456u128),
            ..Account::new()
        };

        let encoded = account.encode();
        assert_eq!(encoded.len(), 104, "SSZ encoding must be 104 bytes");
        let decoded = Account::decode(&encoded).expect("decode must succeed");

        assert_eq!(account, decoded);
    }

    #[test]
    fn encode_decode_roundtrip_contract() {
        let account = sample_contract_account();
        let encoded = account.encode();
        assert_eq!(encoded.len(), 104);
        let decoded = Account::decode(&encoded).expect("decode must succeed");
        assert_eq!(account, decoded);
    }

    #[test]
    fn ssz_fixed_length_contract() {
        assert_eq!(<Account as Encode>::ssz_fixed_len(), 104);
        assert!(<Account as Encode>::is_ssz_fixed_len());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let too_short = vec![0u8; 50];
        assert!(Account::decode(&too_short).is_err());

        let too_long = vec![0u8; 200];
        assert!(Account::decode(&too_long).is_err());
    }

    #[test]
    fn detects_eoa_vs_contract() {
        let eoa = Account::new_eoa(U256::from(10u128));
        assert!(!eoa.is_contract());

        let mut contract = eoa.clone();
        contract.code_hash = H256::repeat_byte(0x22);
        assert!(contract.is_contract());
    }

    #[test]
    fn existence_semantics_match_eth() {
        let mut account = Account::new();
        assert!(!account.exists());

        account.nonce = 1;
        assert!(account.exists());

        account.nonce = 0;
        account.balance = U256::from(1u128);
        assert!(account.exists());

        account.balance = U256::zero();
        account.code_hash = H256::repeat_byte(0x33);
        assert!(account.exists());
    }

    #[test]
    fn default_values_match_constants() {
        let default = Account::default();
        assert_eq!(default.nonce, 0);
        assert_eq!(default.balance, U256::zero());
        assert_eq!(default.code_hash, EMPTY_CODE_HASH);
        assert_eq!(default.storage_root, EMPTY_STORAGE_ROOT);
    }

    #[test]
    fn large_balance_roundtrip() {
        let account = Account {
            nonce: u64::MAX,
            balance: U256::MAX,
            code_hash: H256::repeat_byte(0xFF),
            storage_root: H256::repeat_byte(0xEE),
        };

        let encoded = account.encode();
        let decoded = Account::decode(&encoded).unwrap();
        assert_eq!(account, decoded);
    }
}