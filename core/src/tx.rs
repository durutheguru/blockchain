
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::{self, Visitor};
use primitive_types::U256;
use std::fmt;
use thiserror::Error;
use sha2::{Sha256, Digest};


use crate::crypto::manager::SignatureManager;
use crate::crypto::signature::SecretKey;
use crate::crypto::{address::{Address, AddressError}, signature::{PublicKey, Signature}};


pub const DECIMAL_PLACES: u32 = 18;
pub const WEI_PER_COIN: u128 = 10_u128.pow(DECIMAL_PLACES);

// Convenient constants for common denominations
pub const GWEI: u128 = 1_000_000_000; // 10^9 wei
pub const MWEI: u128 = 1_000_000;     // 10^6 wei
pub const KWEI: u128 = 1_000;         // 10^3 wei

pub const FEE_LIMIT: u64 = 21_000;


/// Helper to create U256 from coins (e.g., 1.5 -> 1.5 * 10^18 wei)
pub fn coins_to_wei(amount: f64) -> U256 {
    U256::from((amount * WEI_PER_COIN as f64).round() as u128)
}

/// Helper to convert wei to decimal coins
pub fn wei_to_coins(value: U256) -> f64 {
    // Convert to u128 first (safe for most reasonable amounts)
    let wei: u128 = value.low_u128();
    wei as f64 / WEI_PER_COIN as f64
}

/// Format wei as human-readable string
pub fn format_wei(value: U256) -> String {
    let wei = value.low_u128();
    let coins = wei / WEI_PER_COIN;
    let fraction = wei % WEI_PER_COIN;
    format!("{}.{:018}", coins, fraction)
}


/// Custom serialization for U256 (as hex string)
mod u256_serde {
    use super::*;

    pub fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error> 
    where 
        S : Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error> 
    where 
        D : Deserializer<'de>,
    {
        struct U256Visitor;

        impl<'de> Visitor<'de> for U256Visitor {
            type Value = U256;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a hex string representing U256")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where 
                E: de::Error,
            {
                let v = v.trim_start_matches("0x");
                U256::from_str_radix(v, 16)
                    .map_err(|e| E::custom(format!("Invalid 256: {}", e)))
            }
        }

        deserializer.deserialize_str(U256Visitor)
    }

}


/// Unsigned transaction for creating signatures
#[derive(Debug, Clone, Serialize)]
pub struct UnsignedTransaction {
    pub from: Address,
    pub to: Address,

    #[serde(with = "u256_serde")]
    pub value: U256,
    
    pub nonce: u64,
    pub data: Vec<u8>,
    pub fee_limit: u64,
    
    #[serde(with = "u256_serde")]
    pub fee_price: U256,
    
    pub timestamp: i64,
}

impl UnsignedTransaction {

    pub fn new_transfer(
        from: Address,
        to: Address,
        value: U256,
        nonce: u64,
        fee_price: U256,
    ) -> Self {
        Self {
            from,
            to,
            value,
            nonce,
            data: Vec::new(),
            fee_limit: FEE_LIMIT,
            fee_price,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Create a contract call transaction
    pub fn new_contract_call(
        from: Address,
        to: Address,
        value: U256,
        nonce: u64,
        data: Vec<u8>,
        fee_limit: u64,
        fee_price: U256,
    ) -> Self {
        Self {
            from,
            to,
            value,
            nonce,
            data,
            fee_limit,
            fee_price,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Serialize for signing
    pub fn to_signable_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Serialization cannot fail")
    }

    /// Sign and convert to full Transaction
    pub fn sign(
        self,
        secret_key: &SecretKey,
        public_key: &PublicKey,
        manager: &SignatureManager,
    ) -> Result<Transaction, TransactionError> {
        let message = self.to_signable_bytes();
        let signature = manager.sign(&message, secret_key)
            .map_err(|e| TransactionError::SigningFailed(e.to_string()))?;
        
        Ok(Transaction {
            from: self.from,
            to: self.to,
            value: self.value,
            nonce: self.nonce,
            data: self.data,
            fee_limit: self.fee_limit,
            fee_price: self.fee_price,
            timestamp: self.timestamp,
            signature,
            public_key: public_key.clone(),
        })
    }

}


#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Invalid public key")]
    InvalidPublicKey,
    
    #[error("Address mismatch: signature address {signature_addr} != declared from address {from_addr}")]
    AddressMismatch {
        signature_addr: String,
        from_addr: String,
    },
    
    #[error("Invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },
    
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: String, available: String },
    
    #[error("Transaction expired: timestamp {timestamp}")]
    Expired { timestamp: i64 },
    
    #[error("Invalid value: {0}")]
    InvalidValue(String),
    
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    
    #[error("Gas limit exceeded")]
    OutOfGas,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender's address derived from public key
    pub from: Address,
    
    /// Recipient's address (or contract address)
    pub to: Address,
    
    /// Amount in wei (10^18 = 1 coin)
    #[serde(with = "u256_serde")]
    pub value: U256,
    
    /// Nonce to prevent replay attacks
    /// Must increment for each transaction from same address
    pub nonce: u64,
    
    /// Optional arbitrary data payload (for smart contracts)
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,

    /// Maximum fee units this transaction can consume
    pub fee_limit: u64,
    
    /// Price per fee unit (in wei)
    #[serde(with = "u256_serde")]
    pub fee_price: U256,
    
    /// Timestamp to aid in ordering and validation
    pub timestamp: i64, // Unix timestamp
    
    /// Cryptographic signature of transaction
    pub signature: Signature,
    
    /// Public key of sender (to verify signature & derive address)
    pub public_key: PublicKey,
}

impl Transaction {
    /// Calculate maximum cost (value + fees)
    pub fn max_cost(&self) -> U256 {
        let fee_cost = U256::from(self.fee_limit) * self.fee_price;
        self.value + fee_cost
    }
    
    /// Calculate actual cost after execution
    pub fn actual_cost(&self, fee_used: u64) -> U256 {
        let fee_cost = U256::from(fee_used) * self.fee_price;
        self.value + fee_cost
    }
    
    /// Verify transaction signature and basic validity
    pub fn verify(&self, manager: &SignatureManager) -> Result<(), TransactionError> {
        // 1. Reconstruct unsigned transaction
        let unsigned = UnsignedTransaction {
            from: self.from.clone(),
            to: self.to.clone(),
            value: self.value,
            nonce: self.nonce,
            data: self.data.clone(),
            fee_limit: self.fee_limit,
            fee_price: self.fee_price,
            timestamp: self.timestamp,
        };
        
        let message = unsigned.to_signable_bytes();
        
        // 2. Verify cryptographic signature
        let valid = manager.verify(&message, &self.signature, &self.public_key)
            .map_err(|_| TransactionError::InvalidSignature)?;
        
        if !valid {
            return Err(TransactionError::InvalidSignature);
        }
        
        // 3. Verify address matches public key
        let network = self.from.network()
            .map_err(|_: AddressError| TransactionError::InvalidPublicKey)?;
        
        let derived_address = self.public_key.derive_address(network)
            .map_err(|_| TransactionError::InvalidPublicKey)?;
        
        if derived_address != self.from {
            return Err(TransactionError::AddressMismatch {
                signature_addr: derived_address.to_string(),
                from_addr: self.from.to_string(),
            });
        }
        
        // 4. Basic sanity checks
        if self.value == U256::zero() && self.data.is_empty() {
            return Err(TransactionError::InvalidValue(
                "Transaction has no value and no data".to_string()
            ));
        }
        
        if self.fee_limit == 0 {
            return Err(TransactionError::InvalidValue(
                "Fee limit cannot be zero".to_string()
            ));
        }
        
        // 5. Timestamp validation
        let now = chrono::Utc::now().timestamp();
        if self.timestamp > now + 300 {
            return Err(TransactionError::Expired { 
                timestamp: self.timestamp 
            });
        }
        
        Ok(())
    }
    
    /// Calculate transaction hash
    pub fn hash(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("Serialization cannot fail");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        format!("{:x}", hasher.finalize())
    }
    
    /// Check if this is a contract call (has data)
    pub fn is_contract_call(&self) -> bool {
        !self.data.is_empty()
    }
}

