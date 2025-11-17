use std::{fmt, path::Path, sync::Arc};

use primitive_types::{H256, U256};
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use thiserror::Error;

use crate::{
    crypto::{
        address::{Address, AddressError},
        algorithm::SignatureAlgorithm,
    },
    state::account::{Account, AccountError},
};

const ACCOUNTS_CF: &str = "accounts";
const STORAGE_CF: &str = "storage";
const CODE_CF: &str = "code";
const TRIE_NODES_CF: &str = "trie_nodes";

/// All persistent column families used by the World State Engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnFamily {
    Accounts,
    Storage,
    Code,
    TrieNodes,
}

impl ColumnFamily {
    fn name(self) -> &'static str {
        match self {
            ColumnFamily::Accounts => ACCOUNTS_CF,
            ColumnFamily::Storage => STORAGE_CF,
            ColumnFamily::Code => CODE_CF,
            ColumnFamily::TrieNodes => TRIE_NODES_CF,
        }
    }
}

impl fmt::Display for ColumnFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Thin wrapper around RocksDB with typed helpers for the world state.
#[derive(Clone)]
pub struct StateDatabase {
    db: Arc<DB>,
}

impl StateDatabase {
    /// Open (or create) a RocksDB instance with the required column families.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DbError> {
        let mut opts = default_options();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let descriptors = column_family_descriptors(&opts);
        let db = DB::open_cf_descriptors(&opts, path, descriptors)?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Read an account object by address.
    pub fn get_account(&self, address: &Address) -> Result<Option<Account>, DbError> {
        let key = encode_account_key(address)?;
        if let Some(bytes) = self.db.get_cf(self.cf(ColumnFamily::Accounts)?, &key)? {
            let account = Account::decode(&bytes)?;
            Ok(Some(account))
        } else {
            Ok(None)
        }
    }

    /// Persist (or update) an account object.
    pub fn put_account(&self, address: &Address, account: &Account) -> Result<(), DbError> {
        let key = encode_account_key(address)?;
        self.db
            .put_cf(self.cf(ColumnFamily::Accounts)?, key, account.encode())?;
        Ok(())
    }

    /// Delete an account entry (used for pruning / rent).
    pub fn delete_account(&self, address: &Address) -> Result<(), DbError> {
        let key = encode_account_key(address)?;
        self.db
            .delete_cf(self.cf(ColumnFamily::Accounts)?, key)?;
        Ok(())
    }

    /// Read single storage slot: (address, slot) → U256.
    pub fn get_storage(&self, address: &Address, slot: &H256) -> Result<Option<U256>, DbError> {
        let key = encode_storage_key(address, slot)?;
        if let Some(bytes) = self.db.get_cf(self.cf(ColumnFamily::Storage)?, &key)? {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes);
            Ok(Some(U256::from_big_endian(&buf)))
        } else {
            Ok(None)
        }
    }

    /// Write storage slot
    pub fn put_storage(
        &self,
        address: &Address,
        slot: &H256,
        value: &U256,
    ) -> Result<(), DbError> {
        let key = encode_storage_key(address, slot)?;
        let mut buf = [0u8; 32];
        value.write_as_big_endian(&mut buf);
        self.db
            .put_cf(self.cf(ColumnFamily::Storage)?, key, buf)?;
        Ok(())
    }

    /// Delete storage slot entry.
    pub fn delete_storage(&self, address: &Address, slot: &H256) -> Result<(), DbError> {
        let key = encode_storage_key(address, slot)?;
        self.db
            .delete_cf(self.cf(ColumnFamily::Storage)?, key)?;
        Ok(())
    }

    /// Store contract bytecode (deduplicated by hash).
    pub fn put_code(&self, code_hash: &H256, code: &[u8]) -> Result<(), DbError> {
        self.db
            .put_cf(self.cf(ColumnFamily::Code)?, code_hash.as_bytes(), code)?;
        Ok(())
    }

    /// Fetch contract bytecode by hash.
    pub fn get_code(&self, code_hash: &H256) -> Result<Option<Vec<u8>>, DbError> {
        let data = self.db.get_cf(self.cf(ColumnFamily::Code)?, code_hash.as_bytes())?;
        Ok(data)
    }

    /// Store serialized trie node by hash.
    pub fn put_trie_node(&self, hash: &H256, node_bytes: &[u8]) -> Result<(), DbError> {
        self.db
            .put_cf(self.cf(ColumnFamily::TrieNodes)?, hash.as_bytes(), node_bytes)?;
        Ok(())
    }

    /// Retrieve serialized trie node bytes.
    pub fn get_trie_node(&self, hash: &H256) -> Result<Option<Vec<u8>>, DbError> {
        let bytes = self
            .db
            .get_cf(self.cf(ColumnFamily::TrieNodes)?, hash.as_bytes())?;
        Ok(bytes)
    }

    /// Create a new RocksDB write batch (caller fills it).
    pub fn new_write_batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Atomically commit a RocksDB write batch.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<(), DbError> {
        self.db.write(batch)?;
        Ok(())
    }

    /// Obtain a RocksDB snapshot for consistent multi-read operations.
    pub fn snapshot(&self) -> rocksdb::Snapshot<'_> {
        self.db.snapshot()
    }

    fn cf(&self, cf: ColumnFamily) -> Result<&rocksdb::ColumnFamily, DbError> {
        self.db
            .cf_handle(cf.name())
            .ok_or(DbError::MissingColumnFamily(cf))
    }
}

/// Errors produced by the database layer.
#[derive(Debug, Error)]
pub enum DbError {
    #[error("rocksdb error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    #[error("account decode error: {0}")]
    AccountDecode(#[from] AccountError),

    #[error("address encoding error: {0}")]
    AddressEncoding(#[from] AddressError),

    #[error("missing column family: {0}")]
    MissingColumnFamily(ColumnFamily),
}

// === internal helpers ======================================================

fn default_options() -> Options {
    let mut opts = Options::default();
    opts.increase_parallelism(num_cpus::get() as i32);
    opts.set_use_fsync(false);
    opts.set_bytes_per_sync(1 << 20); // 1 MB
    opts.set_compaction_style(rocksdb::DBCompactionStyle::Level);
    opts.set_max_write_buffer_number(3);
    opts.set_write_buffer_size(256 << 20); // 256 MB
    opts
}

fn column_family_descriptors(opts: &Options) -> Vec<ColumnFamilyDescriptor> {
    [
        ColumnFamily::Accounts,
        ColumnFamily::Storage,
        ColumnFamily::Code,
        ColumnFamily::TrieNodes,
    ]
    .into_iter()
    .map(|cf| ColumnFamilyDescriptor::new(cf.name(), opts.clone()))
    .collect()
}

fn encode_account_key(address: &Address) -> Result<[u8; 22], AddressError> {
    let mut key = [0u8; 22];
    key[0] = address.network()? as u8;
    key[1] = address
        .algorithm()?
        .to_u8();
    key[2..].copy_from_slice(address.payload());
    Ok(key)
}

fn encode_storage_key(address: &Address, slot: &H256) -> Result<[u8; 54], AddressError> {
    let mut key = [0u8; 54];
    key[..22].copy_from_slice(&encode_account_key(address)?);
    key[22..].copy_from_slice(slot.as_bytes());
    Ok(key)
}

// === tests =================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::signature::PublicKey,
        state::account::{EMPTY_CODE_HASH, EMPTY_STORAGE_ROOT},
    };
    use rand::RngCore;
    use std::{sync::Arc, thread};
    use tempfile::TempDir;

    fn sample_public_key() -> PublicKey {
        let bytes = vec![0xAB; SignatureAlgorithm::Ed25519.public_key_size()];
        PublicKey::new(SignatureAlgorithm::Ed25519, bytes).unwrap()
    }

    fn sample_address() -> Address {
        Address::derive(&sample_public_key(), crate::crypto::address::NetworkId::Testnet).unwrap()
    }

    fn sample_account() -> Account {
        Account {
            nonce: 7,
            balance: U256::from(1337u128),
            code_hash: EMPTY_CODE_HASH,
            storage_root: EMPTY_STORAGE_ROOT,
        }
    }

    #[test]
    fn open_creates_all_column_families() {
        let tmp = TempDir::new().unwrap();
        let db = StateDatabase::open(tmp.path()).unwrap();

        for cf in [
            ColumnFamily::Accounts,
            ColumnFamily::Storage,
            ColumnFamily::Code,
            ColumnFamily::TrieNodes,
        ] {
            assert!(db.cf(cf).is_ok(), "missing column family {cf}");
        }
    }

    #[test]
    fn account_crud_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let db = StateDatabase::open(tmp.path()).unwrap();
        let addr = sample_address();
        let account = sample_account();

        db.put_account(&addr, &account).unwrap();
        let fetched = db.get_account(&addr).unwrap().expect("account present");
        assert_eq!(account, fetched);

        db.delete_account(&addr).unwrap();
        assert!(db.get_account(&addr).unwrap().is_none());
    }

    #[test]
    fn storage_crud_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let db = StateDatabase::open(tmp.path()).unwrap();
        let addr = sample_address();
        let slot = H256::from_low_u64_be(42);
        let value = U256::from(0xDEADBEEFu64);

        db.put_storage(&addr, &slot, &value).unwrap();
        let fetched = db
            .get_storage(&addr, &slot)
            .unwrap()
            .expect("storage value present");
        assert_eq!(value, fetched);

        db.delete_storage(&addr, &slot).unwrap();
        assert!(db.get_storage(&addr, &slot).unwrap().is_none());
    }

    #[test]
    fn code_and_trie_node_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let db = StateDatabase::open(tmp.path()).unwrap();

        let code_hash = H256::from_low_u64_be(1);
        let code = vec![1, 2, 3, 4, 5];
        db.put_code(&code_hash, &code).unwrap();
        assert_eq!(
            db.get_code(&code_hash).unwrap().as_deref(),
            Some(code.as_slice())
        );

        let node_hash = H256::from_low_u64_be(2);
        let node_bytes = vec![9, 9, 9];
        db.put_trie_node(&node_hash, &node_bytes).unwrap();
        assert_eq!(
            db.get_trie_node(&node_hash).unwrap().as_deref(),
            Some(node_bytes.as_slice())
        );
    }

    #[test]
    fn batch_write_is_atomic() {
        let tmp = TempDir::new().unwrap();
        let db = StateDatabase::open(tmp.path()).unwrap();
        let addr = sample_address();
        let account = sample_account();

        let mut batch = db.new_write_batch();
        let key = encode_account_key(&addr).unwrap();
        batch.put_cf(db.cf(ColumnFamily::Accounts).unwrap(), key, account.encode());

        db.write_batch(batch).unwrap();
        assert!(db.get_account(&addr).unwrap().is_some());
    }

    #[test]
    fn concurrent_reads_and_writes() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(StateDatabase::open(tmp.path()).unwrap());
        let threads = 8usize;

        thread::scope(|scope| {
            for i in 0..threads {
                let db = Arc::clone(&db);
                scope.spawn(move || {
                    let mut rng = rand::thread_rng();
                    for _ in 0..100 {
                        let mut slot = H256::zero();
                        let mut bytes = slot.as_bytes_mut();
                        rng.fill_bytes(&mut bytes);
                        slot = H256::from_slice(&bytes);

                        let addr = sample_address();
                        let value = U256::from(i as u64);
                        db.put_storage(&addr, &slot, &value).unwrap();
                        let _ = db.get_storage(&addr, &slot).unwrap();
                    }
                });
            }
        });
    }
}
