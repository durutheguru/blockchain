
use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::tx::Transaction;
use std::fs;


#[derive(Debug, Serialize, Deserialize)]
pub struct Blockchain{
    pub chain: Vec<Block>,
    pub difficulty: usize,
    pub pending_transactions: Vec<Transaction>,
}

impl Blockchain {
    pub fn new(difficulty: usize) -> Self {
        let mut blockchain = Blockchain{
            chain: Vec::new(),
            difficulty,
            pending_transactions: Vec::new(),
        };
        blockchain.chain.push(Blockchain::create_genesis_block());
        blockchain
    }

    fn create_genesis_block() -> Block {
        Block::new(0, vec![], "0".to_string())
    }

    // pub fn add_block(&mut self, data: String) {
    //     let previous_block = self.chain.last().unwrap().clone();
    //     let mut new_block = Block::new(
    //         previous_block.index + 1,
    //         data,
    //         previous_block.hash,
    //     );
    //     new_block.mine_block(self.difficulty);
    //     self.chain.push(new_block);
    // }

    pub fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];

            if current.hash != current.calculate_hash() {
                return false;
            }

            if current.previous_hash != previous.hash {
                return false;
            }
        }

        true
    }

    pub fn add_transaction(&mut self, sender: String, recipient: String, amount: f64) {
        // let transaction = Transaction {
        //     sender,
        //     recipient,
        //     amount,
        // };
        // self.pending_transactions.push(transaction);
    }

    pub fn mine_pending_transactions(&mut self, miner_address: String) {
        // let reward_transaction = Transaction {
        //     sender: "System".to_string(),
        //     recipient: miner_address,
        //     amount: 1.0,
        // };
        // self.pending_transactions.push(reward_transaction);

        // let previous_block = self.chain.last().unwrap().clone();
        // let mut new_block = Block::new(
        //     previous_block.index + 1,
        //     self.pending_transactions.clone(),
        //     previous_block.hash,
        // );

        // new_block.mine_block(self.difficulty);
        // self.chain.push(new_block);
        // self.pending_transactions.clear();
    }

    pub fn save_to_file(&self, filename: &str) {
        let data = serde_json::to_string(self).unwrap();
        fs::write(filename, data).expect("Unable to save blockchain to file");
    }

    pub fn load_from_file(filename: &str) -> Self {
        let data = fs::read_to_string(filename).expect("Unable to load blockchain from file");
        serde_json::from_str(&data).unwrap()
    }

}
