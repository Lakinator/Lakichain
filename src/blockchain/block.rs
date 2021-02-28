use super::Transaction;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::SystemTime;

pub type Nonce = u128;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub index: usize,
    pub timestamp: f64,
    pub transactions: Vec<Transaction>,
    pub nonce: Nonce,
    pub previous_hash: String,
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(
                f,
                "Block {}: {{\n   hash={}\n   timestamp={}\n   {:#?}\n   nonce={}\n   previous_hash={}\n}}",
                self.index, self.hash(), self.timestamp, self.transactions, self.nonce, self.previous_hash
            );
    }
}

impl Block {
    pub fn new(index: usize, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs_f64();

        return Block {
            index: index,
            timestamp: now,
            transactions: transactions,
            nonce: 0,
            previous_hash: previous_hash,
        };
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.as_string().as_bytes());
        let result = hex::encode(hasher.finalize());
        return result;
    }

    pub fn as_json(&self) -> String {
        let json = serde_json::to_string(self).expect("JSON error");
        return json;
    }

    pub fn from_json(json: &String) -> Result<Block, String> {
        match serde_json::from_str::<Block>(json.as_str()) {
            Ok(bl) => return Ok(bl),
            Err(e) => return Err(format!("Error while parsing json: {}", e)),
        }
    }

    pub fn as_string(&self) -> String {
        let mut tx_data = String::new();
        for tx in &self.transactions {
            tx_data.push_str(&tx.as_string());
        }
        return format!(
            "{}{}{}{}{}",
            self.index, self.timestamp, tx_data, self.nonce, self.previous_hash
        );
    }
}
