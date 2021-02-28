use super::crypto;

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub type Lakicoin = u64;

pub const MAX_MSG_LEN: usize = 128;

///
/// Transactions
/// - The ``` message ``` has a maximum length of ``` MAX_MSG_LEN ```
///
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub timestamp: f64,
    pub sender: String,
    pub recipient: String,
    pub message: String,
    pub amount: Lakicoin,
    pub fee: Lakicoin,
    pub signature: String,
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        return self.sender == other.sender
            && self.recipient == other.recipient
            && self.message == other.message
            && self.amount == other.amount
            && self.fee == other.fee
            && self.signature == other.signature;
    }
}

impl Transaction {
    ///
    /// Returns an unsigned transaction
    ///
    pub fn new(
        sender: String,
        recipient: String,
        message: String,
        amount: Lakicoin,
        fee: Lakicoin,
    ) -> Self {
        let mut msg = message;
        if msg.len() > MAX_MSG_LEN {
            msg.replace_range(MAX_MSG_LEN..msg.len(), "");
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs_f64();

        return Transaction {
            timestamp: now,
            sender: sender,
            recipient: recipient,
            message: msg,
            amount: amount,
            fee: fee,
            signature: String::new(),
        };
    }

    ///
    /// Returns a signed transaction
    /// - ``` Ok() ``` -> Returns signed transaction
    /// - ``` Err() ``` -> Returns an error message
    ///
    pub fn with_signature(
        sender: String,
        recipient: String,
        message: String,
        amount: Lakicoin,
        fee: Lakicoin,
        private_key_sender: &String,
    ) -> Result<Transaction, String> {
        let mut new_transaction = Transaction::new(sender, recipient, message, amount, fee);

        // calculate signature
        match crypto::ed25519_sign_transaction(private_key_sender, &new_transaction) {
            Ok(sig) => {
                new_transaction.signature = sig;
                return Ok(new_transaction);
            }
            Err(e) => return Err(e),
        };
    }

    pub fn as_json(&self) -> String {
        let json = serde_json::to_string(self).expect("JSON error");
        return json;
    }

    pub fn from_json(json: &String) -> Result<Transaction, String> {
        match serde_json::from_str::<Transaction>(json.as_str()) {
            Ok(tx) => return Ok(tx),
            Err(e) => return Err(format!("Error while parsing json: {}", e)),
        }
    }

    pub fn as_string(&self) -> String {
        return format!(
            "{}{}{}{}{}{}",
            self.timestamp, self.sender, self.recipient, self.message, self.amount, self.fee
        );
    }
}
