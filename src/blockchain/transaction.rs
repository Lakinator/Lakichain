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
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        return self.sender == other.sender
            && self.recipient == other.recipient
            && self.message == other.message
            && self.amount == other.amount
            && self.fee == other.fee;
    }
}

impl Transaction {
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
        };
    }

    pub fn as_json(&self) -> String {
        let json = serde_json::to_string(self).expect("JSON error");
        return json;
    }

    pub fn as_string(&self) -> String {
        return format!(
            "{}{}{}{}{}{}",
            self.timestamp, self.sender, self.recipient, self.message, self.amount, self.fee
        );
    }
}
