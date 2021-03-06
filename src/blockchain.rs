mod block;
pub mod crypto;
mod transaction;

pub use block::{Block, Nonce};
pub use transaction::{Lakicoin, Transaction};

use serde::{Deserialize, Serialize};
use std::time::Instant;

const MINING_REWARD: Lakicoin = 10;
const MAX_TRANSACTIONS_PER_BLOCK: usize = 128;
const MINING_DIFFICULTY: &str = "0000";
const GENESIS_PREV_HASH: &str = "0";

#[derive(Serialize, Deserialize, Debug)]
pub struct Lakichain {
    chain: Vec<Block>,
    current_transactions: Vec<Transaction>,
    pending_blocks: Vec<(Block, String)>, /* contains blocks and their corresponding miner addresses */
}

impl Lakichain {
    pub fn new() -> Self {
        let blockchain = Lakichain {
            chain: Vec::new(),
            current_transactions: Vec::new(),
            pending_blocks: Vec::new(),
        };
        return blockchain;
    }

    ///
    /// Create genesis block
    ///
    pub fn init(&mut self) {
        let genesis = Block::new(
            1,
            self.current_transactions.clone(),
            String::from(GENESIS_PREV_HASH),
        );
        self.chain.push(genesis);
    }

    ///
    /// Replaces the current chain and validates it
    /// - ``` Ok ``` -> size of chain
    /// - ``` Err ``` -> first index of invalid block
    ///
    pub fn replace_chain(&mut self, chain: Vec<Block>) -> Result<usize, usize> {
        self.chain = chain;
        return self.validate_chain();
    }

    ///
    /// Returns the next block to be mined
    ///
    /// - Prefers transactions with higher fees
    /// - Only a maximum of ``` MAX_TRANSACTIONS_PER_BLOCK - 1 ``` transactions are included in the block to make room for the mining reward transaction
    /// - Checks if added transactions are valid (takes already to this block added transactions in consideration)
    /// - Automatically removes transactions from the ``` current_transactions ``` if they are already in the chain
    ///
    fn next_block(&mut self) -> Block {
        // sort transactions by fee descending
        self.current_transactions.sort_by(|a, b| {
            return b.fee.cmp(&a.fee);
        });

        // max transaction count that go into the next block
        // note: it should be one less, because the block still needs space for the reward transaction
        let mut tx_count = self.current_transactions.len();
        if tx_count > MAX_TRANSACTIONS_PER_BLOCK - 1 {
            tx_count = MAX_TRANSACTIONS_PER_BLOCK - 1
        }

        // validate transactions // TODO: -> very heavy workload, maybe let the miner do this?
        // extract transactions that should be in the next block
        // invalid transaction get removed -> only transactions that are already in the chain

        let mut valid_transactions: Vec<Transaction> = Vec::new();
        let mut i: usize = 0;
        let mut invalid_transactions: Vec<usize> = Vec::new();

        while i < tx_count && i < self.current_transactions.len() {
            let tx = &self.current_transactions[i];

            if self.validate_transaction(tx, &valid_transactions) {
                valid_transactions.push(tx.clone());
            } else {
                if self.chain_contains_transaction(tx) {
                    invalid_transactions.push(i);
                }
            }

            i += 1;
        }

        // remove invalid transactions (starting with the biggest index to avoid errors)
        for index in invalid_transactions.iter().rev() {
            self.current_transactions.remove(index.clone());
        }

        return Block::new(
            self.chain.len() + 1,
            valid_transactions,
            self.last_block().hash(),
        );
    }

    ///
    /// This block can be mined and the nonce that was calculated can be sent back to the chain
    /// It gets stored on a list together with the miner address, so when the miner sends back the nonce it can be validated
    ///
    /// > The reward for mining is already in this block
    ///
    /// ## Example
    /// ```
    /// use lakichain::{Lakichain, crypto};
    /// let private_key_miner = crypto::gen_ed25519_keypair();
    /// let public_key_miner = crypto::ed25519_public_key(&private_key_miner).unwrap();
    ///
    /// let mut lchain = Lakichain::new();
    /// lchain.init();
    ///
    /// let mut block = lchain.get_block_to_mine(&public_key_miner);
    /// let nonce = Lakichain::mine_block(&mut block);
    /// let success = lchain.add_block(block.index, nonce, &public_key_miner);
    ///
    /// match success {
    ///     Ok(len) => println!("Length of chain: {}", len),
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    ///
    pub fn get_block_to_mine(&mut self, reward_address: &String) -> Block {
        let mut n_block = self.next_block();

        // Reward transaction
        let mut reward_with_fees: Lakicoin = MINING_REWARD;

        // add fees from the transactions included in the block
        for tx in &n_block.transactions {
            reward_with_fees += tx.fee;
        }

        let reward_tx = Transaction::new(
            String::from("0"),
            reward_address.clone(),
            format!("Reward for mining block {}", n_block.index),
            reward_with_fees,
            0,
        );

        n_block.transactions.push(reward_tx);

        self.pending_blocks
            .push((n_block.clone(), reward_address.clone()));

        return n_block;
    }

    ///
    /// Add block to the chain that a miner mined
    /// - ``` Ok ``` -> size of chain
    /// - ``` Err ``` -> error message
    /// - Note: pending blocks with outdated index get removed here
    ///
    pub fn add_block(
        &mut self,
        index: usize,
        nonce: Nonce,
        miner_address: &String,
    ) -> Result<usize, String> {
        let last_index: usize = self.last_block().index;

        // remove outdated blocks
        // -> only pending blocks remain which index is one more than the current latest block on the chain
        self.pending_blocks.retain(|(pending_block, _miner)| {
            return pending_block.index == last_index + 1;
        });

        // is the given index outdatet?
        if index == self.last_block().index + 1 {
            // look for the right pending block
            let mut i: usize = 0;
            for (pending_block, miner) in &self.pending_blocks {
                if miner == miner_address && pending_block.index == index {
                    let mut block_clone = pending_block.clone();
                    block_clone.nonce = nonce;
                    // test if the supplied nonce produces a valid hash
                    if Lakichain::is_valid_hash(&block_clone.hash()) {
                        // push block to the chain and remove it from the pending list
                        self.chain.push(block_clone);
                        self.pending_blocks.remove(i);
                        match self.validate_chain() {
                            Ok(len) => return Ok(len),
                            Err(index) => {
                                return Err(format!("Invalid chain starting at {}", index));
                            }
                        }
                    } else {
                        return Err(format!(
                            "The nonce {} doesn't produce a valid hash for block {}",
                            nonce, index
                        ));
                    }
                }
                i += 1;
            }
        } else {
            return Err(format!(
                "Block with index {} was already mined and added to the chain",
                index
            ));
        }

        return Err(String::from("Pending block not found"));
    }

    ///
    /// Returns a new transaction with a signature that can be passed to ``` add_transaction ``` to add it to the pool of transactions
    /// - Signs the transaction with the given ``` private_key ```
    /// - Note: private_key needs to belong to the sender (public key) of the transaction
    /// - ``` Ok() ``` -> Returns a new transaction that can be added to the pool of transactions with ``` add_transaction ```
    /// - ``` Err() ``` -> Returns an error message
    ///
    /// ## Example
    /// ```
    /// use lakichain::{Lakichain, crypto};
    ///
    /// let private_key_1 = crypto::gen_ed25519_keypair();
    /// let public_key_1 = crypto::ed25519_public_key(&private_key_1).unwrap();
    /// let private_key_2 = crypto::gen_ed25519_keypair();
    /// let public_key_2 = crypto::ed25519_public_key(&private_key_2).unwrap();
    ///
    /// let mut lchain = Lakichain::new();
    /// lchain.init();
    ///
    /// match Lakichain::new_transaction(&public_key_1, &public_key_2, &String::from("Address 1 sends 5 $laki to Address 2 with a fee of 1 $laki"), 5, 1, &private_key_1) {
    ///     Ok(transaction) => {
    ///         let success = lchain.add_transaction(&transaction);
    ///         println!("Successfully added transaction to pool? -> {}", success);
    ///     },
    ///     Err(e) => println!("Error: {}", e),
    /// };
    /// ```
    ///
    pub fn new_transaction(
        sender: &String,
        recipient: &String,
        message: &String,
        amount: Lakicoin,
        fee: Lakicoin,
        private_key: &String,
    ) -> Result<Transaction, String> {
        return Transaction::with_signature(
            sender.clone(),
            recipient.clone(),
            message.clone(),
            amount,
            fee,
            private_key,
        );
    }

    ///
    /// Adds a transaction to the current transaction pool
    /// - Returns true if the signature is valid and it got added to the transaction pool
    ///
    pub fn add_transaction(&mut self, transaction: &Transaction) -> bool {
        let valid = crypto::ed25519_verify_transaction(
            &transaction.sender,
            transaction,
            &transaction.signature,
        );

        if valid {
            self.current_transactions.push(transaction.clone());
        }

        return valid;
    }

    ///
    /// Returns a reference to the last block of the chain
    ///
    fn last_block(&self) -> &Block {
        return &self.chain[self.chain.len() - 1];
    }

    ///
    /// Validates a transaction
    /// - Valid addresses?
    /// - Enough balance?
    /// - Transaction already on the chain?
    /// - Includes valid signature?
    /// - open_txs -> checks additional transactions for balance
    ///
    fn validate_transaction(&self, tx: &Transaction, open_txs: &Vec<Transaction>) -> bool {
        let mut _valid = true;
        let sender = &tx.sender;
        let recipient = &tx.recipient;

        if !Lakichain::validate_address(sender)
            || !Lakichain::validate_address(recipient)
            || self.chain_contains_transaction(tx)
            || !crypto::ed25519_verify_transaction(&tx.sender, tx, &tx.signature)
        {
            _valid = false;
        } else {
            let amount = tx.amount + tx.fee;
            let mut _sender_balance: Lakicoin = 0;

            _sender_balance = self.balance(sender);
            Lakichain::balance_from_tx(&mut _sender_balance, open_txs, sender);

            _valid = _sender_balance >= amount;
        }

        return _valid;
    }

    ///
    /// Returns wether a transaction is already on the chain or not
    /// - Note: A transaction can be in the chain and in the pool of pending transactions at the same time,
    /// because a transaction gets removed from the pool only after it is already in the chain AND the next block is requested and
    /// put in the chain. This makes sure a transaction is really valid after at least another block is in the chain,
    /// so if the chain gets replaced the transaction is still pending
    ///
    pub fn chain_contains_transaction(&self, tx: &Transaction) -> bool {
        for block in &self.chain {
            for block_tx in &block.transactions {
                if block_tx == tx {
                    return true;
                }
            }
        }

        return false;
    }

    ///
    /// Returns wether a transaction is in the pool of current pending transactions
    /// - Note: A transaction can be in the chain and in the pool of pending transactions at the same time,
    /// because a transaction gets removed from the pool only after it is already in the chain AND the next block is requested and
    /// put in the chain. This makes sure a transaction is really valid after at least another block is in the chain,
    /// so if the chain gets replaced the transaction is still pending
    ///
    pub fn is_transaction_pending(&self, tx: &Transaction) -> bool {
        for p_tx in &self.current_transactions {
            if p_tx == tx {
                return true;
            }
        }

        return false;
    }

    ///
    /// TODO: Address format: 0x1337...
    ///
    pub fn validate_address(_address: &String) -> bool {
        return true;
    }

    ///
    /// Calculates the balance of an address by looking at transactions of all blocks
    /// (including fees)
    ///
    pub fn balance(&self, address: &String) -> Lakicoin {
        let mut balance: Lakicoin = 0;

        for bl in &self.chain {
            Lakichain::balance_from_tx(&mut balance, &bl.transactions, address);
        }

        return balance;
    }

    //
    /// Calculates the balance of an address by looking at the given transactions
    /// - directly affects the given ``` balance ```
    ///
    fn balance_from_tx(balance: &mut Lakicoin, transactions: &Vec<Transaction>, address: &String) {
        for c_tx in transactions {
            if &c_tx.recipient == address {
                *balance += c_tx.amount;
            }
            if &c_tx.sender == address {
                let cost = c_tx.amount + c_tx.fee;

                // make sure the unsigned integer doesn't overflow (e.g. subtracting more from it)
                if cost >= *balance {
                    *balance = 0;
                } else {
                    *balance -= cost;
                }
            }
        }
    }

    ///
    /// Validates all blocks within the current chain
    /// - ``` Ok ``` -> length of chain
    /// - ``` Err ``` -> first index of invalid block
    ///
    /// # How?
    /// - Validates nonce/content of each block by hashing the block
    /// - Calculates hash of the previous block and tests if the ``` previous_hash ``` value in the current block is the same
    ///
    /// > Note: The nonce/content of each block is only validated for the current block and not each time the hash of the previous block
    /// > is calculated, because the previous block is already validated at this point
    ///
    pub fn validate_chain(&self) -> Result<usize, usize> {
        let mut valid = true;
        let mut index: usize = 0;
        for (i, block) in self.chain.iter().enumerate() {
            // make sure the block got a valid nonce
            let curr_hash = block.hash();
            let mut valid_hash = Lakichain::is_valid_hash(&curr_hash);
            // validate previous hash
            let previous_hash: String;
            let valid_previous_hash: bool;
            if i == 0 {
                previous_hash = String::from(GENESIS_PREV_HASH);
                valid_hash = true; // first block doesn't have a valid hash // FIXME maybe
            } else {
                previous_hash = self.chain[i - 1].hash();
            }
            valid_previous_hash = block.previous_hash == previous_hash;
            valid = valid_hash && valid_previous_hash;
            if !valid {
                index = i;
                break;
            }
        }

        if valid {
            return Ok(self.chain.len());
        } else {
            return Err(index);
        }
    }

    ///
    /// Returns this chain as a json String
    ///
    pub fn to_json(&self) -> String {
        let json = serde_json::to_string(self).expect("JSON error");
        return json;
    }

    ///
    /// Returns a Lakichain from a json string
    /// - ``` Ok ``` -> Lakichain
    /// - ``` Err ``` -> error message
    ///
    pub fn from_json(json: &String) -> Result<Lakichain, String> {
        match serde_json::from_str::<Lakichain>(json.as_str()) {
            Ok(chain) => return Ok(chain),
            Err(e) => return Err(format!("Error while parsing json: {}", e)),
        }
    }

    ///
    /// Mines a given block by calculating its nonce
    ///
    pub fn mine_block(block: &mut Block) -> Nonce {
        let start = Instant::now();
        Lakichain::calculate_nonce(block);
        let duration = start.elapsed();

        println!(
            "Mined block {} with hash: {} in {:?}",
            block.index,
            block.hash(),
            duration
        );

        return block.nonce;
    }

    ///
    /// Keeps hashing the block until a value (nonce) is found so the hash starts with the string ``` MINING_DIFFICULTY ```
    ///
    fn calculate_nonce(block: &mut Block) {
        let mut hash = block.hash();
        while !Lakichain::is_valid_hash(&hash) {
            block.nonce += 1;
            hash = block.hash();
        }
    }

    ///
    /// Checks a given String if it's a valid hash
    ///
    fn is_valid_hash(hash: &String) -> bool {
        return hash.starts_with(MINING_DIFFICULTY);
    }
}
