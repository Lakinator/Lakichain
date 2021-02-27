# Lakichain
My own implementation of a proof-of-work blockchain to understand how they work

Lakichain is a proof-of-work blockchain which contains blocks of transactions consisting of the currency ``` Lakicoin ```
- There is a finite number of transactions per block ``` MAX_TRANSACTIONS_PER_BLOCK ```

### Proof of work
The "mining" of a block basically works by brute forcing a value called ``` nonce ``` so that the hash of the block including this ``` nonce ``` contains
a specified amount of ``` 0's ``` (``` MINING_DIFFICULTY ```) at the start. The hash is base16 so the amount of ``` 0's ``` in binary would be 4-times as much

 ### Cryptography
The transactions are based on public/private key cryptography. They get signed and verified with the ``` ed25519 ``` algorithm using the ring crate

### How transactions work
When a new transaction gets added to the list of ``` current_transactions ``` of a Lakichain object, it is not immediately validated,
it instead is only validated when the mining of a new block is requested, which looks trough all pending transactions, orders them
by the highest fee first and also removes transactions from ``` current_transactions ``` that are already in the blockchain.
You can see if a transaction is pending or valid by using the supplied functions.

### How mining works
A miner can request a block from the chain, mine it and send the nonce he calculated back to the chain. The block he receives also includes
the miner reward transaction where he receives all fees of the transactions included and also a ``` MINING_REWARD ```.
The blocks the miner request get added to a ``` pending_blocks ``` list, which makes sure the ``` nonce ``` sent back from the miner belongs to
the block he originally requested. If someone else mined the block with the same index first, all other miners that mine this block get a invalid response after
sending back their ``` nonce ```

### Balances of addresses
The the current amount of ``` Lakicoin ``` someone owns depends completely on the transactions that are in the blockchain
