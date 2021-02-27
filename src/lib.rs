mod blockchain;

pub use blockchain::{crypto, Block, Lakichain, Lakicoin, Nonce, Transaction};

#[cfg(test)]
mod tests {
    use crate::{crypto, Lakichain};

    #[test]
    fn it_works() {
        let private_key_miner = crypto::gen_ed25519_keypair();
        let public_key_miner = crypto::ed25519_public_key(&private_key_miner);
        let private_key_lukas = crypto::gen_ed25519_keypair();
        let public_key_lukas = crypto::ed25519_public_key(&private_key_lukas);

        let mut lchain = Lakichain::new();
        lchain.init();

        let mut block = lchain.get_block_to_mine(&public_key_miner);
        let nonce = Lakichain::mine_block(&mut block);
        let success = lchain.add_block(block.index, nonce, &public_key_miner);
        println!("Mined block {} -> {:?}", block.index, success);

        match success {
            Ok(len) => println!("Length of chain: {}", len),
            Err(e) => println!("Error: {}", e),
        }

        match Lakichain::new_transaction(
            &public_key_miner,
            &public_key_lukas,
            &String::from("Transaction 1"),
            5,
            1,
            &private_key_miner,
        ) {
            Ok((transaction, signature)) => {
                lchain.add_transaction(&transaction, &signature);
            }
            Err(e) => println!("Error: {}", e),
        };

        let mut block = lchain.get_block_to_mine(&public_key_miner);
        let nonce = Lakichain::mine_block(&mut block);
        let success = lchain.add_block(block.index, nonce, &public_key_miner);
        println!("Mined block {} -> {:?}", block.index, success);

        let mut block = lchain.get_block_to_mine(&public_key_miner);
        let nonce = Lakichain::mine_block(&mut block);
        let success = lchain.add_block(block.index, nonce, &public_key_miner);
        println!("Mined block {} -> {:?}", block.index, success);

        println!(
            "\n{} has {} $laki",
            public_key_miner,
            lchain.balance(&public_key_miner)
        );
        println!(
            "{} has {} $laki",
            public_key_lukas,
            lchain.balance(&public_key_lukas)
        );

        println!("\n\n{:#?}", lchain);
    }
}
