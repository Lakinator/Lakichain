use super::Transaction;

use ring::{
    rand,
    signature::{self, KeyPair},
};

///
/// This generates the pkcs8 bytes encoded as a hex string, which can be used to sign or extract the public key
/// - Based on https://briansmith.org/rustdoc/ring/signature/index.html#signing-and-verifying-with-ed25519
///
/// ## Example
/// ```
/// use lakichain::{Lakichain, Transaction, crypto};
///
/// let private_key = crypto::gen_ed25519_keypair();
/// let public_key = crypto::ed25519_public_key(&private_key).unwrap();
///
/// let transaction = Transaction::new(
///     public_key.clone(),
///     String::from("recipient_addr"),
///     String::from("message"),
///     5,
///     1,
/// );
///
/// match crypto::ed25519_sign_transaction(&private_key, &transaction) {
///     Ok(transaction_signed) => {
///         let verified = crypto::ed25519_verify_transaction(
///             &public_key,
///             &transaction,
///             &transaction_signed,
///         );
///
///         println!(
///             "Private key: {}\nPublic key: {}\nTransaction: {:?}\nSigned transaction: {}\nValid sign -> {}",
///             private_key, public_key, transaction, transaction_signed, verified
///         );
///     }
///     Err(e) => println!("Error: {}", e),
/// };
/// ```
///
pub fn gen_ed25519_keypair() -> String {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes =
        signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("Error during keypair generation");

    let private_key = hex::encode(pkcs8_bytes.as_ref());

    return private_key;
}

///
/// Extracts the public key encoded as a hex string from a pkcs8 private key
///
pub fn ed25519_public_key(private_key: &String) -> Result<String, String> {
    let pkcs8_bytes = match hex::decode(private_key) {
        Ok(bytes) => bytes,
        Err(_) => return Err(String::from("Invalid private key")),
    };

    let key_pair = match signature::Ed25519KeyPair::from_pkcs8(&pkcs8_bytes) {
        Ok(pair_bytes) => pair_bytes,
        Err(_) => return Err(String::from("Error during public key generation")),
    };

    let public_key = hex::encode(key_pair.public_key().as_ref());

    return Ok(public_key);
}

///
/// Signs a transaction with the given pkcs8 private key
/// - Transaction sender needs to be the same as the the public key corresponding to the given private key
/// - ``` Ok -> ``` Returns the signed transaction as a hex string
/// - ``` Err -> ``` Returns an error message
///
pub fn ed25519_sign_transaction(private_key: &String, tx: &Transaction) -> Result<String, String> {
    let public_key = match ed25519_public_key(private_key) {
        Ok(key) => key,
        Err(e) => return Err(e),
    };

    if public_key != tx.sender {
        return Err(String::from("Sender doesn't belong to private key"));
    }

    return ed25519_sign(private_key, &tx.as_string());
}

///
/// Returns a signed message encoded as a hex string with a pkcs8 private key
///
fn ed25519_sign(private_key: &String, message: &String) -> Result<String, String> {
    let pkcs8_bytes = match hex::decode(private_key) {
        Ok(bytes) => bytes,
        Err(_) => return Err(String::from("Invalid private key")),
    };

    let key_pair = match signature::Ed25519KeyPair::from_pkcs8(&pkcs8_bytes) {
        Ok(pair_bytes) => pair_bytes,
        Err(_) => return Err(String::from("Error during public key generation")),
    };

    let signed = key_pair.sign(message.as_str().as_bytes());

    let signed = hex::encode(signed.as_ref());

    return Ok(signed);
}

///
/// Verifies that a transaction and it's signature belong to this public key
/// - Also, the sender in the transaction needs to be the same as the given public key
///
pub fn ed25519_verify_transaction(
    public_key: &String,
    transaction: &Transaction,
    transaction_signature: &String,
) -> bool {
    if ed25519_verify(public_key, &transaction.as_string(), transaction_signature) {
        // make sure the sender is the same as the public key that's used to verify it
        return &transaction.sender == public_key;
    }

    return false;
}

///
/// Verifies that a message and it's signature belong to this public key
///
fn ed25519_verify(public_key: &String, message: &String, signature: &String) -> bool {
    let public_key_bytes = match hex::decode(public_key) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature_bytes = match hex::decode(signature) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let verifier = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);

    match verifier.verify(message.as_str().as_bytes(), &signature_bytes) {
        Ok(_) => return true,
        Err(_) => return false,
    };
}
