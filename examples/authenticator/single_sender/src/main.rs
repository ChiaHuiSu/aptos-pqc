use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    PrivateKey, SigningKey, Uniform,
};
use aptos_types::{
    account_address::AccountAddress,
    transaction::{
        authenticator::{AccountAuthenticator, AnyPublicKey, AnySignature, SingleKeyAuthenticator},
        SignedTransaction, TransactionPayload,
    },
    test_helpers::transaction_test_helpers::get_test_signed_transaction,
    transaction::authenticator::AuthenticationKey,
};

fn main() {
    // 1. Generate Ed25519 keypair
    let sender = Ed25519PrivateKey::generate_for_testing();
    let sender_pub = sender.public_key();

    // 2. Derive authentication address using AnyPublicKey (not raw ed25519)
    let single_sender_auth = AuthenticationKey::any_key(AnyPublicKey::ed25519(sender_pub.clone()));
    let single_sender_addr = single_sender_auth.account_address();

    // 3. Create a test raw transaction
    let raw_txn = get_test_signed_transaction(
        single_sender_addr, // sender address
        0,                  // sequence number
        &sender,            // private key
        sender_pub.clone(), // public key
        None,               // payload
        0,                  // expiration timestamp
        0,                  // gas unit price
        None,               // max gas
    )
    .into_raw_transaction();

    // 4. Sign the raw transaction manually
    let signature = sender.sign(&raw_txn).unwrap();

    // 5. Construct authenticator and wrap it into a signed transaction
    let sk_auth = SingleKeyAuthenticator::new(
        AnyPublicKey::ed25519(sender_pub),
        AnySignature::ed25519(signature),
    );
    let account_auth = AccountAuthenticator::single_key(sk_auth);
    let signed_txn = SignedTransaction::new_single_sender(raw_txn, account_auth);

    // 6. Verify signature
    signed_txn.verify_signature().unwrap();

    println!("✅ Single sender Ed25519 transaction verified successfully.");
}
