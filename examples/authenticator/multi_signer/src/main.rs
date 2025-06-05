use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    multi_ed25519::{MultiEd25519PublicKey, MultiEd25519Signature},
    test_utils::KeyPair,
    PrivateKey, SigningKey,
    Uniform,
};
use aptos_types::{
    account_address::AccountAddress,
    transaction::{
        authenticator::{AccountAuthenticator, AnyPublicKey, AnySignature, MultiKeyAuthenticator},
        SignedTransaction, TransactionPayload,
    },
    test_helpers::transaction_test_helpers::get_test_signed_transaction,
    transaction::authenticator::AuthenticationKey,
};

fn main() {
    // 1. Generate multiple Ed25519 keypairs (e.g. 3 signers)
    let sk0 = Ed25519PrivateKey::generate_for_testing();
    let pk0 = sk0.public_key();
    let sk1 = Ed25519PrivateKey::generate_for_testing();
    let pk1 = sk1.public_key();
    let sk2 = Ed25519PrivateKey::generate_for_testing();
    let pk2 = sk2.public_key();

    // 2. Create MultiEd25519PublicKey with threshold (e.g. 2-of-3)
    let pubkeys = vec![pk0.clone(), pk1.clone(), pk2.clone()];
    let threshold = 2u8;
    let multi_pubkey = MultiEd25519PublicKey::new(pubkeys, threshold).unwrap();

    // 3. Derive account address from MultiEd25519PublicKey
    let auth_key = AuthenticationKey::multi_ed25519(&multi_pubkey);
    let sender_addr = auth_key.account_address();

    // 4. Create a raw transaction
    let raw_txn = get_test_signed_transaction(
        sender_addr,
        0,
        &sk0,          // any one private key can sign raw txn to generate signatures
        pk0.clone(),
        None,
        0,
        0,
        None,
    )
    .into_raw_transaction();

    // 5. Each signer signs the raw transaction
    let sig0 = sk0.sign(&raw_txn).unwrap();
    let sig1 = sk1.sign(&raw_txn).unwrap();
    // Optionally, sig2 if needed, but threshold is 2 so 2 signatures suffice

    // 6. Construct MultiEd25519Signature with signatures and signer indices
    // signers index must correspond to the order of public keys in multi_pubkey
    let signatures = vec![(sig0.clone(), 0), (sig1.clone(), 1)];
    let multi_sig = MultiEd25519Signature::new(signatures).unwrap();

    // 7. Construct MultiKeyAuthenticator wrapping multi-ed25519 keys and signatures
    let multi_key_auth = MultiKeyAuthenticator::new(
        multi_pubkey.into(),              // AnyPublicKey
        vec![
            (0, AnySignature::Ed25519 { signature: sig0.clone()}),
            (1, AnySignature::Ed25519 { signature: sig1.clone()}),
            ]).unwrap();    // AnySignature

    let account_auth = AccountAuthenticator::multi_key(multi_key_auth);

    // 8. Create signed transaction
    let signed_txn = SignedTransaction::new_single_sender(raw_txn, account_auth);

    // 9. Verify multi-ed25519 signature
    signed_txn.verify_signature().unwrap();

    println!("Multi Ed25519 transaction verified successfully.");
}
