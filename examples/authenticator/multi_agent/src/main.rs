use aptos_crypto::{
    ed25519::{Ed25519PrivateKey},
    multi_ed25519::{MultiEd25519PublicKey},
    Uniform,
    SigningKey, PrivateKey,
};
use aptos_types::{
    account_address::AccountAddress,
    transaction::{
        authenticator::{AccountAuthenticator, AnyPublicKey, AnySignature, MultiKeyAuthenticator},
        SignedTransaction, TransactionPayload, Script,
        RawTransaction,
    },
    test_helpers::transaction_test_helpers::get_test_signed_transaction,
    transaction::authenticator::AuthenticationKey,
    chain_id::ChainId,
};

fn main() {
    // Generate two keypairs
    let sk0 = Ed25519PrivateKey::generate_for_testing();
    let pk0 = sk0.public_key();
    let sk1 = Ed25519PrivateKey::generate_for_testing();
    let pk1 = sk1.public_key();

    // Create 2-of-2 multi-ed25519 public key
    let pubkeys = vec![pk0.clone(), pk1.clone()];
    let threshold = 2u8;
    let multi_pubkey = MultiEd25519PublicKey::new(pubkeys.clone(), threshold).unwrap();

    // Derive account address from multi key
    let auth_key = AuthenticationKey::multi_ed25519(&multi_pubkey);
    let sender_addr = auth_key.account_address();

    // Create empty script payload
    let empty_script = Script::new(vec![], vec![], vec![]);

    // Build RawTransaction
    let raw_txn = RawTransaction::new(
        sender_addr,
        0,
        TransactionPayload::Script(empty_script),
        1000,
        1,
        1000000,
        ChainId::test(),
    );

    // Each signer signs the same raw transaction
    let sig0 = sk0.sign(&raw_txn).unwrap();
    let sig1 = sk1.sign(&raw_txn).unwrap();

    // Build MultiEd25519Signature with signer indices
    let multi_sig = aptos_crypto::multi_ed25519::MultiEd25519Signature::new(vec![
        (sig0.clone(), 0),
        (sig1.clone(), 1),
    ]).unwrap();

    // Build MultiKeyAuthenticator with AnySignature
    let any_sigs = vec![
        (0, AnySignature::Ed25519 { signature: sig0 }),
        (1, AnySignature::Ed25519 { signature: sig1 }),
    ];
    let multi_key_auth = MultiKeyAuthenticator::new(multi_pubkey.into(), any_sigs).unwrap();
    let account_auth = AccountAuthenticator::multi_key(multi_key_auth);

    // No secondary signer for this example
    let secondary_addresses = vec![];
    let secondary_authenticators = vec![];

    // Create signed multi-agent transaction
    let signed_txn = SignedTransaction::new_multi_agent(
        raw_txn,
        account_auth,
        secondary_addresses,
        secondary_authenticators,
    );

    // Verify the signature - should succeed
    signed_txn.verify_signature().unwrap();

    println!("Multi-agent multi-ed25519 transaction verified successfully!");
}

