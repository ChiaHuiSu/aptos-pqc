use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519Signature},
    multi_ed25519::MultiEd25519PublicKey,
    Uniform, PrivateKey, SigningKey,
};
use aptos_types::{
    account_address::AccountAddress,
    chain_id::ChainId,
    transaction::{
        authenticator::{AccountAuthenticator, AnyPublicKey, AnySignature, MultiKeyAuthenticator},
        RawTransaction, Script, TransactionPayload, SignedTransaction,
    },
    transaction::authenticator::AuthenticationKey,
};

fn main() {
    // 1. Generate primary multi-signer keys (2-of-2)
    let sk0 = Ed25519PrivateKey::generate_for_testing();
    let pk0 = sk0.public_key();
    let sk1 = Ed25519PrivateKey::generate_for_testing();
    let pk1 = sk1.public_key();
    let pubkeys = vec![pk0.clone(), pk1.clone()];
    let threshold = 2u8;
    let multi_pubkey = MultiEd25519PublicKey::new(pubkeys.clone(), threshold).unwrap();
    let auth_key = AuthenticationKey::multi_ed25519(&multi_pubkey);
    let sender_addr = auth_key.account_address();

    // 2. Generate fee payer key (single Ed25519 signer)
    let fee_payer_sk = Ed25519PrivateKey::generate_for_testing();
    let fee_payer_pk = fee_payer_sk.public_key();
    let fee_payer_auth_key = AuthenticationKey::ed25519(&fee_payer_pk);
    let fee_payer_addr = fee_payer_auth_key.account_address();

    // 3. Create raw transaction from primary sender
    let empty_script = Script::new(vec![], vec![], vec![]);
    let raw_txn = RawTransaction::new(
        sender_addr,
        0,
        TransactionPayload::Script(empty_script),
        1000, // max gas amount
        1,    // gas unit price
        1_000_000,
        ChainId::test(),
    );

    // 4. Each primary signer signs the raw transaction
    let sig0 = sk0.sign(&raw_txn).unwrap();
    let sig1 = sk1.sign(&raw_txn).unwrap();

    // 5. Compose MultiEd25519Signature for primary signer
    let any_sigs_primary = vec![
        (0, AnySignature::Ed25519 { signature: sig0.clone() }),
        (1, AnySignature::Ed25519 { signature: sig1.clone() }),
    ];
    let multi_key_auth = MultiKeyAuthenticator::new(multi_pubkey.into(), any_sigs_primary).unwrap();
    let primary_authenticator = AccountAuthenticator::multi_key(multi_key_auth);

    // 6. Fee payer signs the raw transaction as well
    let fee_payer_sig = fee_payer_sk.sign(&raw_txn).unwrap();
    let fee_payer_authenticator = AccountAuthenticator::ed25519(
        fee_payer_pk,
        fee_payer_sig,
    );

    // 7. Build MultiAgent signed transaction with fee payer as secondary signer
    let secondary_addresses = vec![fee_payer_addr];
    let secondary_authenticators = vec![fee_payer_authenticator];

    let signed_txn = SignedTransaction::new_multi_agent(
        raw_txn,
        primary_authenticator,
        secondary_addresses,
        secondary_authenticators,
    );

    // 8. Verify signatures (should succeed)
    signed_txn.verify_signature().unwrap();

    println!("Feepayer transaction with fee payer verified successfully!");
}
