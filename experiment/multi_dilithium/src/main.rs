use aptos_crypto::ed25519::Ed25519PrivateKey;
use aptos_crypto::Uniform;
use aptos_crypto::PrivateKey;
use aptos_types::{
    account_address::AccountAddress,
    transaction::{
        authenticator::{AnyPublicKey, AuthenticationKey},
        RawTransaction,
    },
    test_helpers::transaction_test_helpers::get_test_signed_transaction,
};
use bcs::to_bytes;
use pqcrypto_dilithium::dilithium3::{keypair, sign, open, SecretKey, PublicKey, SignedMessage};
use std::fs::File;
use std::io::{Write, Read};
use std::time::Instant;


fn generate_message() -> Vec<u8> {
    let sender = Ed25519PrivateKey::generate_for_testing();
    let sender_pub = sender.public_key();

    let single_sender_auth = AuthenticationKey::any_key(AnyPublicKey::ed25519(sender_pub.clone()));
    let single_sender_addr = single_sender_auth.account_address();

    let raw_txn = get_test_signed_transaction(
        single_sender_addr,
        0,
        &sender,
        sender_pub.clone(),
        None,
        0,
        0,
        None,
    )
    .into_raw_transaction();

    let message: Vec<u8> = to_bytes(&raw_txn).expect("bcs encode failed");
    message
}


fn main() {

    let n = 1000; // transaction number
    let m = 8; // multi key

    let mut pks: Vec<PublicKey> = Vec::with_capacity(n * m);
    let mut sks: Vec<SecretKey> = Vec::with_capacity(n * m);

    // 1. Key generate
    let gen_start = Instant::now();
    
    for _ in 0..(n * m) {
        let (pk, sk): (PublicKey, SecretKey) = keypair();
        pks.push(pk);
        sks.push(sk);
    }
    
    let gen_duration = gen_start.elapsed();
    println!("key gen: {:?}", gen_duration);

    // 2. Generate messsage
    let mut messages: Vec<Vec<u8>> = Vec::with_capacity(n);

    for _ in 0..n {
        let msg = generate_message();
        messages.push(msg);
    }

    // 3. sign

    let mut signatures: Vec<SignedMessage> = Vec::with_capacity(n * m);

    let sign_start = Instant::now();

    for i in 0..n {
        for j in 0..m {
            let idx = i * m + j;
            let sig = sign(&messages[i], &sks[idx]);
            signatures.push(sig);
        }
    }

    let sign_duration = sign_start.elapsed();
    println!("sign: {:?}", sign_duration);

    // 4. verify
    let verify_start = Instant::now();

    for i in 0..n {
        for j in 0..m {
            let idx = i * m + j;
            let _ = open(&signatures[idx], &pks[idx]);
        }
    }
    let verify_duration = verify_start.elapsed();
    println!("verify: {:?}", verify_duration);

    // let duration = start.elapsed();
    // println!("執行時間: {:?}", duration);
    
    println!("✅ Single sender Dilithium transaction verified successfully.");
}
