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
use libc::{size_t, c_uchar, c_int};

const CRYPTO_PUBLICKEYBYTES: usize = 1952;
const CRYPTO_SECRETKEYBYTES: usize = 4000;
const CRYPTO_BYTES: usize = 3293;

/// Generate raw transaction
pub fn generate_message() -> Vec<u8> {

    // generate sender（Ed25519）
    let sender = Ed25519PrivateKey::generate_for_testing();
    let sender_pub = sender.public_key();

    // generate address
    let single_sender_auth = AuthenticationKey::any_key(AnyPublicKey::ed25519(sender_pub.clone()));
    let single_sender_addr = single_sender_auth.account_address();

    // build RawTransaction
    let raw_txn = get_test_signed_transaction(
        single_sender_addr,
        0,
        &sender,
        sender_pub,
        None,
        0,
        0,
        None,
    )
    .into_raw_transaction();

    // serialized message
    let message = to_bytes(&raw_txn).expect("BCS encode failed");

    message
}

unsafe extern "C" {

    fn pqcrystals_dilithium3_avx2_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> i32;

    fn pqcrystals_dilithium3_avx2_signature(
        sig: *mut c_uchar,
        siglen: *mut size_t,
        m: *const c_uchar,
        mlen: size_t,
        sk: *const c_uchar,
    ) -> i32;

    fn pqcrystals_dilithium3_avx2_verify(
        sig: *const c_uchar,
        siglen: size_t,
        m: *const c_uchar,
        mlen: size_t,
        pk: *const c_uchar,
    ) -> i32;
}

fn main() {

    let n = 1000; // transaction number
    let m = 32; // multi key
    let mut pks: Vec<[u8; CRYPTO_PUBLICKEYBYTES]> = vec![[0u8; CRYPTO_PUBLICKEYBYTES]; n * m];
    let mut sks: Vec<[u8; CRYPTO_SECRETKEYBYTES]> = vec![[0u8; CRYPTO_SECRETKEYBYTES]; n * m];
    let mut sigs: Vec<[u8; CRYPTO_BYTES]> = vec![[0u8; CRYPTO_BYTES]; n * m];
    let mut siglens: Vec<size_t> = vec![0; n * m];

    unsafe {

        // 1. Key generate

        let key_start = Instant::now();
        for i in 0..(n * m) {
            let key_res = pqcrystals_dilithium3_avx2_keypair(pks[i].as_mut_ptr(), sks[i].as_mut_ptr());
        }
        let key_duration = key_start.elapsed();
        println!("key gen: {:?}", key_duration);

        // 2. Generate message
        let mut messages: Vec<Vec<u8>> = Vec::with_capacity(n);

        for _ in 0..n {
            let msg = generate_message();
            messages.push(msg);
        }

        // 3. Signed
        let sign_start = Instant::now();

        for i in 0..n {

            let msg_ptr = messages[i].as_ptr();
            let msg_len = messages[i].len();

            for j in 0..m {
                let idx = i * m + j;
                let res = pqcrystals_dilithium3_avx2_signature(
                    sigs[idx].as_mut_ptr(),
                    &mut siglens[idx],
                    msg_ptr,
                    msg_len,
                    sks[idx].as_ptr(),
                );
            }
        }
        // for i in 0..n {
        //     let res = pqcrystals_dilithium3_avx2_signature(
        //         sigs[i].as_mut_ptr(),
        //         &mut siglens[i],
        //         messages[i].as_ptr(),
        //         messages[i].len(),
        //         sks[i].as_ptr()
        //     );
        // }
        let sign_duration = sign_start.elapsed();
        println!("sign: {:?}", sign_duration);

        // 4. Verify
        let verify_start = Instant::now();

        for i in 0..n {

            let msg_ptr = messages[i].as_ptr();
            let msg_len = messages[i].len();

            for j in 0..m {
                let idx = i * m + j;
                let verify_result = pqcrystals_dilithium3_avx2_verify(
                    sigs[idx].as_ptr(),
                    siglens[idx],
                    msg_ptr,
                    msg_len,
                    pks[idx].as_ptr(),
                );
            }
        }

        // for i in 0..n {
        //     let verify_result = pqcrystals_dilithium3_avx2_verify(
        //         sigs[i].as_ptr(),
        //         siglens[i],
        //         messages[i].as_ptr(),
        //         messages[i].len(),
        //         pks[i].as_ptr(),
        //     );
        // }
        let verify_duration = verify_start.elapsed();
        println!("verify: {:?}", verify_duration);
    }
}
