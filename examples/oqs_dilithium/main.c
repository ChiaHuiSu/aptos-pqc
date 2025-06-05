#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// Dilithium3 AVX2 函數聲明
extern int pqcrystals_dilithium3_avx2_keypair(uint8_t *pk, uint8_t *sk);
extern int pqcrystals_dilithium3_avx2_signature(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *sk);
extern int pqcrystals_dilithium3_avx2_verify(const uint8_t *sig, size_t siglen,
                                     const uint8_t *m, size_t mlen,
                                     const uint8_t *pk);

// 參數定義
#define MLEN 32
#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_SECRETKEYBYTES 4000
#define CRYPTO_BYTES 3293

int main() {
    // 原始訊息
    uint8_t message[MLEN] = {0};
    memcpy(message, "Hello Dilithium3 AVX2!", 24);

    // 金鑰對
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    // 簽章後的 sm = signature || message
    uint8_t sm[CRYPTO_BYTES + MLEN];
    size_t smlen = 0;

    // 還原後的訊息
    uint8_t recovered[CRYPTO_BYTES + MLEN];
    size_t recovered_len = 0;

    // 1. 產生金鑰對
    if (pqcrystals_dilithium3_avx2_keypair(pk, sk) != 0) {
        fprintf(stderr, "❌ Keypair generation failed!\n");
        return EXIT_FAILURE;
    }

    // 2. 簽章（輸出為 signature || message）
    if (pqcrystals_dilithium3_avx2_signature(sm, &smlen, message, MLEN, sk) != 0) {
        fprintf(stderr, "❌ Signing failed!\n");
        return EXIT_FAILURE;
    }

    // 3. 驗證簽章並還原訊息
    int ret = pqcrystals_dilithium3_avx2_verify(sm, smlen, message, MLEN, pk);
    printf("verify returned: %d\n", ret);

    // if (ret == 0 && recovered_len == MLEN && memcmp(message, recovered, MLEN) == 0) {
    //     printf("✅ Signature verified and message recovered correctly.\n");
    // } else {
    //     printf("❌ Verification failed or message mismatch.\n");
    // }

    return 0;
}
