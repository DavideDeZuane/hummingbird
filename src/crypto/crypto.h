#ifndef CRYPTO_H
#define CRYPTO_H

#include "../common_include.h"
#include "../config/config.h"
#include <openssl/evp.h>
#include <stdint.h>

#define X25519_KEY_LENGTH 32
#define DEFAULT_NONCE_LENGTH 32
#define SHA1_DIGEST_LENGTH 20
#define NUM_KEYS 7

/**
* @brief This struct rappresent the required key material to a ike initiator
* @note We use the union because to derive the shared secret correctly is necessari the context of the private key
* generated for the initiator
*/
typedef struct {
    uint8_t spi[8];
    EVP_PKEY *private_key;
    uint8_t *public_key;  
    uint8_t* nonce;
    size_t key_len;
    size_t nonce_len;
} crypto_context_t;


void initiate_crypto(crypto_context_t* ctx, const cipher_options* suite);

/**
* @brief This function return a secure random string to use as security parameter index for the initiator using random material generated from /dev/urandom
* @return Return 64 bit to use as index for initiator
*/
uint64_t generate_spi();

/**
* @brief This function return a nonce of the specified length
* @param[out] nonce The buffer to populate
* @param[in] length Length of the nonce to generate
*/
//void generate_nonce(uint8_t *nonce, size_t length);

/**
* @brief This function print a baffer passed as input in hex format
* @param[in] data Buffer of data to convert in hexadecimal
* @param[in] len Length of the buffer to print
*/
void print_hex(const unsigned char *data, size_t len);

void derive_secret(EVP_PKEY** pri, uint8_t** pub, uint8_t** secret);

void derive_seed(crypto_context_t* left, crypto_context_t* right, uint8_t* seed);

int prf(uint8_t** key, size_t key_len, uint8_t** data, size_t data_len, uint8_t** digest, unsigned int* digest_len);

void prf_plus(crypto_context_t* left, crypto_context_t* right, uint8_t** T_buffer);

#endif