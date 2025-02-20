#ifndef CRYPTO_H
#define CRYPTO_H

#include "../common_include.h"
#include <openssl/evp.h>

typedef struct {
    uint64_t spi;
    union {
        EVP_PKEY *private_key;
        uint8_t *public_key;  
    };
    uint8_t* nonce;
    size_t key_len;
    size_t nonce_len;
} crypto_context_t;


/**
* @brief This function return a secure random string to use as security parameter index for the initiator using random material generated from /dev/urandom
* @return Return 64 bit to use as index for initiator
*/
uint64_t generate_spi();

void generate_nonce(uint8_t *nonce, size_t length);

/**
* @brief This function print a baffer passed as input in hex format
* @param[in] data Buffer of data to convert in hexadecimal
* @param[in] len Length of the buffer to print
*/
void print_hex(const unsigned char *data, size_t len);

void generate_kex();

#endif