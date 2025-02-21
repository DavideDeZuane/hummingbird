#include "crypto.h" // IWYU pragma: keep
#include <stdint.h>
#include <stdio.h>
#include <sys/random.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

/**
* @brief This function return a secure random string to use as security parameter index for the initiator using random material generated from /dev/urandom
* @return Return 64 bit to use as index for initiator
*/
uint64_t generate_spi() {
    uint64_t spi;
    if (getrandom(&spi, sizeof(spi), 0) != sizeof(spi)) {
        perror("Errore nella generazione dei numeri casuali con getrandom");
        exit(EXIT_FAILURE);
    }
    return spi;
}

/**
* @brief This function return a nonce of the specified length
* @param[out] nonce The buffer to populate
* @param[in] length Length of the nonce to generate
*/
void generate_nonce(uint8_t *nonce, size_t length) {
    ssize_t result = getrandom(nonce, length, 0);
    if (result == -1) {
        perror("getrandom");
        exit(EXIT_FAILURE);
    }
}

//ADD THE FUNCTION FOR GENERATE THE PRIVATE KEY FOR THE INITIATOR

//MOVE HERE THE FUNCTION TO GENERATE CHE SKEYSEED

