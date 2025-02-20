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

void generate_nonce(uint8_t *nonce, size_t length) {
    ssize_t result = getrandom(nonce, length, 0);
    if (result == -1) {
        perror("getrandom");
        exit(EXIT_FAILURE);
    }
}

/**
* @brief This function print a baffer passed as input in hex format
* @param[in] data Buffer of data to convert in hexadecimal
* @param[in] len Length of the buffer to print
*/
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void generate_kex(){
    
    EVP_PKEY *pkey1 = NULL;
    printf("----------------------------------------\n");
    printf("Generating Key\n");
    printf("----------------------------------------\n");

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey1) <= 0) printf("Errore nel generare la chiave");
    if(pkey1 == NULL) printf("Errore nella creazione della chiave");
    //la dimensione del buffer è 32 byte dato che x25519 produce sempre chiavi pubbliche di questa dimensione
    unsigned char buffer[32];
    size_t buffer_len = sizeof(buffer);
    if (EVP_PKEY_get_raw_private_key(pkey1, buffer, &buffer_len) <= 0) printf("Errore extracting the private key");
    printf("Chiave privata (X25519):\n");
    print_hex(buffer, buffer_len);
    // Estrai la chiave pubblica, quindi gli passiamo il contenitore e il buffer da popolare
    if (EVP_PKEY_get_raw_public_key(pkey1, buffer, &buffer_len) <= 0) printf("Errore extracting the public key");
    // Stampa la chiave pubblica in formato esadecimale
    printf("Chiave pubblica (X25519):\n");
    print_hex(buffer, buffer_len);

}