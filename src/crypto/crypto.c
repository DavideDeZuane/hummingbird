#include "crypto.h" // IWYU pragma: keep
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/random.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <time.h>
#include "../log/log.h"
#include "../utils/utils.h"

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

void generate_key(EVP_PKEY** pri, uint8_t** pub){
    
    *pri = NULL;
    *pub = malloc(X25519_KEY_LENGTH);

    EVP_PKEY_CTX*ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, pri) <= 0){
        log_error("Error during the generation of the private key");

    } 
    //la dimensione del buffer è 32 byte dato che x25519 produce sempre chiavi pubbliche di questa dimensione
    unsigned char dump[32];
    size_t len = X25519_KEY_LENGTH;

    //METTERE UNA GUARD CHE FA QUESTA COSA PER FARE IL DUMP SOLO SE IL LOG LEVEL È QUELLO GIUSTO
    if (EVP_PKEY_get_raw_private_key(*pri, dump, &len) <= 0){
        printf("Errore extracting the private key");
        log_error("Errore");
    }
    printf("Private key: \n");
    dump_memory(dump, 32);
    // estraiamo la chiave pubblica da quella privata in modo tale da metterla all'interno di un buffer per poi inviarla nel payload KE
    if (EVP_PKEY_get_raw_public_key(*pri, *pub, &len) <= 0){
        printf("Errore extracting the public key");
        log_error("Errore");
    } 
    // Stampa la chiave pubblica in formato esadecimale
    EVP_PKEY_CTX_free(ctx);

}

void initiate_crypto(crypto_context_t* ctx){

    /* Spi configuration */
    ctx->spi = generate_spi();
    /* Nonce configuration */
    ctx->nonce_len = DEFAULT_NONCE_LENGTH;
    ctx->nonce = malloc(ctx->nonce_len);
    generate_nonce(ctx->nonce, ctx->nonce_len);
    /* Key configuration */
    ctx->key_len = X25519_KEY_LENGTH;
    generate_key(&ctx->private_key, &ctx->public_key);

    log_info("Cryptographyc Material generated for the initiator");
}

//PRF FUNCTION HERE
int prf(){
    return 1;
}
//MOVE HERE THE FUNCTION TO GENERATE CHE SKEYSEED

