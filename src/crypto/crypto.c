#include "crypto.h" // IWYU pragma: keep
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
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
    /*    
    printf("Private key: \n");
    dump_memory(dump, 32);
    */
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
    ctx->spi = htobe64(generate_spi());
    /* Nonce configuration */
    ctx->nonce_len = DEFAULT_NONCE_LENGTH;
    ctx->nonce = malloc(ctx->nonce_len);
    generate_nonce(ctx->nonce, ctx->nonce_len);
    /* Key configuration */
    ctx->key_len = X25519_KEY_LENGTH;
    generate_key(&ctx->private_key, &ctx->public_key);

}

/**
 * @brief This function drive the shared secret between the two peer
 * @note The private key is the type of EVP_PKEY because is necessary his context
 * @param[in] pri The private key of the remote peer
 * @param[in] pub The public key of the remote peer
 */
void derive_secret(EVP_PKEY** pri, uint8_t** pub, uint8_t** secret){

    size_t size = X25519_KEY_LENGTH;
    *secret = malloc(X25519_KEY_LENGTH);

    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, *pub, size);
    if(!peer){ printf("Error"); }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(*pri, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer) <= 0){
        printf("Error");
    }   
    
    if (EVP_PKEY_derive(ctx, *secret, &size) <= 0) { printf("Errore");}

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);


}

//PRF FUNCTION HERE
int prf(uint8_t** key, size_t key_len, uint8_t** data, size_t data_len, uint8_t** digest, unsigned int* digest_len){
    
    if (!key || !data) {
        // se uno dei due non c'è non riesco ad ottenere l'output 
        fprintf(stderr, "Error: NULL input to PRF function\n");
        return EXIT_FAILURE;
    }

    HMAC(EVP_sha1(), *key, key_len, *data, data_len, *digest, digest_len );
    return 1;
}
//MOVE HERE THE FUNCTION TO GENERATE CHE SKEYSEED

// mi servono solo i due contesti perchè mi servono le chiavi per generare il segreto condiviso e i nonce per generare la chiavve da utilizzare per la prf
// modificare in return type intero per vedere se qualcosa è andato male
void derive_seed(crypto_context_t* left, crypto_context_t* right, uint8_t* seed){
    printf("Entro nella funzione");
    //populating the shared secret
    uint8_t* ss = calloc(SHA1_DIGEST_LENGTH,1);
    derive_secret(&left->private_key, &right->public_key, &ss);
    //ather that we concatenate the nonce to derive the key for the hmac
    // Ni | Nr
    size_t key_len = left->nonce_len + right->nonce_len;
    uint8_t* key = calloc(key_len, 1);
    memcpy(key, left->nonce, left->nonce_len);
    memcpy(key+left->nonce_len, right->nonce, right->nonce_len);
    //so at this point we can call prf funciton
    unsigned int seed_len = SHA1_DIGEST_LENGTH;
    prf(&key, key_len, &ss, X25519_KEY_LENGTH, &seed, &seed_len);
    printf("\n");
    dump_memory(seed, SHA1_DIGEST_LENGTH);
}

void prf_plus(crypto_context_t* left, crypto_context_t* right){

}
