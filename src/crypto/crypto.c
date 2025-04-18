#include "crypto.h" // IWYU pragma: keep
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/types.h>
#include <time.h>
#include "../log/log.h"
#include "../utils/utils.h"


int random_bytes(uint8_t** buff, size_t size){
    
    size_t result = getrandom(*buff, size, 0);
    if (result == -1) {
        perror("getrandom");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

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

void generate_raw_spi(uint8_t spi[], size_t len) {
    
    uint8_t* tmp = NULL; 
    alloc_buffer(&tmp, len);
    random_bytes(&tmp, len);
    memcpy(spi, tmp, SPI_LENGTH_BYTE);
}

/**
* @brief This function return a nonce of the specified length
* @param[out] nonce The buffer to populate
* @param[in] length Length of the nonce to generate
*/
void generate_nonce(uint8_t** nonce, size_t len) {
    
    alloc_buffer(nonce, len);
    random_bytes(nonce, len);
}


/**
* @brief This function generates a pair of keys to use for the diffie-hellman exchange
* @param[in] pri The private key, is of the type EVP_PKEY because the context inside this struct are necessary to derive correctly the secret
* @param[in] pub The public key, this is a buffer becuase we have to send this content in the init exchange
*/
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

/**
* @brief This function given a pointer to the cyrpto context of the initiator generates all the material this needs in order to complete the IKE protocol.
* In particular we have: the security parameter index, the nonce, and the key pair for diffie hellman.
* @param[in] ctx This is a pointer to the struct to populate
*/
void initiate_crypto(crypto_context_t* ctx, const cipher_options* suite){

    log_debug("Proposal configured: " ANSI_COLOR_BOLD "%s-%s-%s-%s", suite->enc, suite->aut, suite->kex, suite->prf);

    /* SPI configuration */
    generate_raw_spi(ctx->spi, SPI_LENGTH_BYTE);
    size_t str_len = 2* SPI_LENGTH_BYTE +1;
    char* str = calloc(str_len, BYTE); 
    format_hex_string(str, str_len, ctx->spi, SPI_LENGTH_BYTE);
    log_trace("%-5s: " ANSI_COLOR_BOLD "0x%s","SPIi", str);
    
    /* Nonce configuration */
    ctx->nonce_len = DEFAULT_NONCE_LENGTH;
    generate_nonce(&ctx->nonce, ctx->nonce_len);
    str_len = 2 * DEFAULT_NONCE_LENGTH + 1;
    str = realloc(str, str_len);
    memset(str, 0, str_len);
    format_hex_string(str, str_len, ctx->nonce, ctx->nonce_len);
    log_trace("%-5s: " ANSI_COLOR_BOLD "0x%s", "Ni", str);
    
    /* Key configuration */
    ctx->key_len = X25519_KEY_LENGTH;
    generate_key(&ctx->private_key, &ctx->public_key);
    memset(str, 0, str_len);
    format_hex_string(str, str_len, ctx->public_key, ctx->key_len);
    log_trace("%-5s: " ANSI_COLOR_BOLD "0x%s", "KEi", str);
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
    uint8_t* ss = calloc(X25519_KEY_LENGTH,1);
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

    //fare anche un goto per questo nel caso in cui la derivazione della chiave andasse male
    secure_free(key, key_len);
    secure_free(ss, X25519_KEY_LENGTH);
}

/**
* @brief This function populate the T_buffer
*/
void prf_plus(crypto_context_t* left, crypto_context_t* right, uint8_t** T_buffer){
    //il left e right crypto ci server per ottenere le chiavi e quindi derivare il segreto condiviso 
    //così come i nonce ci servono per derivare il SKEYSEED

    if(*T_buffer == NULL){
        printf("The buffer is not defined");
        return;
    }

    uint8_t* seed = malloc(SHA1_DIGEST_LENGTH);
    derive_seed(left, right, seed);

    dump_memory(seed, SHA1_DIGEST_LENGTH);

    // a questo punto devo generare il materiale da firmare con il skeyseed per generare il T_buffer
    // l'1 finale è per il counter di cui c'è da fare l'append nel buffer
    size_t msg_len = left->nonce_len + right->nonce_len + (2* SPI_LENGTH_BYTE) + 1;
    uint8_t* msg = calloc(msg_len, 1);
    // il messaggio da firmare è così composto Ni | Nr | SPIi | SPIr | counter
    memcpy(msg,                                         left->nonce,    left->nonce_len); 
    memcpy(msg + left->nonce_len,                       right->nonce,   right->nonce_len);
    memcpy(msg + (2*left->nonce_len),                   &left->spi,     SPI_LENGTH_BYTE);
    memcpy(msg + (2*left->nonce_len) + SPI_LENGTH_BYTE, &right->spi,    SPI_LENGTH_BYTE);
    msg[msg_len-1] = 0x01;

    printf("\nMessaggio nella funzione\n");
    dump_memory(msg, msg_len);

    // a questo punto ho generato il messaggio, aggiungere i vari controlli per verificare che i vari puntatori non siano nulli e mettere in una funzione a parte
    // qui implementiamo la logica dell'espansione del key material
    size_t generated = 0;
    unsigned int digest_len = SHA1_DIGEST_LENGTH;
    uint8_t* digest = malloc(digest_len);


    while(generated < NUM_KEYS * SHA1_DIGEST_LENGTH){

        if(generated == 0){
            prf(&seed, SHA1_DIGEST_LENGTH, &msg, msg_len, &digest, &digest_len);
            //ho generato T1 quindi a questo punto
            // updating the message to sign
            msg_len += SHA1_DIGEST_LENGTH;
            msg = realloc(msg, msg_len);
            memmove(msg + SHA1_DIGEST_LENGTH , msg, msg_len - SHA1_DIGEST_LENGTH);
            memcpy(*T_buffer, digest, digest_len);
            // update the generated size to bypass this if 
            generated += SHA1_DIGEST_LENGTH;
            // questa è un iterazionein più ma sti cazzi
            continue;
        }
        //at each iteration we have to increase the counter and replace the digest of previuos output in from of msg
        memcpy(msg, digest, SHA1_DIGEST_LENGTH);
        msg[msg_len-1]++;

        // aggiungere un controllo sul valore di ritorno della funzione
        prf(&seed, SHA1_DIGEST_LENGTH, &msg, msg_len, &digest, &digest_len);
        memcpy(*T_buffer + generated, digest, digest_len);
        generated += SHA1_DIGEST_LENGTH;
    }

    log_info("T_Buffer popoulated");

    

}
