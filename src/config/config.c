#include "../common_include.h" // IWYU pragma: keep
#include "../log/log.h"
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
#define HANDLE_FIELD(sec, field, src, dst, max_len) \
    if (MATCH(sec, field)) { \
        secure_strncpy(dst, src, max_len); \
        return 1; \
    }

enum { CURVE_X25519, AES_128_CBC, HMAC_SHA1 };

typedef struct {
    const char *name;
    char *field;
} FieldMap;

void secure_strncpy(char *dest, const char *src, size_t dest_size) {
    // importanza di limitare la copia per evitare overflow
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';

}

config init_config(){
    config def = {
        .peer = {
            "localhost",
            "127.0.0.1",
            "500"
        },
        .suite = {
            AES_128_CBC,
            HMAC_SHA1,
            HMAC_SHA1,
            CURVE_X25519,
        },
        .log = {
            3,
            "minimal.log"
        },
        32

    };

    return def;
}

int auth_handler(auth_options_t* opts, const char* section, const char* name, const char* value){

    char* sec_name = malloc(strlen("Authentication") + 1); 
    strcpy(sec_name, "Authentication");

    HANDLE_FIELD(sec_name, "id",        value,  opts->id,       MAX_ID_LENGTH);
    HANDLE_FIELD(sec_name, "method",    value,  opts->method,   MAX_AUTH_METHOD_LEN);
    HANDLE_FIELD(sec_name, "data",      value,  opts->data,     MAX_AUTH_DATA_LEN);

    free(sec_name);  
    return 0;
}

int peer_handler(peer_options* opts, const char* section, const char* name, const char* value){

    char* sec_name = malloc(strlen("Network") + 1); 
    strcpy(sec_name, "Network");

    HANDLE_FIELD(sec_name, "hostname",  value,  opts->hostname,  MAX_ID_LENGTH);
    HANDLE_FIELD(sec_name, "address",   value,  opts->address,   MAX_AUTH_METHOD_LEN);
    HANDLE_FIELD(sec_name, "port",      value,  opts->port,      MAX_AUTH_DATA_LEN);

    free(sec_name);
    return 0;

}

int crypto_handler(cipher_options* opts, const char* section, const char* name, const char* value){
    
    char* sec_name = malloc(strlen("Crypto") + 1); 
    strcpy(sec_name, "Crypto");

    HANDLE_FIELD(sec_name, "encryption",        value,  opts->enc,  MAX_ID_LENGTH);
    HANDLE_FIELD(sec_name, "authentication",    value,  opts->aut,  MAX_ID_LENGTH);
    HANDLE_FIELD(sec_name, "pseudorandom",      value,  opts->prf,  MAX_ID_LENGTH);
    HANDLE_FIELD(sec_name, "key-exchange",      value,  opts->kex,  MAX_ID_LENGTH);

    return 0;
}

int handler(void* cfg, const char* section, const char* name, const char* value){

    config* conf = (config *) cfg;

    peer_handler(&conf->peer, section, name, value);
    auth_handler(&conf->auth, section, name, value);
    crypto_handler(&conf->suite, section, name, value);
    

    if (MATCH("Logging", "level")) {
        log_set_level(atoi(value));    
    }


    return 1;

}