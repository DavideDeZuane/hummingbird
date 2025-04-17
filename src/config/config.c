#include "../common_include.h" // IWYU pragma: keep
#include "../log/log.h"
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include "config.h"

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

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

int peer_handler(peer_options* responder, const char* section, const char* name, const char* value){

    if (MATCH("Peer", "hostname")) {
        secure_strncpy(responder->hostname, value, INET_FQNLEN);
    } else if (MATCH("Peer", "address")) {
        secure_strncpy(responder->address, value, INET_ADDRSTRLEN);
    } else if (MATCH("Peer", "port")) {
        secure_strncpy(responder->port, value, MAX_PORT_LENGTH);
    } else {
        return 0;  
    }
    return 1;

}

int crypto_handler(cipher_options* suite, const char* section, const char* name, const char* value){
    
    const char* sec_name = "Cipher-suite"; 

    if (MATCH(sec_name, "encryption")) {
        secure_strncpy(suite->enc, value, MAX_ALGR_LENGTH);    
    } else if (MATCH(sec_name, "authentication")) {
        secure_strncpy(suite->aut, value, MAX_ALGR_LENGTH);    
    } else if (MATCH(sec_name, "pseudorandom")) {
        secure_strncpy(suite->prf, value, MAX_ALGR_LENGTH);    
    } else if (MATCH(sec_name, "key-exchange")) {
        secure_strncpy(suite->kex, value, MAX_ALGR_LENGTH);    
    } else {
        return 0;
    }
    return 1;
}

int handler(void* cfg, const char* section, const char* name, const char* value){

    config* conf = (config *) cfg;

    peer_handler(&conf->peer, section, name, value);
    crypto_handler(&conf->suite, section, name, value);

    if (MATCH("Logging", "level")) {
        log_set_level(atoi(value));    
    }


    return 1;

}