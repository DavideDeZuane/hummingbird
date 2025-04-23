#include "../common_include.h" // IWYU pragma: keep
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

#define SET_DEFAUTL_FIELD(cfg, sub, field, val) strncpy((cfg)->sub.field, (val), sizeof((cfg)->sub.field))

#define HANDLE_FIELD(sec, field, src, dst, max_len) \
    if (MATCH(sec, field)) { \
        secure_strncpy(dst, src, max_len); \
        return 1; \
    }

typedef struct {
    const char *name;
    char *field;
} FieldMap;

void secure_strncpy(char *dest, const char *src, size_t dest_size) {
    // importanza di limitare la copia per evitare overflow
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';

}


void default_config(config* cfg){

    
    SET_DEFAUTL_FIELD(cfg, peer, hostname, "localhost");
    SET_DEFAUTL_FIELD(cfg, peer, address,  "127.0.0.1");
    SET_DEFAUTL_FIELD(cfg, peer, port,     "500");
    
    SET_DEFAUTL_FIELD(cfg, auth, id,       "padrepio");
    SET_DEFAUTL_FIELD(cfg, auth, method,   "psk");
    SET_DEFAUTL_FIELD(cfg, auth, data,     "padrepio");
    
    SET_DEFAUTL_FIELD(cfg, suite, enc, "aes128");
    SET_DEFAUTL_FIELD(cfg, suite, aut, "sha1_96");
    SET_DEFAUTL_FIELD(cfg, suite, prf, "prfsha1");
    SET_DEFAUTL_FIELD(cfg, suite, kex, "x25519");

}

int auth_handler(auth_options_t* opts, const char* section, const char* name, const char* value){


    HANDLE_FIELD(section, "id",        value,  opts->id,       MAX_ID_LENGTH);
    HANDLE_FIELD(section, "method",    value,  opts->method,   MAX_AUTH_METHOD_LEN);
    HANDLE_FIELD(section, "data",      value,  opts->data,     MAX_AUTH_DATA_LEN);

    return 0;
}

int peer_handler(peer_options* opts, const char* section, const char* name, const char* value){

    HANDLE_FIELD(section, "hostname",  value,  opts->hostname,  MAX_ID_LENGTH);
    HANDLE_FIELD(section, "address",   value,  opts->address,   MAX_AUTH_METHOD_LEN);
    HANDLE_FIELD(section, "port",      value,  opts->port,      MAX_AUTH_DATA_LEN);

    return 0;

}

int crypto_handler(cipher_options* opts, const char* section, const char* name, const char* value){
    
    HANDLE_FIELD(section, "encryption",        value,  opts->enc,  MAX_ID_LENGTH);
    HANDLE_FIELD(section, "authentication",    value,  opts->aut,  MAX_ID_LENGTH);
    HANDLE_FIELD(section, "pseudorandom",      value,  opts->prf,  MAX_ID_LENGTH);
    HANDLE_FIELD(section, "key-exchange",      value,  opts->kex,  MAX_ID_LENGTH);

    return 0;
}

/**
* @brief Function to parse the config file
* @param[in] cfg Data Structure to populate
* @param[in] section Section of the config file, name inside the square brakets
* @param[in] name Name of the configuration inside the section
* @param[in] value Value of the specified name
*/
int handler(void* cfg, const char* section, const char* name, const char* value){

    config* conf = (config *) cfg;

    if (strcmp(section, "Network") == 0){
        peer_handler(&conf->peer, section, name, value);
    }
    if (strcmp(section, "Authentication") == 0){
        auth_handler(&conf->auth, section, name, value);
    } 
    if (strcmp(section, "Crypto") == 0){
        crypto_handler(&conf->suite, section, name, value);
    } 
    


    return 1;

}