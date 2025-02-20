#include "../common_include.h" // IWYU pragma: keep
#include "../log/log.h"
#include "config.h"

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

enum { CURVE_X25519, AES_128_CBC, HMAC_SHA1 };

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
        memcpy(responder->hostname, value, INET_FQNLEN);    
    } else if (MATCH("Peer", "address")) {
        memcpy(responder->address, value, INET_ADDRSTRLEN);
    } else if (MATCH("Peer", "port")) {
        memcpy(responder->port, value, MAX_PORT_LENGTH);
    } else {
        return 0;  
    }
    return 1;

}

int handler(void* cfg, const char* section, const char* name, const char* value){

    config *conf = (config *) cfg;
    peer_handler(&conf->peer, section, name, value);

    if (MATCH("Logging", "level")) {
        log_set_level(atoi(value));    
    }


    return 1;

}