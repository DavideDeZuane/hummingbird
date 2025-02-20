#ifndef INITIATOR_H
#define INITIATOR_H

#include "../config/config.h"
#include <stdint.h>
#include <stdio.h>


typedef struct {
    uint64_t spi;
    uint8_t* key;
    size_t key_len;
    uint8_t* nonce;
    size_t nonce_len;
} ike_state_t;

typedef struct {
    struct sockaddr_storage sk;
    ike_state_t sa;;
} ike_responder;

typedef struct {
    int sockfd;
    struct sockaddr_storage sk;
    ike_state_t sa;
} ike_initiator;

/**
* @brief This function populate the responder with the option specified inside che configuration file
* @param[in] responder The struct wich rapresent the peer 
* @param[in] opts Options for the peer specified inside the config file
*/
int initiator_ini(ike_initiator *initiator, ike_responder *responder);
 
/**
* @brief This function populate the responder with the option specified inside che configuration file
* @param[in] responder The struct wich rapresent the peer 
* @param[in] opts Options for the peer specified inside the config file
*/
int responder_ini(ike_responder *responder, peer_options* opts);

#endif