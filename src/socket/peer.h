#ifndef INITIATOR_H
#define INITIATOR_H

#include "../config/config.h"
#include <stdint.h>

typedef struct {
    struct sockaddr_in sk;
    uint64_t spi;
} ike_responder;


typedef struct {
    int sockfd;
    uint64_t spi;
    struct sockaddr_in sk;
} ike_initiator;

/**
* @brief This function populate the responder with the option specified inside che configuration file
* @param[in] responder The struct wich rapresent the peer 
* @param[in] opts Options for the peer specified inside the config file
*/
int initiator_ini(ike_initiator *initiator);
 
/**
* @brief This function populate the responder with the option specified inside che configuration file
* @param[in] responder The struct wich rapresent the peer 
* @param[in] opts Options for the peer specified inside the config file
*/
int responder_ini(ike_responder *responder, peer_options* opts);

#endif