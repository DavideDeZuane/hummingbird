#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include "../include/ike/header.h"
#include "../include/config.h"

#define AF_INVALID -1
#define PORT_INVALID 0
#define EPHEMERAL_PORT 0 

#define MAX_PAYLOAD 1280

/**
 * @brief Rappresenta un endpoint di rete (Initiator o Responder).
 * @note Assumpution for the remote endpoint the file descritor is set to -1 ()
*/
typedef struct {
    int fd;    
    struct sockaddr_storage addr;
} net_endpoint_t;


/**
* @brief This function populate the socket information of both peer based on the option on the configuration file
* @param[out] local   This is the scruct tha will be populate with the network information of the local host
* @param[out] remote  This is the scruct that contains the network information of the remote host
* @param[in]  opts    These are the options provided for the remote peer in the configuration file
*/
int initiate_network(net_endpoint_t *local, net_endpoint_t *remote, peer_options* opts);


#endif