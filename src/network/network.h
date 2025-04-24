#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include "../ike/header.h"
#include "../config/config.h"

#define AF_INVALID -1
#define PORT_INVALID 0
#define EPHEMERAL_PORT 0 

#define MAX_PAYLOAD 1280

#define FIELD_UINT16 16
#define FIELD_UINT32 32
#define FIELD_UINT64 6
#define CONVERT_TO_BIG_ENDIAN(value, type) (type == 16 ? htobe16(value) : (type == 32 ? htobe32(value) : (type == 64 ? htobe64(value) : value)))

/**
 * @brief Rappresenta un endpoint di rete (Initiator o Responder).
 * @note Assumpution for the remote endpoint the file descritor is set to -1 ()
*/
typedef struct {
    int fd;    
    struct sockaddr_storage addr;
} net_endpoint_t;

/**
* @brief The generic pointer to data with the specified type will be converted to big-endin if necessary
* @param[in] data Generic pointer to the data that will be converted to big endian 
* @param[in] type The type of the message to convert
*/
void convert_to_big_endian(void *data, MessageComponent type);

/**
* @brief This function populate the socket information of both peer based on the option on the configuration file
* @param[out] local   This is the scruct tha will be populate with the network information of the local host
* @param[out] remote  This is the scruct that contains the network information of the remote host
* @param[in]  opts    These are the options provided for the remote peer in the configuration file
*/
int initiate_netwok(net_endpoint_t *local, net_endpoint_t *remote, peer_options* opts);


#endif