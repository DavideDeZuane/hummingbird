#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include "../ike/header.h"

#define AF_INVALID -1
#define PORT_INVALID 0
#define EPHEMERAL_PORT 0 

#define FIELD_UINT16 16
#define FIELD_UINT32 32
#define FIELD_UINT64 6
#define CONVERT_TO_BIG_ENDIAN(value, type) (type == 16 ? htobe16(value) : (type == 32 ? htobe32(value) : (type == 64 ? htobe64(value) : value)))

/**
* @brief The generic pointer to data with the specified type will be converted to big-endin if necessary
* @param[in] data Generic pointer to the data that will be converted to big endian 
* @param[in] type The type of the message to convert
*/
void convert_to_big_endian(void *data, MessageComponent type);

/**
* @brief This function check if the ip address is valid
* @param[in] ip  The string wich contains the ip address to check
* @return  Return the AF_INET or AF_INET6 or -1 if the address is not valid 
*/
int validate_address(char *ip);

/**
* @brief This function check the value of the port passed on the configuration file
* @param[in] port  The string wich contains the port to check
* @return Return the port if is valid or 0 if not valid
*/
int validate_port(char *port);


int socket_up(int *sockfd, struct sockaddr_storage *sk_i, int AF, struct sockaddr_storage *sk_r);

/**
* @brief this function populate the address information of the peer socket
*/
int socket_setup(int* sockfd, int AF);

/**
* @brief this function populate the address information of the peer socket
*/
int socket_set_address(struct sockaddr_storage *sk, int AF, char *ip, int port);

#endif