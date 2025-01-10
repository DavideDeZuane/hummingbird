#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>
#include <stdint.h>

#define AF_INVALID -1
#define PORT_INVALID 0
#define EPHEMERAL_PORT 0 

/**
* @brief This function check the AF of the passed string 
* @param[in] ip  The string wich contains the ip address to check
* @return  Return the AF_INET or AF_INET6 or -1 if the address is not valid 
*/
int validate_address(char *ip);

/**
* @brief This function check the value of the port passed on the configuration file
* @param[in] port  The string wich contains the port to check
* @return Return the port if is valid or 0 if is it not valid
*/
int validate_port(char *port);


int socket_up(int *sockfd, struct sockaddr_in *sk);

/**
* @brief this function populate the address information of the peer socket
*/
int socket_setup(int* sockfd);

/**
* @brief this function populate the address information of the peer socket
*/
int socket_set_address(struct sockaddr_in *sk, int AF, char *ip, int port);

#endif