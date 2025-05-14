#include "../include/log.h"
#include "../include/network.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <ifaddrs.h>
#include <endian.h>
#include "../include/ike/constant.h"
#include "../include/utils.h"
#include "../include/config.h"


/**
* @brief This function check if the ip address is valid
* @param[in] ip  The string wich contains the ip address to check
* @return  Return the AF_INET or AF_INET6 or -1 if the address is not valid 
*/
int validate_address(char *ip){
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; 
    if (getaddrinfo(ip, NULL, &hints, &res) == 0) {
        int family = res->ai_family;
        freeaddrinfo(res); 
        return family;    
    }
    return AF_INVALID; 
}

/**
* @brief This function check the value of the port passed on the configuration file
* @param[in] port  The string wich contains the port to check
* @return Return the port if is valid or 0 if not valid
*/
int validate_port(char *port){
    int port_n = atoi(port);
    if(port_n >0 && port_n < 65535)
        return port_n;
    else
        return 0; //chiamare tipo port not valid
}

/**
* @brief This function convert the rappresentation of the field of a struct in big-endian.
* @param[in] data Generic pointer to a buffer of data to convert
* @param[in] type Type of the data to convert this will be used to deterimnate which fields must be converted
*/
void convert_to_big_endian(void *data, MessageComponent type) {
    size_t num_fields = 0;
    field_descriptor_t* fields = fields_to_convert(type, &num_fields);
    for (size_t i = 0; i < num_fields; i++) {
        void *field_ptr = (uint8_t *)data + fields[i].offset;
        switch (fields[i].type) {
            case FIELD_UINT16: {
                uint16_t *value = (uint16_t *)field_ptr;
                *value = CONVERT_TO_BIG_ENDIAN(*value, 16);  // Conversione in big-endian per uint16_t
                break;
            }
            case FIELD_UINT32: {
                uint32_t *value = (uint32_t *)field_ptr;
                *value = CONVERT_TO_BIG_ENDIAN(*value, 32);  // Conversione in big-endian per uint32_t
                break;
            }
            case FIELD_UINT64: {
                uint64_t *value = (uint64_t *)field_ptr;
                *value = CONVERT_TO_BIG_ENDIAN(*value, 64);  
                break;
            }
        }
    }
}

/**
* @brief This function creates the socket that the initiator will then use to communicate to the remote peer
* And configure some options of the socket.
* @param[out] sockfd This is the filedescriptor of the socket that will be used to communicate
* @param[in] AF What type of socket is created, since it depends on the one configured for the responder 
*/
int socket_setup(int *sockfd, int AF){
    int retval = socket(AF, SOCK_DGRAM, IPPROTO_UDP);
    if (retval == -1){
        log_error("Error creating socket. Errno value: %d (%s)\n", errno, strerror(errno));
        return EXIT_FAILURE;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;  
    timeout.tv_usec = 0;
    if (setsockopt(retval, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        printf("Error setting socket options");
        return EXIT_FAILURE;
    }

    *sockfd = retval;
    log_trace("Local socket of type %s created...", address_family_to_string(AF));
    return 0;
}

/**
 * @brief This function populate the sockaddress storage passed for reference
 * @param[out] sk The socket address struct to populate 
 * @param[in]  af Specify which version of internet protocol use
 * @param[in]  ip Specify which ip use
 * @param[in]  port Specify which port use for address 
 * @return 
 */
int socket_set_address(struct sockaddr_storage *sk, int af, char *ip, int port){
    //the struct sockaddr_storage can contains both ipv4 and ipv6
    int retv;
    memset(sk, 0, sizeof(struct sockaddr_storage));
    switch (af) {
        case AF_INET: {
            struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)sk;
            ipv4_addr->sin_port = htons(port);
            ipv4_addr->sin_family = af;
            if(ip == NULL){
                //quando non specifico l'ip è il caso dell'initiator
                ipv4_addr->sin_addr.s_addr = INADDR_ANY;
                return EXIT_SUCCESS;
            }
            retv = inet_pton(AF_INET, ip, &ipv4_addr->sin_addr);
            break;
        };
        case AF_INET6: {
            struct sockaddr_in6 *ipv6_addr = (struct sockaddr_in6 *)sk;
            ipv6_addr->sin6_port = htons(port);
            ipv6_addr->sin6_family = AF_INET6;
            if(ip == NULL){
                //quando non specifico l'ip è il caso dell'initiator
                ipv6_addr->sin6_addr = in6addr_any;
                return EXIT_SUCCESS;
            }
            retv = inet_pton(AF_INET6, ip, &ipv6_addr->sin6_addr);  // Indirizzo IPv6
            break;
        };
    }
    return retv;
}

/**
 * @brief This function performs all the necessary operations to create the local socket and retrieve the ephemeral port that uses
 * @param[out] sockfd Return the file descriptor of the local socket opened to comunicate con the remote 
 * @param[in]  sk_i Address to use for the socket that will be populated and then binded with the file descriptor
 * @param[in]  AF Specify which family use
 * @return 
 */
int socket_up(int *sockfd, struct sockaddr_storage *sk_i, int AF, struct sockaddr_storage *sk_r){ //IMPORTANTE rimuovere il parametro sk_r
    //creating the socket
    if (socket_setup(sockfd, AF) == EXIT_FAILURE){
        log_error("Error during che socket creation");
        return EXIT_FAILURE;
    }
    //setting the soket information
    if (socket_set_address(sk_i, AF, NULL, EPHEMERAL_PORT) == EXIT_FAILURE){
        log_error("Error populating the socket information");
        return EXIT_FAILURE;
    }
    //binding the address with the socket
    if (bind(*sockfd, (struct sockaddr *)sk_i, sizeof(struct sockaddr)) == -1){
        log_error("Error during bind");
        perror("Errore");
        strerror(errno);
    }
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(*sockfd, (struct sockaddr *)&addr, &addr_len) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    if (addr.ss_family == AF_INET) {
        // IPv4
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
        log_trace("Initiator running on ephemeral port (IPv4): " ANSI_COLOR_BOLD "%d" ANSI_COLOR_RESET, ntohs(addr_in->sin_port));
    } else if (addr.ss_family == AF_INET6) {
        // IPv6
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
        log_trace(ANSI_COLOR_YELLOW "Initiator running on ephemeral port (IPv6): %d" ANSI_COLOR_RESET, ntohs(addr_in6->sin6_port));
    }
    return EXIT_SUCCESS;
}

/**
* @brief This function populate the socket information of both peer based on the option on the configuration file
* @param[out] local   This is the scruct tha will be populate with the network information of the local host
* @param[out] remote  This is the scruct that contains the network information of the remote host
* @param[in]  opts    These are the options provided for the remote peer in the configuration file
*/
int initiate_network(net_endpoint_t *local, net_endpoint_t *remote, peer_options* opts){
    //Remote Endpoint configuration
    log_debug("[NET] Validating configurations options");
    int af, port = 0;
    af = validate_address(opts->address);
    port = validate_port(opts->port);
    if(af == AF_INVALID || port == PORT_INVALID){ 
        log_error("Invalid AF or Port for the address of the peer");
        return EXIT_FAILURE;
    }
    socket_set_address(&remote->addr, af, opts->address, port);
    remote->fd = -1;
    log_trace("Peer socket at " ANSI_COLOR_BOLD "%s:%d", opts->address, port);

    //local endpoint configuration
    int retv = socket_up(&local->fd, &local->addr, remote->addr.ss_family, &remote->addr);
    if(retv == -1){
        printf("Error configuring the socket");
        return EXIT_FAILURE;
    }
    // se entrambi vanno a buon fine provo a fare la connect
    //in questo modo facciamo si che il destinatario sia associato al socket, in questo modo possiamo usare direttamente la recv e la send 
    //inoltre  il socket rifiuterà di inviare e ricevere dati da qualsiasi altro indirizzo o porta (il socket è legato al server specifico)
    if (connect(local->fd, (struct sockaddr *) &remote->addr, sizeof(struct sockaddr_storage)) < 0) {
        perror("connect failed");
        close(local->fd);
        return EXIT_FAILURE;
    } 
    return EXIT_SUCCESS;
}