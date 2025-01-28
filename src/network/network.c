#include "../common_include.h" // IWYU pragma: keep
#include "../log/log.h"
#include "network.h"
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

void check_endian(){
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        printf("Il sistema è Little Endian.\n");
    #elif __BYTE_ORDER == __BIG_ENDIAN
        printf("Il sistema è Big Endian.\n");
    #endif
}

// questa può stare anche qui oppure tocca spostarla su utils
const char* address_family_to_string(int af) {
    switch (af) {
        case AF_INET:
            return "AF_INET";
        case AF_INET6:
            return "AF_INET6";
        default:
            return "Unknown Address Family";
    }
}

/**
 * @brief 
 * @return 
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
    log_info("Socketfd of type %s created...", address_family_to_string(AF));
    return 0;
}

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

//questo combina le funzionalità della socket_setup e della socket_set address
//dato che qui configuro l'initiator per determinare quale interfaccia utilizzare devo utilizzare la combo chiamata connect e getsockname
int socket_up(int *sockfd, struct sockaddr_storage *sk_i, int AF, struct sockaddr_storage *sk_r){
    
    if (socket_setup(sockfd, AF) == EXIT_FAILURE){
        log_error("Error during che socket creation");
        return EXIT_FAILURE;
    }

    if (socket_set_address(sk_i, AF, NULL, EPHEMERAL_PORT) == EXIT_FAILURE){
        log_error("Error populating the socket information");
        return EXIT_FAILURE;
    }

    if (bind(*sockfd, (struct sockaddr *)sk_i, sizeof(struct sockaddr)) == -1){
        log_error("Error during bind");
        perror("Errore");
        strerror(errno);
    }


    /*
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(*sockfd, (struct sockaddr *)&addr, &addr_len) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }
    if (addr.ss_family == AF_INET) {
        // IPv4
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
        log_info("Initiator running on ephemeral port (IPv4): %d", ntohs(addr_in->sin_port));
    } else if (addr.ss_family == AF_INET6) {
        // IPv6
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
        log_info("Initiator running on ephemeral port (IPv6): %d", ntohs(addr_in6->sin6_port));
    }
    */
    return EXIT_SUCCESS;
}

int validate_address(char *ip){
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    // Non filtrare per IPv4 o IPv6
    hints.ai_family = AF_UNSPEC; 

    if (getaddrinfo(ip, NULL, &hints, &res) == 0) {
        int family = res->ai_family;
        freeaddrinfo(res); 
        return family;    
    }

    return AF_INVALID;  // Non è un indirizzo valido
}

int validate_port(char *port){
    int port_n = atoi(port);
    if(port_n >0 && port_n < 65535)
        return port_n;
    else
        return 0; //chiamare tipo port not valid
}
