#include "../common_include.h" // IWYU pragma: keep
#include "../log/log.h"
#include "network.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>

int socket_setup(int *sockfd);
int socket_set_address(struct sockaddr_in *sk, int af, char *ip, int port);

int socket_up(int *sockfd, struct sockaddr_in* sk){
    
    if(socket_setup(sockfd) == EXIT_FAILURE){
        log_error("Error during che socket creation");
        return EXIT_FAILURE;
    }

    if(socket_set_address(sk, AF_INET, NULL, EPHEMERAL_PORT) == EXIT_FAILURE){
        log_error("Error populating the socket information");
        return EXIT_FAILURE;
    }

    int retval = bind(*sockfd, (struct sockaddr *)sk, sizeof(struct sockaddr));
    if(retval == -1) printf("Error during bind");
    
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(*sockfd, (struct sockaddr *)&addr, &addr_len) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }
    log_info("Initiator running on ephermal port: %d", ntohs(addr.sin_port));
    return EXIT_SUCCESS;


}

int socket_setup(int *sockfd){
    
    int retval = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(retval == -1){
        printf("Error creating socket. Errno value: %d (%s)\n", errno, strerror(errno));
        return EXIT_FAILURE;
    }
    // setto anche le opzioni del socket
    struct timeval timeout;
    timeout.tv_sec = 1;  
    timeout.tv_usec = 0;
    if (setsockopt(retval, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        printf("Error setting socket options");
        return EXIT_FAILURE;
    }

    *sockfd = retval;
    // se va tutto bene assegna il socket a quello che gli è stato passato per riferimento 
    return 0;

}

int socket_set_address(struct sockaddr_in *sk, int af, char *ip, int port){
    memset(sk, 0, sizeof(struct sockaddr_in));
    sk->sin_port = htons(port);
    sk->sin_family = af;
    if(ip == NULL){
        sk->sin_addr.s_addr = INADDR_ANY;
        return EXIT_SUCCESS;
    }
    inet_pton(af, ip, &sk->sin_addr);
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
