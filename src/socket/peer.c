#include "../common_include.h" // IWYU pragma: keep
#include "../network/network.h"
#include "../log/log.h"
#include "peer.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>


int responder_ini(ike_responder *responder, peer_options* opts){
    int af, port = 0;
    af = validate_address(opts->address);
    port = validate_port(opts->port);
    if(af == AF_INVALID || port == PORT_INVALID){ 
        log_error("Invalid AF or Port for the address of the peer");
        log_fatal("Sthutting down...");
        return EXIT_FAILURE;
    }

    socket_set_address(&responder->sk, af, opts->address, port);
    log_info("Peer socket at %s:%d", opts->address, port);
    return EXIT_SUCCESS;
}

int initiator_ini(ike_initiator *initiator){
    /* 
    **********************************
    Network Configuration of the socket 
    ************************************
    */
    memset(initiator, 0, sizeof(ike_initiator));
    //fare il check del valore di ritorno di questa funzione
    socket_up(&initiator->sockfd, (struct sockaddr_in *)&initiator->sk);

    return EXIT_SUCCESS;

}

int initiator_destroy(ike_initiator *initiator){
    return 1;
}