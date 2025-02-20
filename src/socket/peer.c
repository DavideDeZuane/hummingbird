#include "../common_include.h" // IWYU pragma: keep
#include "../network/network.h"
#include "../log/log.h"
#include "peer.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

int partecipants_ini(endpoint *local, endpoint *remote, peer_options* opts){
    /*-------------------------------------------------------------------
    Remote Endpoint configuration
    -------------------------------------------------------------------*/
    int af, port = 0;
    af = validate_address(opts->address);
    port = validate_port(opts->port);
    if(af == AF_INVALID || port == PORT_INVALID){ 
        log_error("Invalid AF or Port for the address of the peer");
        log_fatal("Sthutting down...");
        return EXIT_FAILURE;
    }
    socket_set_address(&remote->addr, af, opts->address, port);
    remote->fd = -1;
    log_info("Peer socket at %s:%d", opts->address, port);
    /*-------------------------------------------------------------------
    Local Endpoint configuration
    -------------------------------------------------------------------*/
    log_info("Configuring local socket...");
    int retv = socket_up(&local->fd, &local->addr, remote->addr.ss_family, &remote->addr);
    if(retv == -1){
        printf("Error configuring the socket");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}



int responder_ini(ike_responder *responder, peer_options* opts){
    int af, port = 0;
    af = validate_address(opts->address);
    port = validate_port(opts->port);
    if(af == AF_INVALID || port == PORT_INVALID){ 
        log_error("Invalid AF or Port for the address of the peer");
        log_fatal("Sthutting down...");
        return EXIT_FAILURE;
    }
    //in base all'AF configurato per il responder devo configurare quello dell'initiator
    socket_set_address(&responder->sk, af, opts->address, port);
    log_info("Peer socket at %s:%d", opts->address, port);
    return EXIT_SUCCESS;
}

// la configurazione dell'initiator dipende fortemente da quella del responder, per questo motivo per configurare l'inititator gli passiamo anche il responder
int initiator_ini(ike_initiator *initiator, ike_responder *responder){
    /* 
    **********************************
    Network Configuration of the socket 
    ************************************
    */
    memset(initiator, 0, sizeof(ike_initiator));
    int retv = socket_up(&initiator->sockfd, &initiator->sk, responder->sk.ss_family, &responder->sk);
    if(retv == -1){
        printf("Error configuring the socket");
    }
    /* 
    **********************************
    Genereting Cryptograpy Material
    ************************************
    */

    return EXIT_SUCCESS;

}

int initiator_destroy(ike_initiator *initiator){
    return 1;
}