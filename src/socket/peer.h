#ifndef INITIATOR_H
#define INITIATOR_H

#include "../config/config.h"
#include <stdint.h>
#include <stdio.h>


// questo più che stato lo chiamerei crypto_context ovvero il materiale crittografico che serve per determinare lo stato condiviso daella SA
typedef struct {
    uint64_t spi;
    uint8_t* key;
    size_t key_len;
    uint8_t* nonce;
    size_t nonce_len;
} ike_state_t;

typedef struct {
    struct sockaddr_storage sk;
    ike_state_t sa;;
} ike_responder;

// questo lo soprannominerei in node oppure endpoint
typedef struct {
    int sockfd;
    struct sockaddr_storage sk;
    ike_state_t sa;
} ike_initiator;


/**
 * @brief Rappresenta un endpoint di rete (Initiator o Responder).
 *
 * Questa struct memorizza le informazioni necessarie per identificare
 * un nodo in una connessione, inclusi l'indirizzo di rete e (se applicabile)
 * un file descriptor per la comunicazione. Se non ha un socket il fd è valorizzato a -1
 */
typedef struct {
    struct sockaddr_storage addr;
    int fd;    
} endpoint;


int partecipants_ini(endpoint *local, endpoint *remote, peer_options* opts);

/**
* @brief This function populate the responder with the option specified inside che configuration file
* @param[in] responder The struct wich rapresent the peer 
* @param[in] opts Options for the peer specified inside the config file
*/
int initiator_ini(ike_initiator *initiator, ike_responder *responder);
 
/**
* @brief This function populate the responder with the option specified inside che configuration file
* @param[in] responder The struct wich rapresent the peer 
* @param[in] opts Options for the peer specified inside the config file
*/
int responder_ini(ike_responder *responder, peer_options* opts);

#endif