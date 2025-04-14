#ifndef IKE_ALL
#define IKE_ALL

#include "constant.h"
#include "header.h"
#include "../network/network.h"
#include "../socket/peer.h"
#include "../crypto/crypto.h"

typedef enum {
    IKE_INITIATOR,
    IKE_RESPONDER
} ike_role_t;

/**
* @brief This struct represent the security association for the Internet Key Exchange protocol, 
* in particular the keys that are used in the exchange between the peer to authenticate each other, 
* encrypt the traffic and derive the keys for IPsec.
* @note There are two lengths for keys, in fact we have that 
* - the size of encryption keys depend on the algorithm you use. 
* - While the size of the other keys depends on the output of the chosen prf function
*/
typedef struct {
    uint8_t *sk_d;  
    uint8_t *sk_ai;
    uint8_t *sk_ar;
    uint8_t *sk_ei;
    uint8_t *sk_er;
    uint8_t *sk_pi;
    uint8_t *sk_pr;
    size_t oth_key_len;
    size_t enc_key_len;
} ike_sa_t;

/**
* @brief This struct represents the structure that an IKE protocol participant has, viz:
* - it is a node, so it has network information to be reachable 
* - it has cryptographic material that will be used to derive the shared state between the two
* - has a role on the exchange, which can be initiator or responder 
* @note This is what someone needs to participate in the ike exchange
*/
typedef struct {
    ike_role_t role;
    net_endpoint_t node;
    crypto_context_t ctx;
} ike_partecipant_t;

/**
* @brief This is the logical pairing between the two endpoint
*/
typedef struct {
    ike_partecipant_t initiator;
    ike_partecipant_t responder;
    ike_sa_t association;
} ike_session_t;

void initiate_ike(ike_partecipant_t* left, ike_partecipant_t* right, config* cfg);

#endif