#ifndef IKE_ALL
#define IKE_ALL

#include "constant.h"
#include "header.h"
#include "../socket/peer.h"
#include "../crypto/crypto.h"

/**
* @brief Questo enum serve per distinguere il caso in cui stiamo trattando un initiator o un responder
* questo perchè se si tratta di un initiator la chiave sarà di un tipo se si tratta di un responder 
* sarà di un altro tipo 
*/
typedef enum {
    IKE_INITIATOR,
    IKE_RESPONDER
} ike_role_t;

typedef struct {
    uint8_t *sk_d;  
    uint8_t *sk_ai;
    uint8_t *sk_ar;
    uint8_t *sk_ei;
    uint8_t *sk_er;
    uint8_t *sk_pi;
    uint8_t *sk_pr;
    size_t key_len;
} ike_sa_t;

typedef struct {
    uint64_t spi;
    endpoint node;
    ike_role_t role;
    crypto_context_t ctx;
} ike_partecipant_t;

typedef struct {
    ike_partecipant_t initiator;
    ike_partecipant_t responder;
    ike_sa_t association;
} ike_session_t;


#endif