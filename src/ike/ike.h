#ifndef IKE_ALL
#define IKE_ALL

#include "constant.h"
#include "header.h"
#include "../socket/peer.h"
#include "../crypto/crypto.h"
#include <cstdint>

typedef enum {
    IKE_INITIATOR,
    IKE_RESPONDER
} ike_role_t;

typedef struct {
    uint64_t spi;
    endpoint node;
    ike_role_t role;

    // oltre al ruolo è presente il crypto context
} ike_partecipant_t;

typedef struct {
    ike_partecipant_t initiator;
    ike_partecipant_t responder;
} ike_session_t;


#endif