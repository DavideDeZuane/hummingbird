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

/**
* @brief questo struct rapprenta la ike security association
* quindi lo stato condiviso tra i due partecipanti uno dei parametri significativi
* è la lunghezza delle chiavi dato che dipende dalla funzione prf utilizzata
*/
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

/**
* @brief questo struct rapprenta la struttura che ha un partecipante al protocollo IKE, ovvero:
* è un endpoint, quindi ha delle informazioni di rete 
* ha un crypto_context ovvero ha del materiale crittografico che verrà utilizzato per derivare lo stato condiivisi tra i due
* il security parameter index
*/
typedef struct {
    endpoint node;
    ike_role_t role;
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

void initiate_ike(ike_partecipant_t* left, ike_partecipant_t* rigth);

#endif