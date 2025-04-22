#include "ike.h"
#include "../log/log.h"
#include "../network/network.h"
#include "constant.h"
#include <stddef.h>
#include <stdlib.h>
#include "../utils/utils.h"

#define COPY_AND_ADVANCE(dest, src, offset, len)  \
    memcpy((dest), (src) + (offset), (len));      \
    (offset) += (len);



void initiate_ike(ike_partecipant_t* left, ike_partecipant_t* right, config* cfg){


    log_info(ANSI_COLOR_GREEN "Starting the init process of hummingbird..." ANSI_COLOR_RESET);
    int retv = initiate_netwok(&left->node, &right->node, &cfg->peer);
    // function that handle the module if not started successfully
    if(retv != 0){
        log_fatal("Could not initiate the [NET] module" );
        exit(EXIT_FAILURE);
    }
    log_info("[NET] module successfully setup");


    //the initiate crypto function has to return a int 
    //aggiungere le opzioni da verificare nella parte crypto quindi la lunghezza del nonce e le varie informazioni che riguardano le cipher suite da utilizzare
    retv = initiate_crypto(NULL, &left->ctx, &cfg->suite);
    if (retv == EXIT_FAILURE) {
        log_error("Could not initiate the [CRY] module");
        exit(EXIT_FAILURE);
    } 
    log_info(ANSI_COLOR_GREEN "[CRY] module successfully setup" ANSI_COLOR_RESET);
    
    //una volta che ho setuppato il crypto module allora sono pronto per fare la send per iniviare l'IKE_SA_INIT al peer
    // qui va tutta la parte di generazione del messaggio di cui si occupa il modulo IKE
    // aggiungere una struct di authentication data all'initiator e al responder.
    // questi devono essere utilizzati nella fase di IKE AUTH per generare l'authentication payload

    log_info("[IKE] module successfully setup");




}

int derive_ike_sa(ike_session_t* sa){
    
    //queste parti poi dipenderanno dall'algoritmo
    sa->association.enc_key_len = AES128_KEY_LENGTH;
    sa->association.oth_key_len = SHA1_DIGEST_LENGTH;

    size_t buff_len = NUM_KEYS*SHA1_DIGEST_LENGTH;
    uint8_t* T_buffer = calloc(buff_len, BYTE);

    //qui decido la dimensione del t_buffer e mando la lunghezza alla funzione di prf+, in cui quello che devo andare a fare è controllare 
    // che il buffer ci sia e la dimensione

    prf_plus(&sa->initiator.ctx, &sa->responder.ctx, &T_buffer);

    sa->association.sk_d = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_ai = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_ar = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_pi = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_pr = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_ei = calloc(AES128_KEY_LENGTH, BYTE);
    sa->association.sk_er = calloc(AES128_KEY_LENGTH, BYTE);

    size_t offset = 0;

    // al posto delle costanti mettere le variabili che riportano le lunghezze 
    COPY_AND_ADVANCE(sa->association.sk_d,  T_buffer, offset, SHA1_DIGEST_LENGTH);
    COPY_AND_ADVANCE(sa->association.sk_ai, T_buffer, offset, SHA1_DIGEST_LENGTH);
    COPY_AND_ADVANCE(sa->association.sk_ar, T_buffer, offset, SHA1_DIGEST_LENGTH);
    COPY_AND_ADVANCE(sa->association.sk_ei, T_buffer, offset, AES128_KEY_LENGTH);
    COPY_AND_ADVANCE(sa->association.sk_er, T_buffer, offset, AES128_KEY_LENGTH);
    COPY_AND_ADVANCE(sa->association.sk_pi, T_buffer, offset, SHA1_DIGEST_LENGTH);
    COPY_AND_ADVANCE(sa->association.sk_pr, T_buffer, offset, SHA1_DIGEST_LENGTH);


    
    int str_len = 2 * SHA1_DIGEST_LENGTH + 1;
    char* str = calloc(str_len, BYTE);
    format_hex_string(str, str_len, sa->association.sk_d, SHA1_DIGEST_LENGTH);
    log_trace("%-5s: 0x%s", "SK_d", str);

    format_hex_string(str, str_len, sa->association.sk_ai, SHA1_DIGEST_LENGTH);
    log_trace("%-5s: 0x%s", "SK_ai", str);

    format_hex_string(str, str_len, sa->association.sk_ar, SHA1_DIGEST_LENGTH);
    log_trace("%-5s: 0x%s", "SK_ar", str);
    
    format_hex_string(str, str_len, sa->association.sk_ei, AES128_KEY_LENGTH);
    log_trace("%-5s: 0x%s", "SK_ei", str);

    format_hex_string(str, str_len, sa->association.sk_er, AES128_KEY_LENGTH);
    log_trace("%-5s: 0x%s", "SK_er", str);

    format_hex_string(str, str_len, sa->association.sk_pi, SHA1_DIGEST_LENGTH);
    log_trace("%-5s: 0x%s", "SK_pi", str);
    
    format_hex_string(str, str_len, sa->association.sk_pr, SHA1_DIGEST_LENGTH);
    log_trace("%-5s: 0x%s", "SK_pr", str);



    



        
    // a questo punto il buffer popolato lo utilizziamo per derivare le chiavi


    //la dimensione delle chiavi dipende dall'algoritmo di cifrature e autenticazione utilizzato
    // in particolare abbiamo che:
    // - la dimensione delle chiavi di cifratura dipende dalla dimensione della chiave dell'algoritmo scelto, questo incide anche sull'IV
    // - la dimensione delle altre chiavi dipende da quella della dimensione del digest

    return 0;
}
