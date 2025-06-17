#include "../../include/ike/ike.h"
#include "../../include/log.h"
#include "../../include/network.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/utils.h"
#include "../../include/auth.h"

#define COPY_AND_ADVANCE(dest, src, offset, len)    \
    memcpy((dest), (src) + (offset), (len));        \
    (offset) += (len);                              \
\

// macro to handle the loading processos of a module
#define LOAD_MODULE(name, init_fn, ...)                                \
    do {                                                               \
        int ret = init_fn(__VA_ARGS__);                                \
        if (ret != 0) {                                                \
            log_fatal("Could not initiate the [%s] module", name);     \
            exit(EXIT_FAILURE);                                        \
        }                                                              \
    } while (0)                                                        \
\

/**
* @brief 
*/
void initiate_ike(ike_partecipant_t* left, ike_partecipant_t* right, ike_sa_t* sa, config* cfg){

    log_info(ANSI_COLOR_GREEN "Starting the init process of hummingbird..." ANSI_COLOR_RESET);

    LOAD_MODULE("NET", initiate_network, &left->node, &right->node, &cfg->peer);
    LOAD_MODULE("CRY", initiate_crypto, &sa->suite, &left->ctx, &cfg->suite);
    LOAD_MODULE("AUT", initiate_auth, &left->aut, &cfg->auth);

    log_info("[IKE] module successfully setup");
    free(cfg);

}


int derive_ike_sa(ike_session_t* sa){
    
    //queste parti poi dipenderanno dall'algoritmo
    sa->association.enc_key_len = AES128_KEY_LENGTH;
    sa->association.oth_key_len = SHA1_DIGEST_LENGTH;

    size_t buff_len = NUM_KEYS*SHA1_DIGEST_LENGTH;
    uint8_t* T_buffer = calloc(buff_len, BYTE);

    prf_plus(&sa->initiator.ctx, &sa->responder.ctx, &T_buffer);

    sa->association.sk_d  = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_ai = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_ar = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_pi = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_pr = calloc(SHA1_DIGEST_LENGTH, BYTE);
    sa->association.sk_ei = calloc(AES128_KEY_LENGTH, BYTE);
    sa->association.sk_er = calloc(AES128_KEY_LENGTH, BYTE);

    size_t offset = 0;

    //change the constant value for the length with the variable that contains the lengths of the keys
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

    log_info("IKE SA properly configured");

    return 0;
}
