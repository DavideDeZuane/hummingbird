#include "../include/auth.h"
#include "../include/log.h"
#include "../include/ike/constant.h"
#include <string.h>


int initiate_auth(auth_context_t* auth, const auth_options_t* opts){

    // check the validity of the psk
    log_debug("[AUT] Validating configurations options");

    if(strcmp(opts->method, "psk") == 0){
        auth->method = AUTH_METHOD_PSK;

        auth->psk_len = strlen(opts->data);
        auth->psk = calloc(strnlen(opts->data, MAX_AUTH_DATA_LEN), BYTE);
        memcpy(auth->psk, opts->data, auth->psk_len);

        auth->id_len = strlen(opts->id);
        auth->id_data = calloc(strnlen(opts->id, MAX_AUTH_ID_LEN), BYTE);
        memcpy(auth->id_data, opts->id, auth->id_len);

        log_trace("Auth Method PSK");
        log_trace("ID: %s and PSK: " ANSI_COLOR_BOLD "%s", auth->id_data, auth->psk);
    }

    return EXIT_SUCCESS;


}