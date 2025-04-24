#include "auth.h"
#include <string.h>
#include "../log/log.h"
#include "../ike/constant.h"


int initiate_auth(auth_context_t* auth, const auth_options_t* opts){

    // check the validity of the psk
    log_debug("[AUT] Validating configurations options");

    if(strcmp(opts->method, "psk") == 0){
        auth->method = AUTH_METHOD_PSK;
        auth->auth_data_len = strlen(opts->data);
        auth->auth_data = calloc(strnlen(opts->data, MAX_AUTH_DATA_LEN), BYTE);
        memcpy(auth->auth_data, opts->data, auth->auth_data_len);
        log_trace("Auth Method PSK");
        log_trace("PSK: " ANSI_COLOR_BOLD "%s", auth->auth_data);
    }

    return EXIT_SUCCESS;


}