#ifndef AUTH_H
#define AUTH_H

#include "common.h"
#include "config.h"

typedef enum {
    AUTH_METHOD_PSK,
    AUTH_METHOD_RSA,
} auth_method_t;

typedef struct {
    auth_method_t method;
    //manca un campo per l'id
    char *id_data;  
    size_t id_len;
    uint8_t *psk;  
    size_t psk_len;
} auth_context_t;


/**
* @brief
* @param[in] auth
* @param[in] opts
*/
int initiate_auth(auth_context_t* auth, const auth_options_t* opts);

#endif