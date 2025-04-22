#ifndef AUTH_H
#define AUTH_H

#include "../common_include.h"

typedef enum {
    AUTH_METHOD_PSK,
    AUTH_METHOD_RSA,
    AUTH_METHOD_ECDSA,
    AUTH_METHOD_NULL
} auth_method_t;

typedef struct {
    auth_method_t method;
    uint8_t *auth_data;  
    size_t auth_data_len;
} auth_context_t;

#endif