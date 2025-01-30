#include "utils.h"
#include "../network/network.h"
#include <stdio.h>
#include <stdlib.h>

void print_hex(char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

field_descriptor_t* fields_to_convert(MessageComponent type, size_t* num_fields) {
    field_descriptor_t* fields = NULL;
    size_t num = 0;

    // Switch per determinare i campi da convertire in base al tipo di Payload
    switch(type) {
        case IKE_HEADER: {
            field_descriptor_t tmp[] = {
                { offsetof(ike_header_t, initiator_spi), FIELD_UINT64 },
                { offsetof(ike_header_t, responder_spi), FIELD_UINT64 },
                { offsetof(ike_header_t, message_id), FIELD_UINT32 },
                { offsetof(ike_header_t, length), FIELD_UINT32 }
            };
            num = sizeof(tmp) / sizeof(tmp[0]);
            fields = malloc(num * sizeof(field_descriptor_t));
            memcpy(fields, tmp, num * sizeof(field_descriptor_t));
            break;
        }
        default:
            break;
    }
    *num_fields = num;
    return fields;
}