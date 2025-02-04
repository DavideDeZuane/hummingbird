#include "utils.h"
#include "../network/network.h"
#include "../ike/payload.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
* @brief This function securely remove all the content of a pointer, to achive this we use the function explicit_bzero because the memset function migth be ignored by the compiler
* @param[in] ptr Pointer to the memory area to free
* @param[in] size  Size of the memory to replace with all 0
*/
void secure_free(void* ptr, size_t size){
    if(ptr){
        explicit_bzero(ptr, size);
        free(ptr);
        ptr = NULL;
    }
}

/**
* @brief This function convert the numeric value of an AF to a string 
* @param[in] af Value of the AF to print
*/
const char* address_family_to_string(int af) {
    switch (af) {
        case AF_INET:
            return "AF_INET";
        case AF_INET6:
            return "AF_INET6";
        default:
            return "Unknown Address Family";
    }
}

/**
* @brief This function return which fields of a given struct of the IKE packet must be converted for a big endian rappresentation
* @param[in] type The type of the struct to convert
* @param[out] num The number of the field to convert
* @return A dynamic array of the field co convert
*/
field_descriptor_t* fields_to_convert(MessageComponent type, size_t* num_fields) {
    field_descriptor_t* fields = NULL;
    size_t num = 0;

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
        case GENERIC_PAYLOAD_HEADER: {
            field_descriptor_t tmp[] = {
                { offsetof(ike_payload_header_t, length), FIELD_UINT16 },
            };
            num = sizeof(tmp) / sizeof(tmp[0]);
            fields = malloc(num * sizeof(field_descriptor_t));
            memcpy(fields, tmp, num * sizeof(field_descriptor_t));
            break;
        }
        case PAYLOAD_TYPE_KE: {
            field_descriptor_t tmp[] = {
                { offsetof(ike_payload_kex_t, dh_group), FIELD_UINT16 },
            };
            num = sizeof(tmp) / sizeof(tmp[0]);
            fields = malloc(num * sizeof(field_descriptor_t));
            memcpy(fields, tmp, num * sizeof(field_descriptor_t));
            break;
        }
        case PAYLOAD_TYPE_NONCE: {

        }
        default:{
            break;
        }
    }
    *num_fields = num;
    return fields;
}

void dump_memory(const void *mem, size_t len) {
    const unsigned char *ptr = (const unsigned char*) mem;
    for (size_t i = 0; i < len; i += 16) {
        // Stampa i byte in esadecimale (16 byte per riga)
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x", ptr[i + j]);
            else
            printf("   ");
        }
        printf("\n");
    }
    printf("\n");
}