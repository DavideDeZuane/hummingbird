#include "../include/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void alloc_buffer(uint8_t **buff, size_t size) {
    if (buff == NULL || size == 0) return;

    *buff = malloc(size);
    if (*buff == NULL) {
        fprintf(stderr, "Errore allocazione memoria\n");
    }
}

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
* @brief This function return the content of a memory pointed by the pointer specified for the length specified 
* @param[in] mem Pointer to the memory to dump 
* @param[in] len Length of the memory to dump
* @note This function is essential to debug the content of the filed converted to big-endian in memory
* This because the printf function ignore the rappresentation and print as little-endian 
*/
void dump_memory(const void *mem, size_t len) {
    // check on the pointer
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

/**
* @brief This function print a baffer passed as input in hex format
* @param[in] data Buffer of data to convert in hexadecimal
* @param[in] len Length of the buffer to print
*/
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
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
* @brief This function return the corisponding text of next payload
*/
const char* next_payload_to_string(NextPayload type){
    switch (type){
        case NEXT_PAYLOAD_NONE:    return "None";
        case NEXT_PAYLOAD_SA:      return "Security Association (SA)";
        case NEXT_PAYLOAD_KE:      return "Key Exchange (KE)";
        case NEXT_PAYLOAD_IDi:     return "Identity (ID)";
        case NEXT_PAYLOAD_IDr:     return "Identity (ID)";
        case NEXT_PAYLOAD_CERT:    return "Key Exchange (KE)";
        case NEXT_PAYLOAD_CERTREQ: return "Key Exchange (KE)";
        case NEXT_PAYLOAD_AUTH:    return "Key Exchange (KE)";
        case NEXT_PAYLOAD_NONCE:   return "Nonce (N)";
        case NEXT_PAYLOAD_NOTIFIY: return "Notify";
        case NEXT_PAYLOAD_DELETE:  return "";
        case NEXT_PAYLOAD_TSi:     return "";
        case NEXT_PAYLOAD_TSr:     return "";
        case NEXT_PAYLOAD_SK:      return "Encrypted Payload (SK)";
    }
    return "";
}

/** 
* @brief Mapping funcion between NextPayload and MessageComponent
*/
MessageComponent next_payload_to_component(uint8_t np) {
    switch (np) {
        case NEXT_PAYLOAD_NONCE:   return PAYLOAD_TYPE_NONCE;
        case NEXT_PAYLOAD_KE:      return PAYLOAD_TYPE_KE;
        case NEXT_PAYLOAD_SA:      return PAYLOAD_TYPE_SA;
        // aggiungi altri se ti servono
        default:                   return PAYLOAD_TYPE_NONE;  // o GENERIC_PAYLOAD_HEADER
    }
}


uint32_t bytes_to_uint32_be(const uint8_t *bytes) {
    #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    // Architettura big endian: salta la conversione
    #else
    // Architettura little endian: fai la conversione
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8)  |
           ((uint32_t)bytes[3]);
    #endif
}

void uint32_to_bytes_be(uint32_t val, uint8_t *out_bytes) {
    out_bytes[0] = (val >> 24) & 0xFF;
    out_bytes[1] = (val >> 16) & 0xFF;
    out_bytes[2] = (val >> 8) & 0xFF;
    out_bytes[3] = val & 0xFF;
}

uint16_t bytes_to_uint16_be(const uint8_t *bytes) {
    return ((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1];
}

void uint16_to_bytes_be(uint16_t val, uint8_t *out_bytes) {
    out_bytes[0] = (val >> 8) & 0xFF;
    out_bytes[1] = val & 0xFF;
}

void format_hex_string(char *dest, size_t dest_size, const uint8_t *data, size_t data_len) {
    size_t i, written = 0;
    for (i = 0; i < data_len && written + 2 < dest_size; i++) {
        written += snprintf(dest + written, dest_size - written, "%02x", data[i]);
    }
}