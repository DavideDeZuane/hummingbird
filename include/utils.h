#ifndef UTILITY_H
#define UTILITY_H

#include "common.h"
#include "ike/constant.h"
#include <stdio.h>


MessageComponent next_payload_to_component(uint8_t np);

uint32_t bytes_to_uint32_be(const uint8_t *bytes);

uint16_t bytes_to_uint16_be(const uint8_t *bytes);

void uint16_to_bytes_be(uint16_t val, uint8_t *out_bytes);

void uint32_to_bytes_be(uint32_t val, uint8_t *out_bytes);

void format_hex_string(char *dest, size_t dest_size, const uint8_t *data, size_t data_len);


void alloc_buffer(uint8_t **buff, size_t size);

/**
* @brief This function print the value passed in a big endian rappresentation
* @param[in] data The data to print in big-endian format
* @param[in] size The length of the data to print
*/
void dump_memory(const void *mem, size_t len);

/**
* @brief Print the content in hex format
*/
void print_hex(const unsigned char *data, size_t len);

/**
* @brief This function securely remove all the content of a pointer 
* @param[in] ptr Pointer to the memory area to free
* @param[in] size  Size of the memory to replace with all 0
*/
void secure_free(void* ptr, size_t size);

/**
* @brief This function convert the numeric value of an AF to a string 
* @param[in] af Value of the AF to print
*/
const char* address_family_to_string(int af);

/**
* @brief This function convert the numeric value of a Next Payload field of a header in to a string 
* @param[in] type Value of the Next Payload to print
*/
const char* next_payload_to_string(NextPayload type);

#endif