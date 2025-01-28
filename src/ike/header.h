#ifndef HEADER_BUILDER_H
#define HEADER_BUILDER_H

#include <stdint.h>
#include <stddef.h>
#include "constant.h"
#include "../common_include.h"

#define IKE_HEADER_DIM sizeof(ike_header_t)

/*#######################################################
IKE Header Struct
#######################################################*/
typedef struct {
    uint64_t initiator_spi;   
    uint64_t responder_spi;  
    uint8_t next_payload; 
    uint8_t version;        
    uint8_t exchange_type; 
    uint8_t flags;        
    uint32_t message_id;  
    uint32_t length;     
} __attribute__((packed)) ike_header_t;

typedef struct {
    uint8_t  next_payload;  
    uint8_t  critical :1;  
    uint8_t  reserved :7;
    uint16_t length;        
} __attribute__((packed)) ike_payload_header_t;

ike_header_t init_header();
void print_header(ike_header_t* hd);

ike_header_t* parse_header(uint8_t* buffer, size_t size);
//void parse_header(ike_header_t *header, uint8_t* buffer, size_t* buffer_len);

#endif