#ifndef HEADER_BUILDER_H
#define HEADER_BUILDER_H

#include <stdint.h>
#include <stddef.h>

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


//void parse_header(ike_header_t *header, uint8_t* buffer, size_t* buffer_len);

#endif