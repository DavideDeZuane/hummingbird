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

/*

#include <endian.h>

void parse_header(ike_header_t *hdr, uint8_t* buffer, size_t* buffer_len){
    hdr->initiator_spi = be64toh(*(uint64_t*)&buffer[0]); 
    hdr->responder_spi = be64toh(*(uint64_t*)&buffer[8]);  
    hdr->next_payload = buffer[16];
    hdr->version = buffer[17];                  
    hdr->exchange_type = buffer[18];             
    hdr->flags = buffer[19];                      
    hdr->message_id = ntohl(*(uint32_t*)&buffer[20]);   
    hdr->length = ntohl(*(uint32_t*)&buffer[24]);  
*/

#endif