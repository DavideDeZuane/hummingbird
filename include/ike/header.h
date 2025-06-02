#ifndef HEADER_BUILDER_H
#define HEADER_BUILDER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "constant.h"
#include "../common.h"

#define IKE_HDR_DIM sizeof(ike_header_t)
#define GEN_HDR_DIM sizeof(ike_payload_header_t)

/* 
####################################################################
IKE HEADER
####################################################################
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IKE SA Initiator's SPI                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IKE SA Responder's SPI                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Message ID                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Length                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * @brief Struct that rapresent the format of the header  of a IKE Packet 
 * @note The attribute packed is necessary to avoid unwanted padding in the struct
 */
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
    uint8_t initiator_spi[SPI_LENGTH_BYTE];   
    uint8_t responder_spi[SPI_LENGTH_BYTE];  
    uint8_t next_payload; 
    uint8_t version;        
    uint8_t exchange_type; 
    uint8_t flags;        
    uint8_t message_id[MID_LENGTH_BYTE];  
    uint8_t length[HDR_LENGTH_BYTE];     
} __attribute__((packed)) ike_header_raw_t;


/* 
####################################################################
GENERIC PAYLOAD HEADER
####################################################################
                      1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * @brief Struct that rapresent the format of the generic header of a payload
 * @note The attribute packed is necessary to avoid unwanted padding in the struct
 */
typedef struct {
    uint8_t  next_payload;  
    uint8_t  critical :1;  
    uint8_t  reserved :7;
    uint16_t length;        
} __attribute__((packed)) ike_payload_header_t;


typedef struct {
    uint8_t next_payload;  
    uint8_t critical :1;  
    uint8_t reserved :7;
    uint8_t length[GEN_HDR_LENGTH_BYTE];        
} __attribute__((packed)) ike_payload_header_raw_t;


ike_header_t init_header();

int build_header(ike_header_raw_t* hdr, size_t len);

int build_payload_header(ike_payload_header_raw_t* hdr, NextPayload np, uint16_t len);

ike_header_t* parse_header(uint8_t* buffer, size_t size);

int parse_header_raw(uint8_t* buffer, ike_header_raw_t* hdr);

ike_header_raw_t init_header_raw(uint8_t* spi, uint32_t len);
/**
* @brief This function set the flags field of the IKE Message header
*/
void set_flags(ike_header_t* hd, uint8_t flags[]);

bool verify_exchange(const ike_header_raw_t *req, const ike_header_raw_t *res);

#endif