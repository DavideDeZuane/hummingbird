#include "../../include/ike/header.h"
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include "../../include/utils.h"


// DIMENION IN BYTE OF THE FIELDS OF THE IKE HEADER
#define SPI_LENGTH_BYTE     8
#define NEXT_PAYLOAD_BYTE   1
#define VERSION_BYTE        1
#define EXCHANGE_TYPE_BYTE  1
#define FLAGS_BYTE          1
#define MESSAGE_ID_BYTE     4
#define LENGTH_BYTE         4

#define BUFFER_SIZE (SPI_LENGTH_BYTE * 2 + NEXT_PAYLOAD_BYTE + VERSION_BYTE + EXCHANGE_TYPE_BYTE + FLAGS_BYTE + MESSAGE_ID_BYTE + LENGTH_BYTE)

#define UPDATE_BINARY_FIELD(hdr, buffer, offset, field_size)                            \
    memcpy((uint8_t*)(hdr) + (offset), (uint8_t*)(buffer) + (offset), (field_size));    \
    (offset) += (field_size);                                                           \
\

void set_flags(ike_header_t* hd, uint8_t flags[]){
    hd->flags = 0; 
    for (size_t i = 0; flags[i] != 0; i++){
        hd->flags |= flags[i]; 
    } 
}

bool compare_spi(uint8_t* spi1, uint8_t* spi2) {
    for (size_t i = 0; i < SPI_LENGTH_BYTE; i++) {
        if (spi1[i] != spi2[i]) {
            return false;  
        }
    }
    return true;  
}




ike_header_t init_header(){
    uint8_t flag, version = 0;
    uint8_t flags[] = { FLAG_I };
    for (size_t i = 0; i < sizeof(flags)/sizeof(flags[0]); ++i) {
        flag |= flags[i]; 
    } 
    version |= IKEV2;
   
    //qui va modificato, per fare l'init dell'header dobbiamo passargli il ressponder
    ike_header_t header = {
        SPI_NULL,
        SPI_NULL,
        NEXT_PAYLOAD_SA,
        version,
        EXCHANGE_IKE_SA_INIT,
        flag,
        MID_NULL,
        sizeof(ike_header_t)
    };

    //convert_to_big_endian(&header, IKE_HEADER);
    
    return header;
}

ike_header_raw_t init_header_raw(uint8_t* spi, uint32_t len){
    uint8_t flag, version = 0;
    uint8_t flags[] = { FLAG_I };
    for (size_t i = 0; i < sizeof(flags)/sizeof(flags[0]); ++i) {
        flag |= flags[i]; 
    } 
    version |= IKEV2;
   
    ike_header_raw_t header = {0};
    memcpy(header.initiator_spi, spi, SPI_LENGTH_BYTE);
    memset(header.responder_spi, 0, SPI_LENGTH_BYTE);
    memset(header.message_id,    0, MESSAGE_ID_BYTE);
    header.next_payload = NEXT_PAYLOAD_SA;
    header.exchange_type = EXCHANGE_IKE_SA_INIT;
    header.version = version;
    header.flags = flag;
    uint32_to_bytes_be(len, header.length);

    return header;
}

/**
* @brief This function extracts the header from the response buffer.
* @param[in] buffer Is the buffer that contains the response from the responder
*/
int parse_header_raw(uint8_t* buffer, ike_header_raw_t* hdr){

    int offset = 0;
        
    if(hdr == NULL){
        printf("Pointer null exception");
    }
    UPDATE_BINARY_FIELD(hdr, buffer, offset, SPI_LENGTH_BYTE);
    UPDATE_BINARY_FIELD(hdr, buffer, offset, SPI_LENGTH_BYTE);
    UPDATE_BINARY_FIELD(hdr, buffer, offset, NEXT_PAYLOAD_BYTE);
    UPDATE_BINARY_FIELD(hdr, buffer, offset, VERSION_BYTE);
    UPDATE_BINARY_FIELD(hdr, buffer, offset, EXCHANGE_TYPE_BYTE);
    UPDATE_BINARY_FIELD(hdr, buffer, offset, FLAGS_BYTE);
    UPDATE_BINARY_FIELD(hdr, buffer, offset, MESSAGE_ID_BYTE);
    UPDATE_BINARY_FIELD(hdr, buffer, offset, LENGTH_BYTE);

    return EXIT_SUCCESS;

}

bool verify_exchange(const ike_header_raw_t *req, const ike_header_raw_t *res){

    if (memcmp(req->initiator_spi, res->initiator_spi, SPI_LENGTH_BYTE) != 0) return false;
    if (memcmp(req->message_id, res->message_id, MESSAGE_ID_BYTE) != 0) return false;
    if (req->version != res->version) return false;
    if (req->exchange_type != res->exchange_type) return false;
    if (req->flags & 0x40) return false; 

    return true;
}



ike_header_t* parse_header(uint8_t* buffer, size_t size){
    
    ike_header_t * hd = malloc(sizeof(ike_header_t));
    hd->initiator_spi = *(uint64_t*)&buffer[0]; 
    hd->responder_spi = *(uint64_t*)&buffer[8];  
    hd->next_payload = buffer[16];
    hd->version = buffer[17];                  
    hd->exchange_type = buffer[18];             
    hd->flags = buffer[19];                      
    hd->message_id = *(uint32_t*)&buffer[20];   
    hd->length = *(uint32_t*)&buffer[24];  

    return hd;

}

int build_header(ike_header_raw_t *hdr, size_t len);


int build_payload_header(ike_payload_header_raw_t* hdr, NextPayload np, uint16_t len){
    if(hdr == NULL){
        return EXIT_FAILURE;
    }

    hdr->next_payload = np;
    uint16_to_bytes_be(len, hdr->length);

    return EXIT_SUCCESS;
    
}