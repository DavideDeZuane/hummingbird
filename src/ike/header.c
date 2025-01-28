#include "header.h"
#include "constant.h"
#include "../crypto/crypto.h"
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

ike_header_t init_header(){
    uint8_t flag, version = 0;
    uint8_t flags[] = { FLAG_I };
    for (size_t i = 0; i < sizeof(flags)/sizeof(flags[0]); ++i) {
        flag |= flags[i]; 
    } 
    version |= IKEV2;
   
    ike_header_t header = {
        generate_spi(),
        SPI_NULL,
        NEXT_PAYLOAD_SA,
        version,
        EXCHANGE_IKE_SA_INIT,
        flag,
        MID_NULL,
        sizeof(ike_header_t)
    };
    return header;
}

void print_header(ike_header_t *hd){
    printf("Initiator SPI: 0x%llx\n", (long long unsigned int) htobe64(hd->initiator_spi));
    printf("Responder SPI: 0x%llx\n", (long long unsigned int) htobe64(hd->responder_spi));
}

ike_header_t* parse_header(uint8_t* buffer, size_t size){
    
    ike_header_t * hd = malloc(sizeof(ike_header_t));
    hd->initiator_spi = be64toh(*(uint64_t*)&buffer[0]); 
    hd->responder_spi = be64toh(*(uint64_t*)&buffer[8]);  
    hd->next_payload = buffer[16];
    hd->version = buffer[17];                  
    hd->exchange_type = buffer[18];             
    hd->flags = buffer[19];                      
    hd->message_id = be32toh(*(uint32_t*)&buffer[20]);   
    hd->length = be32toh(*(uint32_t*)&buffer[24]);  

    return hd;

}