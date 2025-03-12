#include "header.h"
#include "constant.h"
#include <endian.h>
#include <stdint.h>
#include <sys/types.h>


void set_flags(ike_header_t* hd, uint8_t flags[]){
    hd->flags = 0; 
    for (size_t i = 0; flags[i] != 0; i++){
        hd->flags |= flags[i]; 
    } 
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