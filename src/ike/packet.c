#include "packet.h"
#include "constant.h"
#include "header.h"
#include "ike.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>


void parse_response(uint8_t* req, uint8_t* res, ike_partecipant_t* right){

    ike_header_raw_t req_hdr = {0};
    ike_header_raw_t res_hdr = {0};
    parse_header_raw(res, &res_hdr);
    parse_header_raw(req, &req_hdr);
    
    bool is_exchange = verify_exchange(&req_hdr, &res_hdr);
    if (!is_exchange) {
        printf("Errore la risposta non è formattata correttamente");
        return;
    }
    
    memcpy(right->ctx.spi, res_hdr.responder_spi, SPI_LENGTH_BYTE);
    right->role = IKE_RESPONDER;
    
    uint8_t current_payload = res_hdr.next_payload;

    //subito dopo l'header abbiamo il primo next payload
    uint8_t next_payload = res[IKE_HDR_DIM];         
    res += IKE_HDR_DIM;

    while (next_payload != 0){

        current_payload = next_payload;
        ike_payload_header_t *payload = (ike_payload_header_t *)res;
        
        switch (current_payload) {
            case NEXT_PAYLOAD_KE: {
                break;
            };
            case NEXT_PAYLOAD_NONCE: {
                break;
            };
            case NEXT_PAYLOAD_SA: {
                break;
            }
        }
        //aggiornare il puntatore

   
    }

}