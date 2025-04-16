#ifndef PAYLOAD_H
#define PAYLOAD_H

#include "../common_include.h"
#include "header.h"

/*
1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Payload  |C|  RESERVED   |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ID Type     |                 RESERVED                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                   Identification Data                         ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef  struct {
    uint8_t id_type;
    uint8_t RESERVED1;
    uint16_t RESERVED2;
} __attribute__((packed)) ike_identification_payload_t ;



typedef struct {
    uint16_t type;
    uint16_t value;
} __attribute__((packed)) ike_transofrm_attribute_t;

typedef struct {
    uint8_t last; //specifica se ci sono altre transofrm dopo questa 0 indica che non ce ne sono io 3 indica che ce ne sono ancora
    uint8_t reserved;
    uint16_t length; 
    uint8_t type;
    uint8_t reserved2;
    uint16_t id;
    //aggiungo un puntatore ad attribute se questo è valorizzato allora significa che è presente un attributo, se invece punta a null allora vuol dire che non è presente
    //ike_transofrm_attribute_t* attribute;
} __attribute__((packed)) ike_transofrm_t;

//un altro modo per fare questa sruct è utilizzare un puntatore opzionale 
typedef struct {
    ike_transofrm_t transform;
    ike_transofrm_attribute_t attribute;
} __attribute__((packed)) ike_transofrm_with_attribute_t;

typedef struct {
    uint8_t last; //dato che definisce quante proposal ci sono nel caso di minimal ike è 1 quindi viene sempre valorizzato a 0
    uint8_t reserved;
    uint16_t length; 
    uint8_t number; //identificativo per determinare quale proposal è stata scelta dal peer
    uint8_t protocol; //id del protocollo per cui vale la proposal
    uint8_t spi_size; //per l'init SA deve essere valorizzato a 0 poi in quelli successivi deve essere pari alla lunghezza dello spi del protocol id 
    uint8_t num_transforms; //numero di trasformazioni presenti nella proposal 
    //a questo punto segue il numero di trasformazioni
    ike_transofrm_with_attribute_t enc;
    ike_transofrm_t kex;
    ike_transofrm_t aut;
    ike_transofrm_t prf;
} __attribute__((packed)) ike_payload_proposal_t;

typedef struct {
    uint16_t dh_group;
    uint16_t reserved;
    uint8_t ke_data[32]; //contiene la chiave pubblica generata
} __attribute__((packed)) ike_payload_kex_t;



ike_payload_proposal_t create_proposal();

#endif