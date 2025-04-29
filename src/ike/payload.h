#ifndef PAYLOAD_H
#define PAYLOAD_H

#include "../common_include.h"
#include "../crypto/crypto.h"
#include "constant.h"
#include "header.h"
#include <stddef.h>
#include <stdint.h>


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

/*
                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Payload  |C|  RESERVED   |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                            Nonce Data                         ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct {
    uint8_t data[NONCE_LEN];
} nonce_payload_t;



typedef struct {
    uint16_t type;
    uint16_t value;
} __attribute__((packed)) ike_transofrm_attribute_t;

typedef struct {
    uint8_t type[2];
    uint8_t value[2];
} __attribute__((packed)) ike_transofrm_attribute_raw_t;
/*
                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| 0 (last) or 3 |   RESERVED    |        Transform Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Transform Type |   RESERVED    |          Transform ID         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                      Transform Attributes                     ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
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



typedef struct {
    uint8_t last; //specifica se ci sono altre transofrm dopo questa 0 indica che non ce ne sono io 3 indica che ce ne sono ancora
    uint8_t reserved;
    uint8_t length[2]; 
    uint8_t type;
    uint8_t reserved2;
    uint8_t id[2];
    //aggiungo un puntatore ad attribute se questo è valorizzato allora significa che è presente un attributo, se invece punta a null allora vuol dire che non è presente
    //ike_transofrm_attribute_t* attribute;
} __attribute__((packed)) ike_transofrm_raw_t;


typedef struct {
    ike_transofrm_t transform;
    ike_transofrm_attribute_t attribute;
} __attribute__((packed)) ike_transofrm_with_attribute_t;

//un altro modo per fare questa sruct è utilizzare un puntatore opzionale 
typedef struct {
    ike_transofrm_raw_t transform;
    ike_transofrm_attribute_raw_t attribute;
} __attribute__((packed)) ike_transofrm_with_attribute_raw_t;


typedef struct {
    uint8_t last; //dato che definisce quante proposal ci sono nel caso di minimal ike è 1 quindi viene sempre valorizzato a 0
    uint8_t reserved;
    uint8_t length[2]; 
    uint8_t number; //identificativo per determinare quale proposal è stata scelta dal peer
    uint8_t protocol; //id del protocollo per cui vale la proposal
    uint8_t spi_size; //per l'init SA deve essere valorizzato a 0 poi in quelli successivi deve essere pari alla lunghezza dello spi del protocol id 
    uint8_t num_transforms; //numero di trasformazioni presenti nella proposal 
    //a questo punto segue il numero di trasformazioni
    ike_transofrm_with_attribute_raw_t enc;
    ike_transofrm_raw_t kex;
    ike_transofrm_raw_t aut;
    ike_transofrm_raw_t prf;
} __attribute__((packed)) ike_payload_proposal_raw_t;


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


/*
                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Payload  |C|  RESERVED   |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Diffie-Hellman Group Num    |           RESERVED            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                       Key Exchange Data                       ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct {
    uint16_t dh_group;
    uint16_t reserved;
    uint8_t ke_data[32]; 
} __attribute__((packed)) ike_payload_kex_t;

typedef struct {
    MessageComponent type; 
    ike_payload_header_t hdr;
    const void* body; // qui usiamo const poichè passiamo il riferimento alla struct che compone il body senza doverla copiare, il const ci garantisce che non viene modificata.
    size_t len;
} ike_payload_t;


int build_proposal(ike_payload_proposal_raw_t* proposal, cipher_suite_t* suite);

int build_payload(ike_payload_t* payload, MessageComponent type, void *body, size_t len);

ike_payload_proposal_t create_proposal();

#endif