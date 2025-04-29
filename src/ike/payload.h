#ifndef PAYLOAD_H
#define PAYLOAD_H

#include "../common_include.h"
#include "../crypto/crypto.h"
#include "constant.h"
#include "header.h"
#include <stddef.h>
#include <stdint.h>

/*
########################################################################################################
Structures representing protocol payloads
All are in binary format so that it can be sent on the buffer without having to perform conversions
########################################################################################################
*/

/**
* @brief  
*/
typedef  struct {
    uint8_t id_type;
    uint8_t RESERVED1;
    uint16_t RESERVED2;
} __attribute__((packed)) ike_id_payload_t ;
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

/** 
* @brief ADD DESCRIPTION
*/
typedef struct {
    uint8_t data[NONCE_LEN];
} ike_nonce_payload_t;
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

/** 
* @brief ADD DESCRIPTION
*/
typedef struct {
    uint8_t type[2];
    uint8_t value[2];
} __attribute__((packed)) ike_transofrm_attr_t;

/** 
* @brief ADD DESCRIPTION
*/
typedef struct {
    uint8_t last; 
    uint8_t reserved;
    uint8_t length[2]; 
    uint8_t type;
    uint8_t reserved2;
    uint8_t id[2];
} __attribute__((packed)) ike_transofrm_t;
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
    ike_transofrm_t transform;
    ike_transofrm_attr_t attribute;
} __attribute__((packed)) ike_transofrm_with_attr_t;


/** 
* @brief ADD DESCRIPTION
*/
typedef struct {
    uint8_t last; 
    uint8_t reserved;
    uint8_t length[2]; 
    uint8_t number; //identificativo per determinare quale proposal è stata scelta dal peer
    uint8_t protocol; //id del protocollo per cui vale la proposal
    uint8_t spi_size; //per l'init SA deve essere valorizzato a 0 poi in quelli successivi deve essere pari alla lunghezza dello spi del protocol id 
    uint8_t num_transforms; 
    ike_transofrm_with_attr_t enc;
    ike_transofrm_t kex;
    ike_transofrm_t aut;
    ike_transofrm_t prf;
} __attribute__((packed)) ike_proposal_payload_t;
/*
1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| 0 (last) or 2 |   RESERVED    |         Proposal Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~                        SPI (variable)                         ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                        <Transforms>                           ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


/** 
* @brief ADD DESCRIPTION
*/
typedef struct {
    uint16_t dh_group;
    uint16_t reserved;
    uint8_t ke_data[32]; 
} __attribute__((packed)) ike_payload_kex_t;
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
    MessageComponent type; 
    ike_payload_header_t hdr;
    void* body; // qui usiamo const poichè passiamo il riferimento alla struct che compone il body senza doverla copiare, il const ci garantisce che non viene modificata.
    size_t len;
} ike_payload_t;


int build_proposal(ike_proposal_payload_t* proposal, cipher_suite_t* suite);

int build_payload(ike_payload_t* payload, MessageComponent type, void *body, size_t len);


#endif