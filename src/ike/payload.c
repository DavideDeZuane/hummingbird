#include "../log/log.h"
#include "payload.h"
#include "constant.h"
#include "header.h"
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../crypto/crypto.h"
#include "../utils/utils.h"

int build_transform(void* tran, algo_t* alg){
    
    switch(alg->type){
        case ALGO_TYPE_ENCRYPTION: {
            ike_transofrm_with_attr_t* tmp = (ike_transofrm_with_attr_t *) tran;

            tmp->transform.last = LAST;
            tmp->transform.type = alg->type;
            uint16_to_bytes_be(alg->iana_code, tmp->transform.id);
            uint16_to_bytes_be(sizeof(ike_transofrm_with_attr_t), tmp->transform.length);


            uint16_to_bytes_be(KEY_LEN_ATTRIBUTE, tmp->attribute.type);
            uint16_to_bytes_be(alg->key_len, tmp->attribute.value);
            break;
        };
        case ALGO_TYPE_PRF: 
        case ALGO_TYPE_KEX: 
        case ALGO_TYPE_AUTH:{ 
            ike_transofrm_t *tmp = (ike_transofrm_t *) tran;
            tmp->last = LAST;
            tmp->type = alg->type;
            uint16_to_bytes_be(alg->iana_code, tmp->id);
            uint16_to_bytes_be(sizeof(ike_transofrm_t), tmp->length);
            break;
        };
        case ALGO_TYPE_UNKNOWN: {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;

}

int build_proposal(ike_proposal_payload_t* proposal, cipher_suite_t* suite){

    proposal->protocol = PROTOCOL_ID_IKE;
    proposal->num_transforms = NUM_TRANSFORM;
    proposal->last = LAST;
    proposal->number = 1;
    proposal->spi_size = 0;

    build_transform(&proposal->aut, &suite->auth);
    build_transform(&proposal->prf, &suite->prf);
    build_transform(&proposal->enc, &suite->enc);
    build_transform(&proposal->kex, &suite->kex);

    uint16_to_bytes_be(sizeof(ike_proposal_payload_t), proposal->length);

    return EXIT_SUCCESS;

}

/**
* This function serialized the content of the payload in a buffer
*/
int build_payload(ike_payload_t* payload, MessageComponent type, void* body, size_t len){

    switch (type) {
        case PAYLOAD_TYPE_NONCE: {
            // popolo il campo body 
            // in questo caso non devo fare niente dato che 
            payload->type = type;
            payload->len = len;
            payload->body = body;
            //popolo il campo hdr
            build_payload_header(&payload->hdr, NEXT_PAYLOAD_NONE, len);
            break;
        };
        case PAYLOAD_TYPE_KE: {
            payload->type = type;
        };
        case PAYLOAD_TYPE_SA: {
            cipher_suite_t* tmp = (cipher_suite_t *) body;
            payload->body = calloc(sizeof(ike_proposal_payload_t), BYTE);
            build_proposal((ike_proposal_payload_t *) payload->body, tmp);
            dump_memory(payload->body, sizeof(ike_proposal_payload_t));



        };
        default: {

        }
    }

    return EXIT_SUCCESS;

}
