#include "../log/log.h"
#include "payload.h"
#include "constant.h"
#include "header.h"
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "../crypto/crypto.h"
#include "../utils/utils.h"

int build_transform(void* tran, algo_t* alg){
    
    switch(alg->type){
        case ALGO_TYPE_ENCRYPTION: {
            ike_transofrm_with_attribute_raw_t* tmp = (ike_transofrm_with_attribute_raw_t *) tran;

            tmp->transform.last = LAST;
            tmp->transform.type = alg->type;
            uint16_to_bytes_be(alg->iana_code, tmp->transform.id);
            uint16_to_bytes_be(sizeof(ike_transofrm_with_attribute_raw_t), tmp->transform.length);


            uint16_to_bytes_be(KEY_LEN_ATTRIBUTE, tmp->attribute.type);
            uint16_to_bytes_be(alg->key_len, tmp->attribute.value);
            break;
        };
        case ALGO_TYPE_PRF: 
        case ALGO_TYPE_KEX: 
        case ALGO_TYPE_AUTH:{ 
            ike_transofrm_raw_t *tmp = (ike_transofrm_raw_t *) tran;
            tmp->last = LAST;
            tmp->type = alg->type;
            uint16_to_bytes_be(alg->iana_code, tmp->id);
            uint16_to_bytes_be(sizeof(ike_transofrm_raw_t), tmp->length);
            break;
        };
        case ALGO_TYPE_UNKNOWN: {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;

}

int build_proposal(ike_payload_proposal_raw_t* proposal, cipher_suite_t* suite){

    proposal->protocol = PROTOCOL_ID_IKE;
    proposal->num_transforms = NUM_TRANSFORM;
    proposal->last = LAST;
    proposal->number = 1;
    proposal->spi_size = 0;

    build_transform(&proposal->aut, &suite->auth);
    build_transform(&proposal->prf, &suite->prf);
    build_transform(&proposal->enc, &suite->enc);
    build_transform(&proposal->kex, &suite->kex);

    uint16_to_bytes_be(sizeof(ike_payload_proposal_raw_t), proposal->length);

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
            ike_transofrm_raw_t tmp2 = {0};



        };
        default: {

        }
    }

    return EXIT_SUCCESS;

}

//trasformare questa in modo tale che accetti i parametri dalla configurazione
ike_payload_proposal_t create_proposal(){


    ike_payload_proposal_t proposal = {0};
    proposal.protocol = PROTOCOL_ID_IKE;
    proposal.spi_size = 0;
    proposal.num_transforms = 4;
    //questo numero è fondamentale e va messo fisso ad uno dato che quando facciamo ike minimal mandiamo solo una proposal, quindi:
    // fissiamo il numero della proposal ad uno 
    // e fissiamo last a 0 in modo da indicare che sarà un unica proposal
    proposal.last = 0; //last 
    proposal.number = 1;

    proposal.enc.transform.type = TRANSFORM_TYPE_ENCR;
    proposal.enc.transform.id = htobe16(12);
    proposal.enc.transform.last = LAST; //no ce ne sono ancora
    proposal.enc.attribute.value = 1;
    //questo lo settiamo a questo valore dato che il campo è 16 bit ma il primo bit deve essere pari a 1, seguito da lvalore 14 che è il valore dell'attributo chiave
    proposal.enc.attribute.type = htobe16(0x800E);
    proposal.enc.attribute.value = htobe16(128);
    proposal.enc.transform.length = htobe16(sizeof(ike_transofrm_with_attribute_t));

    proposal.kex.type = TRANSFORM_TYPE_DHG;
    proposal.kex.id = htobe16(31);
    proposal.kex.last = LAST; //no ce ne sono ancora
    proposal.kex.length = htobe16(sizeof(ike_transofrm_t));

    proposal.aut.type = TRANSFROM_TYPE_AUTH;
    proposal.aut.id = htobe16(2);
    proposal.aut.last = LAST; //no ce ne sono ancora
    proposal.aut.length = htobe16(sizeof(ike_transofrm_t));

    proposal.prf.type = TRANSFORM_TYPE_PRF;
    proposal.prf.id = htobe16(2);
    proposal.prf.last = LAST; //no ce ne sono ancora
    proposal.prf.length = htobe16(sizeof(ike_transofrm_t));

    proposal.length = htobe16(sizeof(ike_payload_proposal_t));

    return proposal;
}
