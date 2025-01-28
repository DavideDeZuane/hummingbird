#include "payload.h"
#include "constant.h"
#include <endian.h>


ike_payload_proposal create_proposal(){
    ike_payload_proposal proposal = {0};
    proposal.last = 0; //last 
    proposal.protocol = PROTOCOL_ID_IKE;
    proposal.spi_size = 0;
    proposal.num_transforms = 4;

    proposal.enc.transform.type = TRANSFORM_TYPE_ENCR;
    proposal.enc.transform.id = htobe16(12);
    proposal.enc.transform.last = MORE; //no ce ne sono ancora
    proposal.enc.attribute.value = 1;
    proposal.enc.attribute.type = 14;
    proposal.enc.attribute.value = 128;
    proposal.enc.transform.length = htobe16(sizeof(ike_transofrm_with_attribute_t));

    proposal.kex.type = TRANSFORM_TYPE_DHG;
    proposal.kex.type = htobe16(14);
    proposal.kex.last = MORE; //no ce ne sono ancora

    proposal.aut.type = TRANSFROM_TYPE_AUTH;
    proposal.aut.type = htobe16(2);
    proposal.aut.last = MORE; //no ce ne sono ancora

    proposal.prf.type = TRANSFORM_TYPE_DHG;
    proposal.prf.type = htobe16(2);
    proposal.prf.last = LAST; //no ce ne sono ancora

    proposal.length = sizeof(ike_payload_proposal);

    return proposal;
}