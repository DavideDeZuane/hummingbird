#include "payload.h"
#include "constant.h"
#include <endian.h>



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