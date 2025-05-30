#include "../../include/ike/payload.h"
#include "../../include/ike/constant.h"
#include "../../include/ike/header.h"

#include <endian.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../../include/crypto.h"
#include "../../include/utils.h"

/**
 * @brief Builds a transform structure for an IKE proposal based on the algorithm type.
 * 
 * This function initializes the appropriate transform structure depending on the algorithm type 
 * For encryption algorithms, it includes an additional attribute field specifying the key length.
 * 
 * @param[out] tran Pointer to the memory where the transform structure will be written.
 *                 Its concrete type depends on the algorithm type:
 *                 - `ike_transofrm_with_attr_t*` for encryption (with key length attribute),
 *                 - `ike_transofrm_t*` for other algorithm types.
 * @param[in] alg Pointer to the algorithm specification containing type, IANA code, and key length.
 */
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

/**
 * @brief Builds an IKE proposal payload (SA) to be sent to the responder containing the cryptographic algorithms.
 * 
 * This function initializes the proposal payload with the required parameters,
 * including the protocol ID, the number of transforms, and the specific transforms
 * for authentication, PRF, encryption, and key exchange, based on the provided cipher suite.
 * 
 * @param[out] proposal Pointer to the proposal payload to be populated.
 * @param[in] suite Pointer to the cipher suite containing the algorithms to use.
 * 
 * @return int Returns EXIT_SUCCESS on success.
 */
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
 * @brief Builds the Key Exchange (KEX) payload for the IKE message.
 * 
 * This function sets the Diffie-Hellman group identifier in the payload,
 * retrieves the length of the raw public key, resizes the payload buffer accordingly,
 * and copies the raw public key data into the payload.
 * 
 * @param[in,out] ke Pointer to the KEX payload structure to be built. It will be reallocated to fit the key data.
 * @param[in] data Pointer to the cryptographic context containing the DH group and private key information.
 * 
 * @return int Returns EXIT_SUCCESS on success.
 */
int build_kex(ike_payload_kex_raw_t* ke, crypto_context_t* data){

    uint16_to_bytes_be(data->dh_group, ke->dh_group);
    // retrieve che public key len 
    EVP_PKEY_get_raw_public_key(data->private_key, NULL, &data->key_len);
    ke = realloc(ke, data->key_len + sizeof(ike_payload_kex_raw_t));

    EVP_PKEY_get_raw_public_key(data->private_key, ke->data, &data->key_len);
    return EXIT_SUCCESS;
}

/**
* @brief This function serialized the content of the payload in a buffer and create the generic payload header
*/
int build_payload(ike_payload_t* payload, MessageComponent type, void* body, size_t len){


    switch (type) {
        case PAYLOAD_TYPE_NONCE: {
            // popolo il campo body 
            // in questo caso non devo fare niente dato che 

            payload->type = type;
            payload->len = len + GEN_HDR_DIM;
            payload->body = body;

            //popolo il campo hdr e aggiungo qua la dimensione del generic payload header
            build_payload_header(&payload->hdr, NEXT_PAYLOAD_NONE, payload->len);
            break;
        };
        case PAYLOAD_TYPE_KE: {

            crypto_context_t* tmp = (crypto_context_t *) body;
            EVP_PKEY_get_raw_public_key(tmp->private_key, NULL, &tmp->key_len);

            payload->len = tmp->key_len + 4;
            payload->body = calloc(tmp->key_len + 4, BYTE);
            ike_payload_kex_raw_t* tmp2 = (ike_payload_kex_raw_t *) payload->body;
            uint16_to_bytes_be(tmp->dh_group, tmp2->dh_group);
            EVP_PKEY_get_raw_public_key(tmp->private_key, tmp2->data, &tmp->key_len);
            memset(&payload->hdr, 0, sizeof(ike_payload_kex_raw_t));

            build_payload_header(&payload->hdr, NEXT_PAYLOAD_NONCE, payload->len+ GEN_HDR_DIM);
            break;
        };
        case PAYLOAD_TYPE_SA: {
            cipher_suite_t* tmp = (cipher_suite_t *) body;
            payload->body = calloc(sizeof(ike_proposal_payload_t), BYTE);
            payload->len = len + GEN_HDR_DIM;
            build_proposal((ike_proposal_payload_t *) payload->body, tmp);
            build_payload_header(&payload->hdr, NEXT_PAYLOAD_KE, payload->len);

            break;
        };
        default: {

        }
    }

    return EXIT_SUCCESS;

}
