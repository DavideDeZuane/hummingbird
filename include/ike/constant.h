#ifndef IKE_ALIASES_H
#define IKE_ALIASES_H

#include "../common.h"

#define BYTE 1

#define NONCE_LEN 32 

#define INIT_MSG_COMPONENT 4

#define MID_NULL 0x00000000
#define SPI_NULL 0x0000000000000000 //valore speciale del campo che indica che l'initiator non conosce l'SPI del responder

#define MID_LENGTH_BYTE 4
#define SPI_LENGTH 64
#define SPI_LENGTH_BYTE 8
#define HDR_LENGTH_BYTE 4
#define GEN_HDR_LENGTH_BYTE 2

/*#######################################################
Flag, sono le maschere binarie per settare i flag
#######################################################*/
#define FLAG_R 0x20  // Bit R (0010 0000 in binario)
#define FLAG_V 0x10  // Bit V (0001 0000 in binario)
#define FLAG_I 0x08  // Bit I (0000 1000 in binario)

#define LAST 0
#define MORE 3
#define NUM_TRANSFORM 4
#define KEY_LEN_ATTRIBUTE 0x800E

#define IKEV2 0x20

/**
 * @brief Enum with the type of the protocol for the Transform Payload
 */
typedef enum {
    PROTOCOL_ID_IKE = 1,
    PROTOCOL_ID_AH  = 2,
    PROTOCOL_ID_ESP = 3
} ProtocolType;

typedef enum {
    PAYLOAD_TYPE_NONE,
    PAYLOAD_TYPE_NONCE,
    PAYLOAD_TYPE_KE,
    PAYLOAD_TYPE_SA,
    PAYLOAD_TYPE_ID,
    GENERIC_PAYLOAD_HEADER,
    IKE_HEADER,
    TRANSFORM,
} MessageComponent;

/**
 * @brief Enum for the transformation type in the proposal
 *
 */
typedef enum {
    TRANSFORM_TYPE_ENCR = 1,
    TRANSFORM_TYPE_PRF  = 2,
    TRANSFROM_TYPE_AUTH = 3,
    TRANSFORM_TYPE_DHG  = 4,
    TRANSFORM_TYPE_ESN  = 5 
} TransformType;

/**
 * @brief Enum per rappresentare le varie tipologie dei payload.
 *
 * Questa enumerazione definisce i diversi ID dei tipi di payload che
 * vannno specificati nel generic header.
 */
typedef enum {
    NEXT_PAYLOAD_NONE    = 0,
    NEXT_PAYLOAD_SA      = 33,
    NEXT_PAYLOAD_KE      = 34,
    NEXT_PAYLOAD_IDi     = 35,
    NEXT_PAYLOAD_IDr     = 36,
    NEXT_PAYLOAD_CERT    = 37,
    NEXT_PAYLOAD_CERTREQ = 38,
    NEXT_PAYLOAD_AUTH    = 39,
    NEXT_PAYLOAD_Ni      = 40,
    NEXT_PAYLOAD_NONCE   = 40,
    NEXT_PAYLOAD_NOTIFIY = 41,
    NEXT_PAYLOAD_DELETE  = 42,
    NEXT_PAYLOAD_TSi     = 44,
    NEXT_PAYLOAD_TSr     = 45,
    NEXT_PAYLOAD_SK      = 46
} NextPayload;

/**
 * @brief Enum per rappresentare il tipo di exchange in atto
 *
 * Questa enumerazione definisce i diversi ID degli scambi che coinvolgono
 * initiator e responder, vanno a imporre quali payload dovranno essere inviati ad ogni scambio.
 */
typedef enum {
    EXCHANGE_IKE_SA_INIT     = 34,
    EXCHANGE_IKE_AUTH        = 35, 
    EXCHANGE_CREATE_CHILD_SA = 36,
    EXCHANGE_INFORMATIONAL   = 37   
} ExchangeType;


typedef enum {
    ID_TYPE_IPV4_ADDR        = 1,
    ID_TYPE_FQDN             = 2,  // Fully Qualified Domain Name
    ID_TYPE_RFC822_ADDR      = 3,  // Email address (e.g., user@example.com)
    ID_TYPE_IPV6_ADDR        = 5,
    ID_TYPE_DER_ASN1_DN      = 9,  // Distinguished Name (X.509)
    ID_TYPE_DER_ASN1_GN      = 10, // General Name (X.509)
    ID_TYPE_KEY_ID           = 11  // Opaque Key Identifier
} IDType;


/**
 * @brief This sctruct defines the information necessary to operate the conversion
 * in the big endian rappresentation 
 */
typedef struct {
    size_t offset;  
    int type;       
} field_descriptor_t;


#endif
