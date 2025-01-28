#ifndef IKE_ALIASES_H
#define IKE_ALIASES_H

#define MID_NULL 0x00000000
#define SPI_NULL 0x0000000000000000 //valore speciale del campo che indica che l'initiator non conosce l'SPI del responder
#define SPI_LENGTH 64

/*#######################################################
Flag, sono le maschere binarie per settare i flag
#######################################################*/
#define FLAG_R 0x20  // Bit R (0010 0000 in binario)
#define FLAG_V 0x10  // Bit V (0001 0000 in binario)
#define FLAG_I 0x08  // Bit I (0000 1000 in binario)

#define LAST 0
#define MORE 3

#define IKEV2 0x20

/**
 * @brief Enum per rappresentare i tipi di protocollo.
 *
 * Questo enum definisce i diversi ID dei protocolli da utilizzare
 * in fase in cui occorre specificare la proposal a che protocollo server. 
 *
 */
typedef enum {
    PROTOCOL_ID_IKE = 1,
    PROTOCOL_ID_AH  = 2,
    PROTOCOL_ID_ESP = 3
} ProtocolType;

/**
 * @brief Enum per rappresentare i tipi di trasformazioni.
 * 
 * Specifica il tipo di trasformazione che si sta proponendo.
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

#endif
