#include "common_include.h" // IWYU pragma: keep
#include <endian.h>
#include <ini.h>
#include "./config/config.h"
#include "./socket/peer.h"
#include "./log/log.h"
#include "./ike/header.h"
#include "crypto/crypto.h"
#include "ike/constant.h"
#include "./ike/header.h"
#include "ike/ike.h"
#include "ike/payload.h"
#include "utils/utils.h"

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//QUESTO INSIEME ALLA PARTE DI SEND E RECEVE DEVE ANDARE NELLA PARTE DI NETWORK 
#define MAX_PAYLOAD 1444
#define SHA1_DIGEST_LENGTH 20
#define NUM_KEYS 7
//spostare questo nel modulo packet, questa è quella parte che si occupa di creare il messaggio e il creeate message ritorna il buffer che poi verrò inviato tramite socket sulla rete 

typedef struct {
    void *next; // Puntatore generico al prossimo payload
    void *prev; // Puntatore generico al precedente payload
    void *data;                  // Puntatore generico ai dati del payload
    size_t length;
    MessageComponent type; 
} ike_message_component_t;

typedef struct {
    ike_message_component_t *head;
    ike_message_component_t *tail;
} ike_message_t;

void push_component(ike_message_t* list, MessageComponent type, void *data, size_t length){

    ike_message_component_t* new = malloc(sizeof(ike_message_component_t));
    if (new == NULL) printf("Error during malloc\n");
    
    new->prev = NULL; //dato che faccio il prepend l'elemento che aggiungo diventa il primo e quindi lo posso lasciare qui
    new->data = data;
    new->length = length;
    new->type = type;
    
    if(list->head == NULL){
        list->head = new;
        list->tail = new;
        return;
    }
    new->next = list->head;
    list->head->prev = new;
    list->head = new;
}

uint8_t* create_message(ike_message_t* list, size_t* len){

    size_t buffer_len = 0;
    size_t offset = 0;

    uint8_t* buffer = NULL;
    ike_message_component_t* scan = list->tail;

    while(scan != NULL){
        buffer_len += scan->length;
        buffer = realloc(buffer, buffer_len);
        offset += scan->length;
        //una volta allocato il buffer prima di scriverci sopra facciamo la conversione in big endian di quello che ci vogliamo scrivere
        if (buffer_len > scan->length) memmove(buffer + scan->length, buffer, buffer_len - scan->length);

        if(scan->type == GENERIC_PAYLOAD_HEADER) {
            //se il componente che andiamo a considerare è quello del generic payload allora vuol dire che il componente che lo precedeva 
            //ha questo come header e quindi dato che ci server conoscere la sua lunhgezza utilizziamo il campo offset per determinare la dimensione del 
            //payload precedente in modo da non dover scrivere a mano la lunghezza. Una volta aggiornato il compo del generic header resettiamo l'offset
            //dato che passiamo al prossimo payload
            ike_payload_header_t* hd = (ike_payload_header_t*) scan->data;
            hd->length = htobe16(offset);
            offset = 0;
        }
        if(scan->type == IKE_HEADER){
            ike_header_t * hdr = (ike_header_t *) scan->data;
            hdr->length = htobe32(buffer_len) ;
        }

        memcpy(buffer, scan->data, scan->length);
        scan = scan->prev;
    }

    *len = buffer_len;
    return buffer;



}

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char* argv[]){
    /*---------------------------------------------
    Command Line arguments
    ---------------------------------------------*/
    int opts;
    struct option long_opts[] = {
        {"version", no_argument, 0, 'v'},
        {"config", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0} // Terminatore
    };
    while((opts = getopt_long(argc, argv, "hvc", long_opts, NULL)) != -1){
        switch (opts) {
            case 'h': {
                printf("Usage of the command");
                return EXIT_SUCCESS;
            };
            case 'v': {
                printf("Version number..");
                return EXIT_SUCCESS;
            };
            case 'c': {
                char *cwd;
                cwd = getcwd(NULL, 0);
                cwd = realloc(cwd, strlen(cwd)+2);
                strcat(cwd, "/");
                printf("Path of the configuration file: %s%s\n", cwd, DEFAULT_CONFIG);
                return EXIT_SUCCESS;
            }
        
        }
    }  
    /*--------------------------------------------
    Loading configuration file
    --------------------------------------------*/
    config cfg = init_config();
    log_set_level(LOG_INFO);
    int n;
    if ((n = ini_parse(DEFAULT_CONFIG, handler, &cfg)) < 0) {
        printf("Can't load %s\n", DEFAULT_CONFIG);
        log_error("Error on opening the configuration file %s\n", DEFAULT_CONFIG);
        return 1;
    }
    log_info("Configuration file %s loaded successfully", COLOR_TEXT(ANSI_COLOR_YELLOW,DEFAULT_CONFIG));
    /*
    endpoint local = {0};
    endpoint remote  = {0};
    partecipants_ini(&local, &remote, &cfg.peer);
    */
    /*
    *********************************************
    Setting initiator
    ********************************************* 
    */

    ike_partecipant_t left = {0};
    ike_partecipant_t rigth = {0};
    initiate_ike(&left, &rigth);



    ike_initiator initiator = {0};
    ike_responder responder = {0};
    responder_ini(&responder, &cfg.peer);
    initiator_ini(&initiator, &responder);
    //in questo modo facciamo si che il destinatario sia associato al socket, in questo modo possiamo usare direttamente la recv e la send 
    //inoltre  il socket rifiuterà di inviare e ricevere dati da qualsiasi altro indirizzo o porta (il socket è legato al server specifico)
    if (connect(initiator.sockfd, (struct sockaddr *)&responder.sk, sizeof(responder.sk)) < 0) {
        perror("connect failed");
        close(initiator.sockfd);
        return EXIT_FAILURE;
    } 

    ike_message_t packet_list = {NULL, NULL};
    ike_header_t header = init_header();
    header.next_payload = NEXT_PAYLOAD_SA;
    ike_payload_header_t pd = {0};
    pd.next_payload = NEXT_PAYLOAD_NONCE;
    ike_payload_kex_t kd = {0};
    kd.dh_group = htobe16(31);


    memcpy(&kd.ke_data, left.ctx.public_key, 32);
    memcpy(&header.initiator_spi, &left.ctx.spi, 8);

    ike_payload_header_t np = {0};
    np.next_payload = NEXT_PAYLOAD_NONE;

    ike_payload_proposal_t proposal = create_proposal();
    ike_payload_header_t header_1 = {0} ;
    header_1.next_payload = NEXT_PAYLOAD_KE;

    push_component(&packet_list, PAYLOAD_TYPE_NONCE,        left.ctx.nonce,      left.ctx.nonce_len);
    push_component(&packet_list, GENERIC_PAYLOAD_HEADER,    &np,        sizeof(ike_payload_header_t));
    push_component(&packet_list, PAYLOAD_TYPE_KE,           &kd,        sizeof(ike_payload_kex_t));
    push_component(&packet_list, GENERIC_PAYLOAD_HEADER,    &pd,        sizeof(ike_payload_header_t));
    push_component(&packet_list, PAYLOAD_TYPE_SA,           &proposal,  sizeof(ike_payload_proposal_t));
    push_component(&packet_list, GENERIC_PAYLOAD_HEADER,    &header_1,  sizeof(ike_payload_header_t));
    push_component(&packet_list, IKE_HEADER,                &header,    sizeof(ike_header_t));
    
    uint8_t* buff;
    size_t len = 0;
    
    buff = create_message(&packet_list, &len);

    dump_memory(buff, len);

    //memcpy(buff, &header, sizeof(ike_header_t));
    //memcpy(buff+sizeof(ike_payload_header_t)+8, &sa_payload, sizeof(ike_payload_proposal));

    int retval =  send(initiator.sockfd, buff, len, 0);
    if(retval == -1){
        printf("Errore per la send");
        return -1;
    }
    //il free non azzera il contenuto dice solamente che la memoria ora è disponibile, quindi la rilascia al sistema operativo
    free(buff);

    //la gestione della recv e del caso in cui il timeout scade va gestita nella parte network
    uint8_t* buffer = calloc(MAX_PAYLOAD, sizeof(uint8_t));
    printf("Waiting...\n");
    n = recv(initiator.sockfd, buffer, MAX_PAYLOAD, 0);
    if (n < 0) {
        if (errno == EAGAIN ) {
            printf("Timeout scaduto: nessun dato ricevuto entro 1 secondo.\n");
        } else {
            perror("Errore durante la ricezione");
            return EXIT_FAILURE;
        }
    } 
    printf("Byte Ricevuti dal responder %d\n", n);
    buffer = realloc(buffer, n);
    buffer[n] = '\0'; 

    //qunado vado a fare il parsing dei vari elementi vorrei fare in modo di confrontare il payload dal buffer per aggiornare quello che ho inviato io 
    ike_header_t* hd = parse_header(buffer, n);
    
    //porcodio
    responder.sa.spi = hd->responder_spi;
    // funzione che fa il parsing, quello che fa è prendere la strucct del responder e il buffer che poi utilizzeremo per pooplarla
    //CONVERT THIS PIECE OF CODE UNTIL THE END TO A FUNCTION
    uint8_t *ptr = buffer+28; 
    uint8_t next_payload = ptr[0];         
    uint8_t current_payload = hd->next_payload;

    while (next_payload != 0){
        current_payload = next_payload;
        //printf("Il payload corrente è %s\n", next_payload_to_string(current_payload));
        ike_payload_header_t *payload = (ike_payload_header_t *)ptr;

        if(current_payload == NEXT_PAYLOAD_KE){
            responder.sa.key_len = 32;
            responder.sa.key = malloc(responder.sa.key_len);
            memcpy(responder.sa.key, ptr+8, responder.sa.key_len);
        }
        
        if(current_payload == NEXT_PAYLOAD_NONCE){
            //printf("sono al payload nonce\n");
            responder.sa.nonce_len = be16toh(payload->length) -4;
            responder.sa.nonce = malloc(responder.sa.nonce_len);
            memcpy(responder.sa.nonce, ptr+4, 32);
        }

        //printf("Next payload di tipo %s, tra %d byte\n", next_payload_to_string(payload->next_payload), be16toh(payload->length));
        next_payload = payload->next_payload;
        ptr += be16toh(payload->length);
    }
    //END

    //ora ho ottenuto il key material adesso vediamo se riesco a derivare il segreto condiviso corretto

    //THIS EXCHANGE IS NECESSARY BECAUSE STRONGSWAN USE COOKIE AS DDOS PREVENTION
    //SO BEFORE GENERATING THE SKEYSEED AND OTHER THINGS HE WAIT THE IKE_AUTH_INIT 
    hd->exchange_type = EXCHANGE_IKE_AUTH;
    hd->message_id = htobe32(1);
    uint8_t flags[] = {FLAG_I, 0};
    set_flags(hd, flags);
    memset(buff, 0, len);
    memcpy(buff, hd, 28);
    retval =  send(initiator.sockfd, buff, len, 0);
    //END - THIS PIECE OF CODE GENERATE THE IKE AUTH MOCK



    
    // THIS IS THE PIECE OF CODE TO GENERATE THE SHARED SECRET 
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, responder.sa.key, responder.sa.key_len);
    if (!peer) handleErrors();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(left.ctx.private_key, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer) <= 0){
        handleErrors();
    }
    // Ottenere la dimensione del segreto condiviso
    size_t secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0)
        handleErrors();
    // Derivare il segreto condiviso
    unsigned char shared_secret[secret_len];
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0)
        handleErrors();
    // Stampa del segreto condiviso
    printf("Segreto condiviso: \n");
    for (size_t i = 0; i < secret_len; i++)
        printf("%02X", shared_secret[i]);
    printf("\n");
    // Pulizia
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    // AT THE HAND WE HAVE THE SHARED SECRET





    //concateno i nonce 
    uint8_t* wa = malloc(32+32);
    memcpy(wa, left.ctx.nonce, 32);
    mempcpy(wa+32, responder.sa.nonce, responder.sa.nonce_len);

    uint8_t skeyseed[20];  // Buffer di output (max 20 byte per SHA-1)
    unsigned int skeyseed_len = 0;

    //with the notation prf(Ni|Nr, g^ir) the first argument is the key, the second the data
    //spostare questa funzione nella sezione crypto e chiamarla anche prf
    HMAC(EVP_sha1(), wa, 32+32, shared_secret, 32, skeyseed,  &skeyseed_len);


    printf("SKEYSEED: ");
    for (size_t i = 0; i < skeyseed_len; i++)
        printf("%02X", skeyseed[i]);
    printf("\n");
    
    wa = realloc(wa, 32+32+8+8);
    memcpy(wa+64, &left.ctx.spi, 8);
    memcpy(wa+72, &responder.sa.spi, 8);


    uint8_t *data = calloc(81, 1);
    size_t data_len = 81;
    memcpy(data, wa, 80);
    data[80] = 0x01;

    unsigned int output_len = 20;
    uint8_t *output = calloc(SHA1_DIGEST_LENGTH, 1);
    HMAC(EVP_sha1(), skeyseed, skeyseed_len, data, data_len, output, &output_len );
    printf("T1 \n");
    dump_memory(output, SHA1_DIGEST_LENGTH);

    dump_memory(data, data_len);

    //il +1 non ci va basta aggiornare il valore del contatore, dunque quello che facciamo è spostare tutto della dimensione del digest
    //spostare quello che c'era prima e cambiare l'ultimo bit che è quello del contatore
    data_len += SHA1_DIGEST_LENGTH;

    data = realloc(data, data_len);
    memmove(data +20, data, data_len-20);
    memcpy(data, output, output_len);
    data[data_len-1] = 0x02; //aggiorniamo il contatore 
    HMAC(EVP_sha1(), skeyseed, skeyseed_len, data, data_len, output, &output_len );
    
    printf("T2 \n");
    dump_memory(output, SHA1_DIGEST_LENGTH);

    dump_memory(data, data_len);
    
    memcpy(data, output, output_len);
    data[data_len-1] = 0x03; //aggiorniamo il contatore 
    HMAC(EVP_sha1(), skeyseed, skeyseed_len, data, data_len, output, &output_len );

    printf("T3 \n");
    dump_memory(output, SHA1_DIGEST_LENGTH);
    return 0;
}
