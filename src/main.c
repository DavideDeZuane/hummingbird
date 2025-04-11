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
#include "network/network.h"
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
#include <sys/random.h>

//QUESTO INSIEME ALLA PARTE DI SEND E RECEVE DEVE ANDARE NELLA PARTE DI NETWORK 
// la specifica dice che deve gestire messaggi che hanno massimo questa dimensoine
#define MAX_PAYLOAD 1280
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

    
    ike_partecipant_t left = {0};
    ike_partecipant_t right = {0};
    
    initiate_ike(&left, &right, &cfg);

    ike_responder responder = {0};


    ike_message_t packet_list = {NULL, NULL};

    ike_header_t header = init_header();


    ike_payload_header_t pd = {0};
    pd.next_payload = NEXT_PAYLOAD_NONCE;

    // questa parte deve essere scelta in base alla proposal specificata
    ike_payload_kex_t kd = {0};
    kd.dh_group = htobe16(31);
    // questa parte andrà spostata nella creazione del pacchetto
    memcpy(&kd.ke_data, left.ctx.public_key, 32);
    memcpy(&header.initiator_spi, &left.ctx.spi, 8);

    ike_payload_header_t np = {0};
    np.next_payload = NEXT_PAYLOAD_NONE;

    ike_payload_proposal_t proposal = create_proposal();
    ike_payload_header_t header_1 = {0} ;
    header_1.next_payload = NEXT_PAYLOAD_KE;

    push_component(&packet_list, PAYLOAD_TYPE_NONCE,        left.ctx.nonce,         left.ctx.nonce_len);
    push_component(&packet_list, GENERIC_PAYLOAD_HEADER,    &np,                    sizeof(ike_payload_header_t));
    push_component(&packet_list, PAYLOAD_TYPE_KE,           &kd,                    sizeof(ike_payload_kex_t));
    push_component(&packet_list, GENERIC_PAYLOAD_HEADER,    &pd,                    sizeof(ike_payload_header_t));
    push_component(&packet_list, PAYLOAD_TYPE_SA,           &proposal,              sizeof(ike_payload_proposal_t));
    push_component(&packet_list, GENERIC_PAYLOAD_HEADER,    &header_1,              sizeof(ike_payload_header_t));
    push_component(&packet_list, IKE_HEADER,                &header,                sizeof(ike_header_t));
    
    uint8_t* buff;
    size_t len = 0;
    
    buff = create_message(&packet_list, &len);

    int retval =  send(left.node.fd, buff, len, 0);
    if(retval == -1){
        printf("Errore per la send");
        return -1;
    }
    //il free non azzera il contenuto dice solamente che la memoria ora è disponibile, quindi la rilascia al sistema operativo
    // questo buffer molto probabilmente servirà per la fase di auth
    // non facciamo il free ma lo riutilizziamo in fase di auth

    //la gestione della recv e del caso in cui il timeout scade va gestita nella parte network
    uint8_t* buffer = calloc(MAX_PAYLOAD, sizeof(uint8_t));
    printf("Waiting...\n");
    n = recv(left.node.fd, buffer, MAX_PAYLOAD, 0);
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
    right.ctx.spi = hd->responder_spi;
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
            right.ctx.key_len = 32;
            right.ctx.public_key = malloc(right.ctx.key_len);
            memcpy(right.ctx.public_key, ptr+8, right.ctx.key_len);

            responder.sa.key = malloc(responder.sa.key_len);
            memcpy(responder.sa.key, ptr+8, responder.sa.key_len);
        }
        
        if(current_payload == NEXT_PAYLOAD_NONCE){
            //printf("sono al payload nonce\n");
            responder.sa.nonce_len = be16toh(payload->length) -4;
            responder.sa.nonce = malloc(responder.sa.nonce_len);
            memcpy(responder.sa.nonce, ptr+4, 32);
            right.ctx.nonce_len = be16toh(payload->length) - 4;
            right.ctx.nonce = malloc(right.ctx.nonce_len);
            memcpy(right.ctx.nonce, ptr+4, 32);
        }

        //printf("Next payload di tipo %s, tra %d byte\n", next_payload_to_string(payload->next_payload), be16toh(payload->length));
        next_payload = payload->next_payload;
        ptr += be16toh(payload->length);
    }
    //END

    /*   
    //THIS EXCHANGE IS NECESSARY BECAUSE STRONGSWAN USE COOKIE AS DDOS PREVENTION
    //SO BEFORE GENERATING THE SKEYSEED AND OTHER THINGS HE WAIT THE IKE_AUTH_INIT 
    hd->exchange_type = EXCHANGE_IKE_AUTH;
    hd->message_id = htobe32(1);
    uint8_t flags[] = {FLAG_I, 0};
    set_flags(hd, flags);
    memset(buff, 0, len);
    memcpy(buff, hd, 28);
    retval =  send(left.node.fd, buff, len, 0);
    //END - THIS PIECE OF CODE GENERATE THE IKE AUTH MOCK

    */

    //fare una funzione che si chiama derive keys che deriva tutte le chiavi necessarie per le fasi successive
    // al cui interno metto tutta la parte di derivazione del segreto e concatenazione dei nonce
    
    // questa funzione che deriva il segreto condiviso io la chiamerei nella funzione che si occupa di derivare il seed

    uint8_t *T_buffer = calloc(NUM_KEYS * SHA1_DIGEST_LENGTH, 1);
    size_t generated = 0;
    
    unsigned int digest_len = SHA1_DIGEST_LENGTH;
    uint8_t *digest = malloc(digest_len);
    
    prf_plus(&left.ctx, &right.ctx, &T_buffer);
    printf("\n");
    dump_memory(T_buffer, NUM_KEYS*SHA1_DIGEST_LENGTH);

    //a questo punto posso popolare le chiavi 
    uint8_t* SK_d = malloc(SHA1_DIGEST_LENGTH);
    uint8_t* SK_ai = malloc(SHA1_DIGEST_LENGTH);
    uint8_t* SK_ar = malloc(SHA1_DIGEST_LENGTH);
    uint8_t* SK_ei = malloc(16); // questo va sostiutito con la lunghezza della chiave di AES, dato che è 128 bit sono 16 byte
    uint8_t* SK_er = malloc(16); //parametrizzare anche questo 
    uint8_t* SK_pi = malloc(SHA1_DIGEST_LENGTH);
    uint8_t* SK_pr = malloc(SHA1_DIGEST_LENGTH);

    memcpy(SK_d, T_buffer, SHA1_DIGEST_LENGTH);
    memcpy(SK_ai, T_buffer + SHA1_DIGEST_LENGTH, SHA1_DIGEST_LENGTH);
    memcpy(SK_ar, T_buffer + 2*SHA1_DIGEST_LENGTH, SHA1_DIGEST_LENGTH);
    memcpy(SK_ei, T_buffer + 3*SHA1_DIGEST_LENGTH, 16);
    memcpy(SK_er, T_buffer + 3*SHA1_DIGEST_LENGTH + 16, 16);
    memcpy(SK_pi, T_buffer + 3*SHA1_DIGEST_LENGTH + 2*16, SHA1_DIGEST_LENGTH);
    memcpy(SK_pr, T_buffer + 4*SHA1_DIGEST_LENGTH + 2*16, SHA1_DIGEST_LENGTH);
    printf("\n");
    printf("SK_d: ");
    dump_memory(SK_d, SHA1_DIGEST_LENGTH);
    printf("SK_ai: ");
    dump_memory(SK_ai, SHA1_DIGEST_LENGTH);
    printf("SK_ar: ");
    dump_memory(SK_ar, SHA1_DIGEST_LENGTH);
    printf("SK_ei: ");
    dump_memory(SK_ei, 16);
    printf("SK_er: ");
    dump_memory(SK_er, 16);
    printf("SK_pi: ");
    dump_memory(SK_pi, SHA1_DIGEST_LENGTH);
    printf("SK_pr: ");
    dump_memory(SK_pr, SHA1_DIGEST_LENGTH);
    printf("\n");
    

    uint8_t id_i[8] = {0};
    id_i[0] = 0x01;
    id_i[1] = 0x00;   // Reserved
    id_i[2] = 0x00;  
    id_i[3] = 0x00;
    id_i[4] = 0x00;
    id_i[5] = 0x00;
    id_i[6] = 0x00;
    id_i[7] = 0x00;

    //il contenuto di id payload insieme a quello di auth e della proposal va messo all'interno di encrypted and authenticated

    uint8_t auth_i[4] = {0};
    auth_i[0] = 0x02;
    auth_i[1] = 0x00;   // Reserved
    auth_i[2] = 0x00;  
    auth_i[3] = 0x00;


    //una volta generate le chiavi mi basta prendere il pacchetto precedente, mettergli in append il nonce del responder e i dati del ID payload
    //l 'auth payload è composto dal primo messaggio, a cui si concatena il nonce del responder e l'hash dell'IDpayload
    uint8_t* auth_payload = malloc(len + right.ctx.nonce_len + SHA1_DIGEST_LENGTH);
    size_t auth_len =  len + right.ctx.nonce_len + SHA1_DIGEST_LENGTH;  // il seed me lo devo salvare da qualche parte

    //le variabili buff e len le ho prese da sopra, riformulare quella parte
    memcpy(auth_payload, buff,len);
    memcpy(auth_payload + len, right.ctx.nonce, right.ctx.nonce_len);
    //dopo questi che dipendeno uno dalla richiesta e uno dalla risposta ne serve uno che dipende dallo scambio che deve avvenire ovvero quello di autenticazione, quidni
    // si aggiunge l'hmac dell'id

    uint8_t* md = malloc(SHA1_DIGEST_LENGTH);
    unsigned int md_len = 0;
    HMAC(EVP_sha1(), SK_pi, SHA1_DIGEST_LENGTH, id_i, 8, md, &md_len);

    memcpy(auth_payload + len + right.ctx.nonce_len, md, md_len);

    // questo auth payload a questo punto deve essere dato in pasto ad un prf 
    // AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
    char *secret = "padrepio";
    size_t secret_len = 8;

    const char *key_pad_str = "Key Pad for IKEv2";
    size_t key_pad_len = 17; // Senza \0

    HMAC(EVP_sha1(),secret, secret_len, (const unsigned char *)key_pad_str, key_pad_len, md, &md_len);
    printf("Key expansion \n");
    dump_memory(md, md_len);

    uint8_t* output = malloc(SHA1_DIGEST_LENGTH);
    unsigned int out_len = 0;
    //ora questo deve essere utilizzato pe firmare l'auth payload
    HMAC(EVP_sha1(), md, md_len, auth_payload, auth_len, output, &out_len);
    printf("AUTH PAYLOAD \n");
    dump_memory(output, out_len);

    //la parte di authentication non è ancora il problema dato che non otteniamo l'errore authentication failed
    // generato il paylaod quello che dobbiamo fare è crearne uno di tipo Encrypted and authenticated

    ike_payload_header_t sk = {0};
    sk.next_payload = NEXT_PAYLOAD_IDi;

    ike_payload_header_t identity = {0};
    identity.next_payload = NEXT_PAYLOAD_AUTH;
    identity.length = htobe16(8+4);

    ike_payload_header_t authentication = {0};
    authentication.next_payload = NEXT_PAYLOAD_NONE;
    authentication.length = htobe16(SHA1_DIGEST_LENGTH + 4 + 4); // da convertire il parametro della lunghezza
    // la lunghezza è 20 per il digest + 4 per l'header + 4 per informazioni per specificare l'auth method

    int plaintext_len = 8 + SHA1_DIGEST_LENGTH + 8+ 4 ;
    uint8_t* enc_buffer = malloc(plaintext_len);
    mempcpy(enc_buffer ,&identity, 4);
    memcpy(enc_buffer + 4 , id_i, 8);
    memcpy(enc_buffer + 12, &authentication, 4);
    memcpy(enc_buffer +16 , &auth_i, 4);
    memcpy(enc_buffer +16+4, output, out_len);

    //questo è il payload che devo cifrare, quindi adesso mi creo un iv che deve essere di 16 byte

    size_t iv_len = 16;
    uint8_t* iv = malloc(iv_len);
    getrandom(iv, iv_len, 0);

    printf("IV: \n");
    dump_memory(iv, iv_len);
    
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, SK_ei, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    //per vedere quanto sarà il padding verificare la lunghezza del buffer di cifratura
    //anche la quantità di padding va cifrata, il padding va calcolateo considerando che un byte deve essere riservato alla pad length
    //quindi dal padd da aggiungere togliamo un byte
    int padd =  16 - (plaintext_len % 16); 
    printf("Padding da aggiungere: %d", padd);
    printf("\n");

    enc_buffer = realloc(enc_buffer, plaintext_len + padd);
    memset(enc_buffer + plaintext_len, 0, padd-1);
    memset(enc_buffer + plaintext_len + padd -1, padd-1, 1);
    plaintext_len += padd;

    dump_memory(enc_buffer, plaintext_len);


    uint8_t ciphertext[256];
    int len_cip;
    int ciphertext_len;


    EVP_EncryptUpdate(ctx, ciphertext, &len_cip, enc_buffer, plaintext_len);
    ciphertext_len = len_cip;

    printf("Ciphertext len %d vs Actual length %d", ciphertext_len, plaintext_len);
    //after completing the encryption we have to calculate the checksum

    // al checksum va aggiunto anche l'header    
    printf("Ciphertext:\n");
    dump_memory(ciphertext, ciphertext_len);

    // la dimensione del checksum deve essere di 12 byte, dato che l'algoritmo che si utilizza per calcolarlo è
    // AUTH_HMAC_SHA1_96 bytes because the HMAC gets truncated from 160 to 96 bits 
    // se non vogliamo specificare questo possiamo utilizzare AUTH_HMAC_SHA1_160 che quindi non ha bisogno di troncamento
    size_t icv_len = 12; 

    size_t response_len = 4+iv_len+ciphertext_len+icv_len;
    uint8_t* response = malloc(response_len);
    sk.length = htobe16(response_len);

    memcpy(response, &sk, 4);
    memcpy(response + 4 , iv, iv_len);
    memcpy(response +4 + iv_len , ciphertext, ciphertext_len);

    printf("Data to sign\n");
    dump_memory(response, response_len-icv_len);
    
    uint8_t* checksum = malloc(SHA1_DIGEST_LENGTH);
    printf("Key dump SK_ai\n");
    dump_memory(SK_ai, SHA1_DIGEST_LENGTH);

    HMAC(EVP_sha1(), SK_ai, SHA1_DIGEST_LENGTH, response, response_len-icv_len, checksum, &md_len);
    mempcpy(response + 4 + iv_len + ciphertext_len, checksum, icv_len);

    printf("Checksum truncated\n");
    dump_memory(checksum, 12);
    //prima cè da incluedere anche l'header
    printf("Checksum complete\n");
    dump_memory(checksum, SHA1_DIGEST_LENGTH);
    
    hd->exchange_type = EXCHANGE_IKE_AUTH;
    hd->next_payload = NEXT_PAYLOAD_SK;
    hd->message_id = htobe32(1);
    hd->length = htobe32(28+response_len);
    uint8_t flags[] = {FLAG_I, 0};
    set_flags(hd, flags);

    printf("header");
    dump_memory(hd, 28);

    response = realloc(response, response_len+28);
    memmove(response+28, response, response_len);
    memcpy(response, hd, 28);    
    
    /*
    HMAC(EVP_sha1(), SK_ar, SHA1_DIGEST_LENGTH, response, response_len-icv_len, checksum, &md_len);
    mempcpy(response + 28  + response_len -icv_len, checksum, icv_len);
    printf("Checksum\n");
    dump_memory(checksum, 12);
    */

    retval =  send(left.node.fd, response, response_len+28, 0);
    // dump di tutto 
    printf("################################\n");
    printf("Response\n");
    printf("################################\n");
    dump_memory(response, response_len + 28);
    // prendere il filename dalle variabili d'ambiente
    
    return 0;
}
