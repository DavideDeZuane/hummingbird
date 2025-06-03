#include "../include/common.h" // IWYU pragma: keep
#include <ini.h>
#include "../include/config.h"
#include "../include/log.h"
#include "../include/crypto.h"
#include "../include/utils.h"
#include "../include/network.h"
#include "../include/ike/header.h"
#include "../include/ike/constant.h"
#include "../include//ike/header.h"
#include "../include/ike/ike.h"
#include "../include/ike/payload.h"

#include <openssl/hmac.h> //spostare utilizzo di hmac diretto nel modulo crytpo
#include <stdio.h>
#include <string.h>
#include <sys/random.h> //spostare la definizione dell'IV per l'encrypted payload nel modulo IKE


typedef struct {
    void *next; 
    void *prev; 
    void *data; 
    size_t length;
    MessageComponent type; 
} ike_message_component_t;

typedef struct {
    ike_message_component_t *head;
    ike_message_component_t *tail;
} ike_message_t;


int add_payload(ike_message_t* msg, ike_payload_t* payload){

}

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

    uint8_t* buffer = NULL;
    ike_message_component_t* scan = list->tail;

    while(scan != NULL){
        buffer_len += scan->length;
        buffer = realloc(buffer, buffer_len);
        //una volta allocato il buffer prima di scriverci sopra facciamo la conversione in big endian di quello che ci vogliamo scrivere
        if (buffer_len > scan->length) memmove(buffer + scan->length, buffer, buffer_len - scan->length);

        if(scan->type == IKE_HEADER){
            ike_header_raw_t * hdr = (ike_header_raw_t *) scan->data;
            uint32_to_bytes_be(buffer_len, hdr->length);
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
    config* cfg = malloc(sizeof(config));
    default_config(cfg);

    int n;
    if ((n = ini_parse(DEFAULT_CONFIG, handler, cfg)) != 0) {
        if (n == -1) {
            log_error("Error on opening the configuration file %s", COLOR_TEXT(ANSI_COLOR_YELLOW, DEFAULT_CONFIG));
            log_error("The file %s not exists", COLOR_TEXT(ANSI_COLOR_RED, DEFAULT_CONFIG));
            return EXIT_FAILURE;
        }
        if (n > 0) {
            log_error(ANSI_COLOR_RED "Error on reading the configuration file " ANSI_COLOR_BOLD "%s" ANSI_COLOR_RESET ANSI_COLOR_RED", at line" ANSI_COLOR_BOLD " %d" ANSI_COLOR_RESET , DEFAULT_CONFIG, n);
            log_error(ANSI_COLOR_RED "Can't load " ANSI_COLOR_BOLD "%s" ANSI_COLOR_RESET ANSI_COLOR_RED " due to syntax error", DEFAULT_CONFIG);
            return EXIT_FAILURE;
        }
        return EXIT_FAILURE;
    }

    log_set_quiet(cfg->log.quiet);
    log_set_level(cfg->log.level);
    log_info("Configuration file %s loaded successfully", DEFAULT_CONFIG);
    log_info("[CFG] module successfully setup", DEFAULT_CONFIG);

    ike_partecipant_t left = {0};
    ike_partecipant_t right = {0};
    ike_sa_t sa = {0};
    
    initiate_ike(&left, &right, &sa, cfg);
    free(cfg);

    // crearli in maniera dinamica in modo tale da poterli distruggere una volta creato il messaggio,
    // quello che ci server per la fase di autenticazione è il messaggio completo
    ike_payload_t ni_data = {0};
    ike_payload_t kex_data = {0};
    ike_payload_t sa_data = {0};
    
    // al build payload non devo passare la lunghezza e lui che mi deve popolare il valore della lunghezza con quello totale

    build_payload(&ni_data,     PAYLOAD_TYPE_NONCE, left.ctx.nonce);
    build_payload(&kex_data,    PAYLOAD_TYPE_KE,    &left.ctx);
    build_payload(&sa_data,     PAYLOAD_TYPE_SA,    &sa.suite);

    ike_message_t packet_list = {NULL, NULL};
    ike_header_raw_t header = init_header_raw(left.ctx.spi,0);

    push_component(&packet_list, PAYLOAD_TYPE_NONCE, ni_data.body,   ni_data.len);
    push_component(&packet_list, PAYLOAD_TYPE_KE,    kex_data.body,  kex_data.len);
    push_component(&packet_list, PAYLOAD_TYPE_SA,    sa_data.body,   sa_data.len);
    push_component(&packet_list, IKE_HEADER,         &header,        sizeof(ike_header_raw_t));

    uint8_t* buff;
    size_t len = 0;
    
    buff = create_message(&packet_list, &len);

    int retval =  send(left.node.fd, buff, len, 0);
    if(retval == -1){
        printf("Errore per la send");
        return -1;
    }

    log_info("INIT message with dimension %zu bytes, sended to responder", len);

    //la gestione della recv e del caso in cui il timeout scade va gestita nella parte network
    uint8_t* buffer = calloc(MAX_PAYLOAD, sizeof(uint8_t));
    log_debug("Sended INIT request, waiting for the response");

    n = recv(left.node.fd, buffer, MAX_PAYLOAD, 0);
    if (n < 0) {
        if (errno == EAGAIN ) {
            printf("Timeout scaduto: nessun dato ricevuto entro 1 secondo.\n");
        } else {
            perror("Errore durante la ricezione");
            return EXIT_FAILURE;
        }
    } 
    log_debug("Bytes received from the responder %d", n);
    buffer = realloc(buffer, n);
    buffer[n] = '\0'; 

    //qunado vado a fare il parsing dei vari elementi vorrei fare in modo di confrontare il payload dal buffer per aggiornare quello che ho inviato io 
    ike_header_t* hd = parse_header(buffer, n);
    // #########################################################################################
    //porcodio
    // #########################################################################################
    memcpy(right.ctx.spi, &hd->responder_spi , 8);

    /* 
    #########################################################################################
    # RESPONSE PARSING, to move in ike directory and use in the recv method
    #########################################################################################
    */
    uint8_t *ptr = buffer+28; 
    uint8_t next_payload = ptr[0];         
    uint8_t current_payload = hd->next_payload;

    while (next_payload != 0){
        current_payload = next_payload;
        //printf("Il payload corrente è %s\n", next_payload_to_string(current_payload));
        ike_payload_header_raw_t *payload = (ike_payload_header_raw_t *)ptr;

        if(current_payload == NEXT_PAYLOAD_KE){
            // aggiungere il controllo sul contenuto della risposta del dh group 
            right.ctx.dh_group = bytes_to_uint16_be(ptr + 4);
            right.ctx.key_len = bytes_to_uint16_be(payload->length) - 8;
            right.ctx.public_key = malloc(right.ctx.key_len);
            memcpy(right.ctx.public_key, ptr+8, right.ctx.key_len);
        }
        
        if(current_payload == NEXT_PAYLOAD_NONCE){
            //printf("sono al payload nonce\n");
            right.ctx.nonce_len = bytes_to_uint16_be(payload->length) - GEN_HDR_DIM;
            right.ctx.nonce = malloc(right.ctx.nonce_len);
            memcpy(right.ctx.nonce, ptr + GEN_HDR_DIM, right.ctx.nonce_len);
        }

        //printf("Next payload di tipo %s, tra %d byte\n", next_payload_to_string(payload->next_payload), be16toh(payload->length));
        next_payload = payload->next_payload;
        ptr += bytes_to_uint16_be(payload->length);
    }
    /*
    #########################################################################################
    # END
    #########################################################################################
    */
    /* 
    #########################################################################################
    # GENERATING KEY MATERIALS, the prf plus method is in the crypto, but the key materials
    # to be generated depends on parameters of ike like number of keys
    #########################################################################################
    */
    ike_session_t ike_sa = {0};
    ike_sa.initiator = left;
    ike_sa.responder = right;

    derive_ike_sa(&ike_sa);
    /*
    ####################################################################################
    # GENERATING THE IKE AUTH EXCHANGE
    ####################################################################################
    */
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
    HMAC(EVP_sha1(), ike_sa.association.sk_pi, SHA1_DIGEST_LENGTH, id_i, 8, md, &md_len);

    memcpy(auth_payload + len + right.ctx.nonce_len, md, md_len);

    // questo auth payload a questo punto deve essere dato in pasto ad un prf 
    // AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
    // LA PARTE SUL SEGRETO CONDIVISO E DI POPOLAMENTO DELL'AUTH PAYLAOD VA SPOSTATA NELLA PARTE DI AUTH

    char *secret = "padrepio";
    size_t secret_len = 8;

    const char *key_pad_str = "Key Pad for IKEv2";
    size_t key_pad_len = 17; // Senza \0

    HMAC(EVP_sha1(),secret, secret_len, (const unsigned char *)key_pad_str, key_pad_len, md, &md_len);
    //printf("Key expansion \n");
    //dump_memory(md, md_len);

    uint8_t* output = malloc(SHA1_DIGEST_LENGTH);
    unsigned int out_len = 0;
    //ora questo deve essere utilizzato pe firmare l'auth payload
    HMAC(EVP_sha1(), md, md_len, auth_payload, auth_len, output, &out_len);
    //printf("AUTH PAYLOAD \n");
    //dump_memory(output, out_len);

    ike_payload_header_t sk = {0};
    sk.next_payload = NEXT_PAYLOAD_IDi;

    ike_payload_header_t identity = {0};
    identity.next_payload = NEXT_PAYLOAD_AUTH;
    identity.length = htobe16(8+4);

    ike_payload_header_t authentication = {0};
    authentication.next_payload = NEXT_PAYLOAD_NONE;
    authentication.length = htobe16(SHA1_DIGEST_LENGTH + 4 + 4); // da convertire il parametro della lunghezza
    // la lunghezza è 20 per il digest + 4 per l'header + 4 per informazioni per specificare l'auth method


    int plaintext_len = 8 + SHA1_DIGEST_LENGTH + 8+ 4; //+ 8;
    uint8_t* enc_buffer = malloc(plaintext_len);

    mempcpy(enc_buffer ,&identity, GEN_HDR_DIM);
    memcpy(enc_buffer + GEN_HDR_DIM , id_i, 8);
    memcpy(enc_buffer + 12, &authentication, GEN_HDR_DIM);
    memcpy(enc_buffer +16 , &auth_i, 4);
    memcpy(enc_buffer +16+4, output, out_len);

    //questo è il payload che devo cifrare, quindi adesso mi creo un iv che deve essere di 16 byte
    //la dimensione dell'iv dipendende dalla lunghezza della chiave in cbc
    // ########################################################################################
    // DA SPOSTARE NELLA PARTE DI CREAZIONE DELL'ENCRYPTED PAYLOAD
    // ########################################################################################
    size_t iv_len = 16;
    uint8_t* iv = malloc(iv_len);
    getrandom(iv, iv_len, 0);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, ike_sa.association.sk_ei, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    //per vedere quanto sarà il padding verificare la lunghezza del buffer di cifratura
    //anche la quantità di padding va cifrata, il padding va calcolateo considerando che un byte deve essere riservato alla pad length
    //quindi dal padd da aggiungere togliamo un byte

    int padd =  16 - (plaintext_len % 16); 

    enc_buffer = realloc(enc_buffer, plaintext_len + padd);
    memset(enc_buffer + plaintext_len, 0, padd-1);
    memset(enc_buffer + plaintext_len + padd -1, padd-1, 1);
    plaintext_len += padd;


    uint8_t ciphertext[256];
    int len_cip;
    int ciphertext_len;


    EVP_EncryptUpdate(ctx, ciphertext, &len_cip, enc_buffer, plaintext_len);
    ciphertext_len = len_cip;

    
    // ##########################################################################################
    // FINO A QUA
    // ##########################################################################################

    // la dimensione del checksum deve essere di 12 byte, dato che l'algoritmo che si utilizza per calcolarlo è
    // AUTH_HMAC_SHA1_96 bytes because the HMAC gets truncated from 160 to 96 bits 
    // se non vogliamo specificare questo possiamo utilizzare AUTH_HMAC_SHA1_160 che quindi non ha bisogno di troncamento
    size_t icv_len = 12; 

    size_t response_len = GEN_HDR_DIM+iv_len+ciphertext_len;
    uint8_t* response = malloc(response_len);
    sk.length = htobe16(response_len+icv_len); //nel generare la lunghezza del payload cifrato e autenticato aggiunto la dimensione del checksum

    memcpy(response, &sk, GEN_HDR_DIM);
    memcpy(response + GEN_HDR_DIM , iv, iv_len);
    memcpy(response + GEN_HDR_DIM + iv_len , ciphertext, ciphertext_len);
    
    hd->exchange_type = EXCHANGE_IKE_AUTH;
    hd->next_payload = NEXT_PAYLOAD_SK;
    hd->message_id = htobe32(1);
    hd->length = htobe32(28+response_len+icv_len);
    uint8_t flags[] = {FLAG_I, 0};
    set_flags(hd, flags);

    response_len +=28;
    response = realloc(response, response_len);
    memmove(response+28, response, response_len-28);
    memcpy(response, hd, 28);    

    uint8_t *checksum = malloc(icv_len);

    HMAC(EVP_sha1(), ike_sa.association.sk_ai, SHA1_DIGEST_LENGTH, response, response_len, checksum, &md_len);
    response = realloc(response, response_len+icv_len);
    mempcpy(response + 28 + 4 +iv_len + ciphertext_len, checksum, icv_len);

    retval =  send(left.node.fd, response, response_len+icv_len, 0);

    log_info("Waiting for the IKE AUTH response");

    buffer = realloc(buffer, MAX_PAYLOAD);
    n = recv(left.node.fd, buffer, MAX_PAYLOAD, 0);
    if (n < 0) {
        if (errno == EAGAIN ) {
            printf("Timeout scaduto: nessun dato ricevuto entro 1 secondo.\n");
        } else {
            perror("Errore durante la ricezione");
            return EXIT_FAILURE;
        }
    } 

    log_debug("Bytes received from the responder %d", n);

    ike_header_raw_t raw = {0};
    parse_header_raw(buffer, &raw);
    

    // quando tratto i dati siamo già nel mondo della CPU, ovvero non stiamo più trattando byte 
    // ma stiamo operando su una variabile che è nativa per la macchina, quindi il compilatore conosce l'endianess della CPU e come rappresentare il dato
    // l'endianess conta solo quando interpretiamo l'array di byte come interi o altri dati nativi 

    secure_free(response, response_len);


    
    return 0;
}
